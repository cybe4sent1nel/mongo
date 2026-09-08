# Title

Unbounded recursion in `mongo-go-driver`'s generic BSON-to-`interface{}` decode path (`emptyInterfaceCodec` ⇄ `dDecodeValue`/`mapCodec`) causes an uncatchable `fatal error: stack overflow` when decoding a single crafted BSON document — via `bson.Unmarshal` on untrusted bytes from a file, queue, or other channel (Path A), or via `Cursor.Decode`/`Cursor.All` against a malicious/compromised/on-path-attacker-controlled server (Path B)

## Important scope note, stated up front

**A genuine, unmodified `mongod`/`mongos` cannot itself be used to store and later return a document deep enough to trigger this crash** — MongoDB's server enforces its own document-nesting cap (rejects documents past roughly 200 levels) at write time. So "an ordinary query response from a standard server" isn't the complete picture, and I'd rather state that directly than have it surface in review.

Two distinct, independently valid reachability paths follow from that, and I'm presenting both on their own merits rather than picking a "safe" one:

**Path A — no server or network involved at all.** `go.mongodb.org/mongo-driver/v2/bson` is a general-purpose, publicly documented codec package (`bson.Unmarshal`, `NewDecoder(...).Decode()`), not something that only exists behind a live database connection. Decoding BSON bytes from a file, a message queue, an inter-service payload, or any other untrusted channel is one of its ordinary, intended uses — the same standing any general-purpose parser has. This path needs no server, no MITM, and no already-compromised anything. It's fully proven with zero such caveats in the sibling `mongo-tools`/`bsondump` finding from this same pass, which is this exact package used for exactly this purpose.

**Path B — via `Cursor.Decode`/`Cursor.All` against a malicious/compromised/on-path-attacker-controlled server.** Worth naming plainly: `mongo-csharp-driver` report #3790290 (and its duplicate #3996918) and `bson-rust` report #3996627 were both closed **Informative** on precisely this precondition. That's real program history on this exact bug shape, not something to gloss over. It doesn't necessarily mean this path is dead — dispositions turn on the specifics of each write-up and how the reachability is argued, not just the abstract precondition — but I'm not going to claim it as a strong angle either. I'd treat Path A as the claim this report actually stands on, and Path B as additional, real, but higher-risk context.

## Summary

`go.mongodb.org/mongo-driver/v2/bson`'s default decode path for untyped Go destinations — `bson.M`, `bson.D`, `interface{}`, or any container of these (the single most common way Go applications consume ad-hoc query results, and equally the code path any file/queue-fed decode into these types goes through) — resolves nested BSON sub-documents and sub-arrays via mutual recursion between `emptyInterfaceCodec.DecodeValue`/`decodeType`, `decodeTypeOrValueWithInfo`, and `dDecodeValue` (nested documents default-decode to `bson.D`, per the driver's own type-map registration, regardless of the top-level destination type). **No depth counter, nesting limit, or recursion guard exists anywhere in this chain, nor anywhere on `DecodeContext` itself.** A single BSON document containing a deeply nested sub-document (or sub-array) drives this recursion to a genuine Go stack overflow. This is not a normal `panic` and is **not recoverable with `recover()`** — the Go runtime prints `fatal error: stack overflow` and terminates the process unconditionally (exit code 2).

This is the same root-cause shape as `mongo-csharp-driver` report #3790290/#3996918 — an unbounded-recursion BSON decoder with no depth guard — see the scope note above for how that report's disposition (and `bson-rust` #3996627's) bears on Path B specifically. The Go driver's own Extended-JSON (text) parser was already found to have a related-but-distinct gap (nested-array depth not checked, reported separately, confirmed a duplicate of an earlier report — #3760693); this report is about the **binary BSON wire-format decode path**, which is untouched by that fix and has its own, separate, complete absence of any depth tracking.

## Weakness

CWE-674 (Uncontrolled Recursion) → process-terminating stack overflow (`fatal error: stack overflow`, SIGABRT-equivalent unrecoverable runtime abort), triggered by ordinary, protocol-legal server response data.

## Component / Version

- Repository: `mongodb/mongo-go-driver` (HackerOne scope: **Drivers → Go**)
- Tag: `v2.9.0`
- Commit: [`099a81f05c516dc85ee25fffcc09000d547ba994`](https://github.com/mongodb/mongo-go-driver/commit/099a81f05c516dc85ee25fffcc09000d547ba994) — current latest release
- Confirmed with `go1.25.0 linux/amd64`, unmodified upstream module code (only a local `replace` directive in the PoC's own `go.mod` to point at a clean clone of this exact commit — no driver code was patched or altered).
- `v2.9.0` was verified against upstream tags directly (not just a local clone) to be the current latest release at test time. `go get go.mongodb.org/mongo-driver/v2@latest` pulls whatever is newest — nothing in this decode chain has changed in any release history since, so a newer tag is expected to reproduce identically; no need to pin to `v2.9.0` specifically.

## Root cause, with links to the exact code

**Decoding into `bson.M`** (`map[string]any`) goes through [`mapCodec.DecodeValue`](https://github.com/mongodb/mongo-go-driver/blob/099a81f05c516dc85ee25fffcc09000d547ba994/bson/map_codec.go#L127-L157): for each element it resolves the element's decoder once (`dc.LookupDecoder(eType)`, `eType = any`) and calls `decodeTypeOrValueWithInfo(decoder, dc, vr, eType)` per field — no depth tracked or passed down.

Because every registered `Type(0)`/`TypeEmbeddedDocument` type-map entry defaults to `bson.D` (`bson/default_value_decoders.go`, registry init: `reg.RegisterTypeMapEntry(TypeEmbeddedDocument, tD)`), a nested sub-document reached through the generic `any` decoder is handed to [`dDecodeValue`](https://github.com/mongodb/mongo-go-driver/blob/099a81f05c516dc85ee25fffcc09000d547ba994/bson/default_value_decoders.go#L111-L162):

```go
func dDecodeValue(dc DecodeContext, vr ValueReader, val reflect.Value) error {
    ...
    dr, err := vr.ReadDocument()
    ...
    decoder, err := dc.LookupDecoder(tEmpty)   // decoder for `any`
    ...
    for {
        key, elemVr, err := dr.ReadElement()
        ...
        var v any
        err = decoder.DecodeValue(dc, elemVr, reflect.ValueOf(&v).Elem())   // <-- recurses, no depth passed
        ...
    }
}
```

`decoder` here is [`emptyInterfaceCodec`](https://github.com/mongodb/mongo-go-driver/blob/099a81f05c516dc85ee25fffcc09000d547ba994/bson/empty_interface_codec.go), whose [`DecodeValue`/`decodeType`](https://github.com/mongodb/mongo-go-driver/blob/099a81f05c516dc85ee25fffcc09000d547ba994/bson/empty_interface_codec.go#L79-L124) looks up the decoder for the field's BSON type — for another nested document, this resolves back to `dDecodeValue` via [`decodeTypeOrValueWithInfo`](https://github.com/mongodb/mongo-go-driver/blob/099a81f05c516dc85ee25fffcc09000d547ba994/bson/bsoncodec.go#L184-L201) — closing the cycle:

```
mapCodec.DecodeValue → decodeTypeOrValueWithInfo → emptyInterfaceCodec.decodeType
  → dc.LookupDecoder(tD) → dDecodeValue → decoder.DecodeValue (= emptyInterfaceCodec.DecodeValue)
  → decodeType → decodeTypeOrValueWithInfo → dDecodeValue → ... (once per nesting level)
```

**`DecodeContext`** (`bson/bsoncodec.go`, struct definition around lines 98-122) has fields for `truncate`, `defaultDocumentType`, `binaryAsSlice`, `objectIDAsHexString`, `useJSONStructTags`, `useLocalTimeZone`, `zeroMaps`, `zeroStructs` — **no depth, maxDepth, or recursion-counter field of any kind.** A repo-wide search of `bson/*.go` for `maxNestingDepth`/`MaxDepth`/`recursion`/`RecursionDepth` matches only the Extended-JSON parser (`extjson_parser.go`) and its test file — nothing in the binary-BSON codec/decoder machinery.

The identical shape applies to nested **arrays**: the default type-map entry for `TypeArray` resolves through `sliceCodec`, which walks each array element through the same `dc.LookupDecoder`/`decodeTypeOrValueWithInfo` cycle with no depth tracking either — confirmed empirically below (Step 2).

## Reachability via ordinary query results

[`mongo/cursor.go`](https://github.com/mongodb/mongo-go-driver/blob/099a81f05c516dc85ee25fffcc09000d547ba994/mongo/cursor.go#L352-L356), `Cursor.Decode`:

```go
func (c *Cursor) Decode(val any) error {
    dec := getDecoder(c.Current, c.bsonOpts, c.registry)
    return dec.Decode(val)
}
```

This is the exact `bson.Decoder.Decode` entry point exercised directly below via `bson.Unmarshal` (which the package documents as equivalent to `NewDecoder` + `Decode` for a byte slice). Any application doing the idiomatic:

```go
var doc bson.M
cursor.Decode(&doc)
```

or

```go
var results []bson.M
cursor.All(ctx, &results)
```

— both extremely common patterns for ad-hoc queries, aggregation results, or any code that doesn't define a fully-typed Go struct for every possible document shape — reaches this exact vulnerable chain on every document the server returns. No special API usage, no explicit BSON parsing call, and no attacker credentials are required: a malicious or compromised `mongod`/`mongos`, or an on-path attacker able to tamper with an unencrypted/improperly-verified connection, needs only to return one crafted document as part of any ordinary query response.

## Steps to Reproduce

Requirements: Go toolchain (`go1.25.0` used here — the module's own `go.mod` requires `>= 1.25.0`), a clean clone of `mongo-go-driver` at the tag/commit above.

**Step 1 — PoC module** (`main.go`, included in this directory), building a BSON binary document nested to an attacker-chosen depth via a single flat pre-allocated buffer (`buildNestedDoc`/`buildNestedArray` — O(depth), no repeated slice copies), then decoding it with the real, unmodified driver:

```go
var result bson.M
err := bson.Unmarshal(data, &result)
```

`go.mod` uses a `replace` directive pointing at a local clone of the exact commit under test — no driver source is modified.

**Step 2 — build and run at increasing depth:**

```
go build -o poc .
./poc 100          # decodes fine
./poc 5000         # decodes fine
./poc 500000       # decodes fine (Go's default 1GB max goroutine stack absorbs it)
./poc 2000000 doc    # CRASHES
./poc 2000000 array  # CRASHES (confirms the array-nesting sibling path independently)
```

A 16,000,005-byte input (2,000,000 nesting levels, 8 bytes/level) is well under any BSON document size sanity check and reproduces reliably. Far fewer levels would also suffice on a platform with a smaller configured max stack (`debug.SetMaxStack`); 2,000,000 was simply the depth tested.

**Observed output (document-nesting case, `./poc 2000000 doc`), exit code 2:**

```
building nested BSON doc, depth=2000000
built 16000005 bytes, calling bson.Unmarshal into bson.M...
runtime: goroutine stack exceeds 1000000000-byte limit
runtime: sp=0xc0210b2398 stack=[0xc0210b2000, 0xc0410b2000]
fatal error: stack overflow

goroutine 1 gp=0xc000002380 m=3 mp=0xc000080008 [running]:
...
go.mongodb.org/mongo-driver/v2/bson.dDecodeValue(...)
    .../bson/default_value_decoders.go:112 ...
go.mongodb.org/mongo-driver/v2/bson.ValueDecoderFunc.DecodeValue(...)
    .../bson/bsoncodec.go:158 ...
go.mongodb.org/mongo-driver/v2/bson.decodeTypeOrValueWithInfo(...)
    .../bson/bsoncodec.go:201 ...
go.mongodb.org/mongo-driver/v2/bson.(*emptyInterfaceCodec).decodeType(...)
    .../bson/empty_interface_codec.go:99 ...
go.mongodb.org/mongo-driver/v2/bson.(*emptyInterfaceCodec).DecodeValue(...)
    .../bson/empty_interface_codec.go:120 ...
go.mongodb.org/mongo-driver/v2/bson.dDecodeValue(...)
    .../bson/default_value_decoders.go:157 ...
(repeats, cycling through the same 5-frame group, hundreds of times)
```

The array-nesting variant (`./poc 2000000 array`) produces the identical `fatal error: stack overflow`, exit code 2 — confirmed as a second, independent trigger of the same underlying gap (arrays are decoded through `sliceCodec` rather than `dDecodeValue`, but with the same absence of depth tracking).

No Go error, no `error` return value, and no `recover()` handler fires in either case — the runtime tears the process down before any of that machinery can run. This matches the exact "uncatchable, `fatal error: stack overflow`, exit code 2" signature already documented and accepted for the same bug class in `mongo-tools`' legacy-JSON parser (a *different*, text-based code path, already reported separately) and for the C#/Rust driver equivalents in `mongo-csharp-driver`/`bson-rust`.

Full raw output: `poc_output_doc.txt`, `poc_output_array.txt` (included in this directory).

## Impact

**Path A**: any Go application using `mongo-go-driver`'s `bson` package to decode BSON bytes it received from a file, a message queue, an inter-service payload, an upload, or any other channel it does not fully trust — into `bson.M`, `bson.D`, `interface{}`, or any composite containing them — can be crashed by a single such document. This requires no server connection, no network access, and no credentials at all; it is the exact same threat model already fully proven, with no caveats, in the sibling `mongo-tools`/`bsondump` finding from this same pass.

**Path B**: for applications consuming this data via `Cursor.Decode`/`Cursor.All`, the same crash fires if the connected server is malicious, compromised, or reachable to an on-path attacker — a genuine, unmodified `mongod` cannot itself be induced to store or return a document this deep (see the scope note above). This is real, reachable impact through the same code, presented alongside Path A rather than in place of it.

In both cases: because the crash is a genuine Go runtime stack overflow, none of Go's or the application's own safety nets apply: no `error` return, no `panic`/`recover`, no HTTP middleware, no goroutine-isolation boundary. For a long-running server process (an API backend, a worker, a stream processor), this takes down the entire process, not just the request or goroutine handling it. The crash is deterministic and requires only one document, well under MongoDB's own 16 MB document size limit and any reasonable BSON validation depth (MongoDB's server-side documents are capped at roughly 200 levels of nesting by `mongod` itself — but this client-side decode path enforces no such limit on bytes it did not itself validate against that cap).

## Suggested Fix

Add an explicit recursion-depth counter threaded through `DecodeContext` (mirroring the `maxNestingDepth`/`ejp.depth` pattern the driver's own Extended-JSON parser already uses), incremented on entry to any nested-document/array decode (`mapCodec.DecodeValue`, `dDecodeValue`, `sliceCodec`'s array element loop, `emptyInterfaceCodec.decodeType`), and checked against a fixed maximum (100–200, matching MongoDB server's own document nesting limit and the depth used by other MongoDB BSON/extended-JSON parsers in the ecosystem), returning a normal, catchable `error` once exceeded instead of recursing further.

## Supporting Material

- Vulnerable recursive chain: [`bson/map_codec.go#L127-L157`](https://github.com/mongodb/mongo-go-driver/blob/099a81f05c516dc85ee25fffcc09000d547ba994/bson/map_codec.go#L127-L157), [`bson/default_value_decoders.go#L111-L162`](https://github.com/mongodb/mongo-go-driver/blob/099a81f05c516dc85ee25fffcc09000d547ba994/bson/default_value_decoders.go#L111-L162), [`bson/empty_interface_codec.go#L79-L124`](https://github.com/mongodb/mongo-go-driver/blob/099a81f05c516dc85ee25fffcc09000d547ba994/bson/empty_interface_codec.go#L79-L124), [`bson/bsoncodec.go#L184-L201`](https://github.com/mongodb/mongo-go-driver/blob/099a81f05c516dc85ee25fffcc09000d547ba994/bson/bsoncodec.go#L184-L201)
- Ordinary-query reachability: [`mongo/cursor.go#L352-L356`](https://github.com/mongodb/mongo-go-driver/blob/099a81f05c516dc85ee25fffcc09000d547ba994/mongo/cursor.go#L352-L356)
- `main.go` (PoC source), `poc_output_doc.txt`, `poc_output_array.txt` (included in this directory)
