# Title

`bsondump --type=debug --objcheck` crashes with an uncatchable `fatal error: stack overflow` on a single crafted `.bson` file — direct reachability of the (separately reported) `mongo-go-driver` generic-decode unbounded-recursion bug through this tool's own `--objcheck` validation call; plus a second, independent, first-party unguarded recursion in the same tool's `--type=debug` document printer

## Summary

`bsondump`, the Database Tools utility for converting `.bson` files to human-readable output, has two independent unbounded-recursion paths in its `Debug()` code path (`bsondump --type=debug`):

1. **Inherited from `mongo-go-driver`**: when `--objcheck` is also passed, `bsondump.go` validates each document with `bson.Unmarshal(result, &validated)` where `validated` is `bson.M{}` — the exact vulnerable call pattern I reported separately against `mongo-go-driver` itself (generic decode into `bson.M`/`interface{}` recurses through `mapCodec`/`dDecodeValue`/`emptyInterfaceCodec` with zero depth tracking anywhere on `DecodeContext`). I built the real, unmodified `bsondump` binary from this repository's own source (vendoring `mongo-go-driver` v2.7.0) and confirmed it crashes with `fatal error: stack overflow` (exit code 2) on a single malicious `.bson` file, with the driver's exact vulnerable call chain visible in the crash trace.
2. **First-party, independent of the driver bug**: `bsondump`'s own `printBSON` function (always called by `Debug()`, with or without `--objcheck`) recursively descends into nested documents and arrays with **no depth limit of its own** — a second, separately-introduced instance of the same CWE-674 shape, in code this repository owns directly rather than inherits.

Both are triggered by nothing more than running `bsondump` against a single crafted `.bson` file — no server connection, no credentials, no network access required. This makes `bsondump` a concrete, directly-exploitable consumer of the go-driver bug (rather than a hypothetical "any Go application that decodes into `bson.M`"), and additionally has its own separate defect in code it fully owns.

## Weakness

CWE-674 (Uncontrolled Recursion) → process-terminating stack overflow (`fatal error: stack overflow`, unrecoverable, exit code 2), triggered by parsing a single untrusted `.bson` file — no server, network, or credentials involved.

## Component / Version

- Repository: `mongodb/mongo-tools` (HackerOne scope: **Database Tools**)
- Tag: `100.18.0`
- Commit: [`21a342dfee6468ad9350d156d25086da64dd03b1`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/bsondump/bsondump.go) — the same tag/commit already cited in this program's existing `mongoimport --legacy` finding (a different, text-JSON code path; this report covers `bsondump`'s binary-`.bson` handling instead)
- Vendored driver at this tag: `go.mongodb.org/mongo-driver/v2 v2.7.0` (older than the `v2.9.0` I audited directly for the standalone driver finding — confirms this gap has been present across at least three minor driver releases)
- Confirmed by building the real, unmodified `bsondump` binary (`go build ./bsondump/main/`) from this exact tagged source tree.
- `100.18.0` was the current latest Database Tools release at the time of this test (verified against upstream tags directly, not just this local clone). Nothing in the fix history since then touches `bsondump.go` or `printBSON`, so whatever is the latest release at the time this is read is expected to reproduce identically — download the current release from the [Database Tools download page](https://www.mongodb.com/try/download/database-tools) rather than pinning to `100.18.0` specifically if a newer one is available.

## Root cause, with links to the exact code

**Path 1 — inherited driver bug, gated behind `--objcheck`:**

[`bsondump/bsondump.go#L196-L203`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/bsondump/bsondump.go#L196-L203), inside `Debug()`:

```go
if bd.OutputOptions.ObjCheck {
    validated := bson.M{}
    err := bson.Unmarshal(result, &validated)
    if err != nil {
        // ObjCheck is turned on and we hit an error, so short-circuit now.
        return numFound, fmt.Errorf("failed to validate bson during objcheck: %v", err)
    }
}
```

`result` is `bson.Raw(bd.InputSource.LoadNext())` — the raw bytes of whatever document was next in the input `.bson` file, completely unvalidated at this point. This is the identical `bson.Unmarshal(data, &bsonMValue)` shape I already reported and empirically proved crashes `mongo-go-driver` itself (see the standalone driver report, `security-research/mongo-go-driver/bson-generic-decode-unbounded-recursion-2026-09-07/`): decoding into `bson.M` recurses through `mapCodec.DecodeValue` → `emptyInterfaceCodec` → `dDecodeValue` with no depth counter anywhere on `DecodeContext`.

**Path 2 — first-party, unconditional in `Debug()` mode, independent of `--objcheck`:**

[`bsondump/bsondump.go#L222-L253`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/bsondump/bsondump.go#L222-L253), `printBSON`:

```go
func printBSON(raw bson.Raw, indentLevel int, out io.Writer) error {
    ...
    elements, err := raw.Elements()
    ...
    for _, rawElem := range elements {
        ...
        // For nested objects or arrays, recurse.
        if value.Type == bson.TypeEmbeddedDocument || value.Type == bson.TypeArray {
            err = printBSON(value.Value, indentLevel+3, out)
            ...
        }
    }
    return nil
}
```

This is `mongo-tools`' own code (not the driver's) — it uses the lower-level `bson.Raw.Elements()` lazy-parsing API directly, and recurses on every nested document/array field with **no depth parameter, counter, or limit anywhere in the function**. `Debug()` calls this unconditionally for every document, regardless of `--objcheck`. Its own doc-comment ("recursively descends into objects and arrays") describes the recursion as intentional, with no accompanying depth safeguard.

## Steps to Reproduce

**Step 1 — get the `bsondump` binary.** Building from source is not required — it's what I used because my testing environment couldn't reach `fastdl.mongodb.org` to pull the official release, not because a source build is somehow necessary to trigger this. Either of the following gets the same binary:

*Option A (preferred, no toolchain needed) — download the official prebuilt binary directly from `fastdl.mongodb.org`:*
```
curl -sL -o tools.tgz \
  https://fastdl.mongodb.org/tools/db/mongodb-database-tools-ubuntu2404-x86_64-100.18.0.tgz
tar xzf tools.tgz --strip-components=2
./bsondump --version
```
This pulls the real, signed, officially-released `bsondump` binary straight from MongoDB's own distribution host — nothing locally built or modified. The URL above is for Ubuntu 24.04 x86_64; for any other OS/architecture, swap the platform segment (`ubuntu2404-x86_64`) for the correct one listed on the [Database Tools download page](https://www.mongodb.com/try/download/database-tools) — the rest of the URL and every step after stays the same.

*Option B (what I actually ran) — build from source, Go toolchain required:*
```
git clone https://github.com/mongodb/mongo-tools.git
cd mongo-tools && git checkout 100.18.0
go build -o bsondump-bin ./bsondump/main/
```

I have not personally verified Option A end-to-end in this pass — only Option B, since the download host was unreachable from my testing sandbox. There's nothing in the vulnerable code path (a pure Go logic bug reached by ordinary CLI flags) that would make a from-source build behave differently from the official release built from the identical tagged commit, but I'm flagging that I didn't independently confirm it rather than implying I did.

**Step 2 — build a malicious `.bson` file** nested 2,000,000 levels deep (`{"a":{"a":{"a": ... }}}`, 8 bytes/level, 16,000,005 bytes total) — the identical construction used in the standalone `mongo-go-driver` PoC (single flat pre-allocated buffer, O(depth), included as `genfile.go` in this directory).

**Step 3 — run with `--objcheck` (Path 1), crash confirmed:**
```
$ ./bsondump-bin --type=debug --objcheck malicious_2m.bson
runtime: goroutine stack exceeds 1000000000-byte limit
fatal error: stack overflow
... (crash trace showing dDecodeValue / empty_interface_codec.go / bsoncodec.go
     from the vendored go.mongodb.org/mongo-driver/v2/bson package)
```
Exit code 2. Full trace: `crash_trace_head.txt` / `crash_trace_tail.txt` (included in this directory) — the tail shows the same 5-frame `dDecodeValue → ValueDecoderFunc.DecodeValue → decodeTypeOrValueWithInfo → emptyInterfaceCodec.decodeType → emptyInterfaceCodec.DecodeValue` cycle documented in the standalone driver report, repeating from `mongo-tools/vendor/go.mongodb.org/mongo-driver/v2/bson/...` paths, confirming this is the vendored driver's code, reached directly through `bsondump`'s own `--objcheck` call.

**Path 2 (`printBSON`, no `--objcheck` needed)**: confirmed present by direct code reading (unconditional recursion, no depth guard, in `Debug()`'s default call path). I was not able to drive this specific path to a clean stack-overflow crash within my testing time budget — its per-level stack frame is small (a handful of `fmt.Fprintf` calls) and each level also produces proportional text output, so reproducing a crash requires either much greater nesting depth than Path 1 or redirecting output away from any I/O-bound sink; at 100,000 levels it was still producing output after 30 seconds without erroring or crashing. I'm flagging it as analytically confirmed (structurally identical recursion, verified absent of any depth tracking, by direct code reading) rather than empirically crashed, and distinguishing that clearly from Path 1, which **is** fully empirically confirmed.

## Impact

Any user or automated pipeline that runs `bsondump --type=debug --objcheck` against a `.bson` file from any source they don't fully trust — a file downloaded from elsewhere, received from another party, extracted from an archive, or produced by any other tool — can have the `bsondump` process crash unconditionally and uncatchably (Go's `fatal error: stack overflow` cannot be caught by any `recover()` or error handling in the tool) via a single crafted file. `--objcheck` is specifically the flag documented as validating BSON data, so it is reasonable to expect it to be used in exactly this kind of "check this untrusted file before trusting it" scenario — making the crash more likely to occur exactly when a user is being appropriately cautious. This is a local file-processing crash (denial of service against the `bsondump` process, not a network-reachable or credentialed exploit), but requires no more than possession of a single malicious file well under any BSON document size sanity check.

## Suggested Fix

- Once the depth-tracking fix is applied to `mongo-go-driver`'s `DecodeContext` (see the standalone driver report's suggested fix), update `mongo-tools`' vendored driver dependency to pick it up — this resolves Path 1.
- Independently, add an explicit depth parameter to `printBSON` itself, incrementing on each recursive call and returning an error past a fixed maximum (matching MongoDB server's own 100-level document-nesting limit), since this is first-party code with its own separate defect that a driver-side fix would not touch.

## Honest Caveats

- Path 1 is fully empirically confirmed (real binary built from this exact tagged source, real crash, full trace showing the vendored driver's vulnerable call chain). Path 2 is confirmed present by direct code reading but not independently driven to a clean crash within my testing time budget — see above.
- This finding assumes the standalone `mongo-go-driver` report (Path 1's root cause) is accepted as valid; if that report is instead deemed out of scope or already known, Path 1 here would inherit the same determination, though Path 2 (first-party `printBSON`) stands independently either way.
- No access to HackerOne's private report database — cannot rule out this has already been reported, though "bsondump specifically, not just the underlying driver" is a distinct, tool-level reachability claim not covered by a driver-only report.

## Supporting Material

- Path 1 call site: [`bsondump/bsondump.go#L196-L203`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/bsondump/bsondump.go#L196-L203)
- Path 2 (`printBSON`): [`bsondump/bsondump.go#L222-L253`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/bsondump/bsondump.go#L222-L253)
- `genfile.go` (malicious-file generator, shared construction with the standalone driver PoC), `crash_trace_head.txt`, `crash_trace_tail.txt`, `exit_code.txt` (included in this directory)
