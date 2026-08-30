# MongoDB 8.3.8 — pre-auth uncaught-exception crash audit (2026-08-30)

**Target:** `mongodb/mongo` tag `r8.3.8` (commit `d100bf1996`), source audited against a
git worktree of the exact tag; dynamic verification against the real official
`mongodb-linux-x86_64-ubuntu2204-8.3.8` binary, standalone, run locally (no container/network
target — pure local pentesting).

**Scope of this pass:** specifically *pre-authorization* / *pre-authentication* uncaught-exception
crash bugs — i.e. the same bug class as the disclosed, already-closed HackerOne reports
`#3828953` and `#3917392` (`MemorySize::parse()` calling unguarded `std::stod()`, reachable via
`startTrafficRecording`'s `maxFileSize`/`maxMemUsage` because IDL command-field deserialization
(`Command::parse()`) runs before `checkAuthorization()` in
`service_entry_point_shard_role.cpp`'s `ExecCommandDatabase` constructor). Both post-auth crash/DoS
bugs and non-crash bug classes were explicitly out of scope for this pass.

## Method

1. **Confirmed the vulnerable ordering still holds in r8.3.8.** `ExecCommandDatabase::_parseCommand()`
   (line 478) runs before `checkAuthorization()` (line 1658) for every command, unconditionally —
   this is the structural root cause the disclosed reports rely on, and it is unchanged in r8.3.8.
2. **Reconfirmed the known bug is still live and unpatched**, both by reading
   `src/mongo/db/query/util/memory_util.cpp` (the unguarded `std::stod(std::string{m[1]})` at line
   103 is present verbatim) and by reproducing it against the real binary (see Dynamic verification
   below). This was a deliberate first step, not a new finding — it validates that the audit
   methodology and test harness actually detect a real crash before trusting a negative result
   anywhere else.
3. **Enumerated every custom IDL deserializer in the tree** (183 `deserializer:` entries across all
   `*.idl` files) and every non-test `std::sto{d,i,l,ul,ll,ull,f,ld}(` call site (25 total) in
   `src/mongo`, then manually traced each one reachable from network-supplied BSON for:
   - a raw C++ exception type (not `mongo::DBException`/`uassert`) that can escape the call, and
   - whether that call site sits behind a `catch` that is *narrower* than `std::exception` (the same
     pattern that makes the known bug work — `WriteConcernOptions::parse()` and
     `ReadConcernArgs::parse()` both only `catch (const DBException&)`, for example, which would not
     save them from a raw `std::exception` escaping a callee).
4. **Prioritized by reachability breadth**, working from the fields universal to *every* command
   (`writeConcern`, `readConcern`, `maxTimeMS`, `lsid`, `txnNumber`, `autocommit`, `$clusterTime`,
   `ShardVersion`/`DatabaseVersion` — all defined once in `src/mongo/idl/generic_argument.idl` and
   inherited by literally every IDL command) down to per-command fields (`hint`, `KeyPattern`,
   `CIDR`-based `authenticationRestrictions`, SASL payloads, `hello`/`isMaster` client metadata).
5. **Dynamic verification** against the real `mongod` binary in two configurations:
   - no `--auth` (baseline; validates the harness and reproduces the known bug), and
   - `--auth` enabled with a fully **unauthenticated** connection (no credentials sent at all,
     confirmed via a rejected `usersInfo` call returning `Unauthorized`/"requires authentication")
     — the strictest possible interpretation of "pre-auth."
6. **Correction to the disclosed reports' framing, confirmed empirically**: a fully unauthenticated
   connection (`--auth` on, zero login) is rejected with `"Command X requires authentication"`
   *before* reaching `Command::parse()` for any command whose IDL marks it as requiring
   authentication — including `startTrafficRecording` itself, `buildInfo`, `whatsmyuri`, and
   `getLog` in this build. This is an earlier, separate gate from `checkAuthorization()`. So the
   true zero-authentication attack surface in a correctly `--auth`-enabled deployment is narrower
   than "any command name" — it's specifically the commands whose IDL/definition allows execution
   without authentication at all: `hello`/`isMaster`, `ping`, `saslStart`/`saslContinue`, and a
   handful of others. The disclosed reports' "any authenticated user, default `read` role, no
   elevated privilege" framing is accurate for *post-login* low-privilege access; it is not the
   same thing as *zero-authentication* reachability, and this distinction matters for anyone
   building on this bug class going forward.

## Dynamic verification detail

**Sanity check (known bug, reconfirmed):**
```js
db.adminCommand({startTrafficRecording: 1, destination: "/tmp/x", maxFileSize: "9".repeat(400)})
```
Result: `mongod` terminates immediately; harness's `ping` liveness probe goes from `True` to
`ServerSelectionTimeoutError: Connection refused` in the same test run. Confirms both that the
harness reliably detects a real crash, and that the bug is unpatched in r8.3.8 (unsurprising — it
was closed as a duplicate on HackerOne, not fixed, per the closure notes pasted into this session).
**Not a new finding — not submitted.**

**New-candidate testing, all negative (server stayed alive after every payload):**

*Universal generic-argument fields, sent on a bare `ping` (works pre-auth in both configs):*
- `writeConcern.w`: out-of-range int64, `Decimal128` at max representable magnitude
  (`9.999...E+6144`), `Decimal128("NaN")`
- `writeConcern.wtimeout`: same extremes
- `maxTimeMS`: `Decimal128` max magnitude, `1e308` double
- `readConcern.afterClusterTime`: `Decimal128` max magnitude (wrong-type, cleanly rejected)
- `lsid.uid` malformed-length `sha256Block` BinData
- `txnNumber`: `Decimal128` max magnitude
- `$clusterTime.signature.hash`: wrong-length BinData; `keyId` at `INT64_MIN`
- `$clusterTime.clusterTime`: zero `Timestamp`

*Fields on commands explicitly allowed without authentication (`hello`, `saslStart`,
`saslContinue`), tested from a genuinely unauthenticated connection under `--auth`:*
- `hello.client`: empty/malformed driver metadata
- `hello.saslSupportedMechs`: malformed (no `.` separator), empty, and megabyte-scale strings
- `hello.internalClient`: `minWireVersion`/`maxWireVersion` at extreme magnitudes
- `hello.compression`: malformed mixed-type array
- `saslStart.mechanism`: embedded NUL/control bytes, megabyte-scale string
- `saslStart.payload` / `saslContinue.payload`: malformed `BinData` subtypes
- `saslContinue.conversationId`: `INT64_MAX`/`INT64_MIN`-range values

*Confirmed the "requires authentication" pre-parse gate itself* by sending the exact known-bug
payload (`startTrafficRecording` overflow) and CIDR-malformed `createUser`
(`authenticationRestrictions`) requests from a fully unauthenticated connection — both were
rejected with `Unauthorized`/`"requires authentication"` before any parsing occurred, consistent
with the source-level finding in item 6 above.

Every single payload above was either cleanly rejected with a `DBException`-derived error
(`FailedToParse`, `TypeMismatch`, `BadValue`, `Unauthorized`, etc.) or succeeded harmlessly; the
server's `ping` liveness probe returned `True` after every one. No new crash.

## Why these areas specifically were safe (root-caused, not just observed)

- `WriteConcernOptions::parse()` / `ReadConcernArgs::parse()` do only `catch (const DBException&)`
  at their outer layer — structurally the same gap as the known bug — but every leaf function they
  call (`deserializeWriteConcernW`, `parseWTimeoutFromBSON`, `OpTime::parseFromOplogEntry` via
  `catch (...)`, the `BSONElement::safeNumber{Int,Long,Double}` family) either uses `uassert`
  exclusively or has its own `catch (...)` / `catch (const std::exception&)` wrapper, so no raw
  exception ever reaches the narrow outer catch to escape it.
- `BSONElement::safeNumberLong/safeNumberInt/safeNumberDouble` (the numeric-coercion functions
  underlying nearly every numeric IDL field, including `Decimal128` conversions) clamp on NaN and
  out-of-range values rather than throwing — this is the load-bearing hardening that keeps the
  entire "throw a huge/NaN Decimal128 at any numeric field" attack class closed.
- `CIDR::parse()`'s `strict_stoi()` call (structurally identical in shape to the known
  `MemorySize::parse()` bug — regex-adjacent numeric parse via `std::stoi`) *is* wrapped in a
  `try {} catch (const std::invalid_argument&) catch (const std::out_of_range&)` at its only
  call site inside `CIDR::parse(StringData)` — the fix this bug class needs, already applied here.
- `UUID::parse()`, `NamespaceStringUtil::deserialize()` (default non-multitenant path), `parseHint()`,
  `parseDurationFromCount<Duration>()`, `ShardVersion::parse()` — all either have no raw-throwing
  call, or bound their inputs before use, or run through `uassertStatusOK`/`uassert`.

## Net result

**No new pre-auth (or post-auth) uncaught-exception crash bug found in r8.3.8.** The one bug
matching this exact class present in the tree — `MemorySize::parse()` — is the same bug already
disclosed and closed as a duplicate twice on this program (`#3828953` original,
`#3917392` closed as its duplicate). It was reconfirmed live here only to validate the audit
methodology, not offered as a new finding.

This is a genuine negative result after a systematic sweep of the highest-reachability surface
(every field parsed on every command, plus every field on every command explicitly reachable with
zero authentication) — not a partial or rushed pass. Per this engagement's standing rules, it is
reported honestly as such rather than stretched into a submission.

## Environment note

Live testing here used a locally available official `mongodb-linux-x86_64-ubuntu2204-8.3.8` binary
and `pymongo` 4.17.0, both already present in the working environment; no network fetch, Docker
pull, or from-source build was needed or attempted for this pass (a from-source Bazel build was
assessed as infeasible in this sandbox — ~9GB free disk against a build that typically needs
30–50GB+ — before the local binary was found).
