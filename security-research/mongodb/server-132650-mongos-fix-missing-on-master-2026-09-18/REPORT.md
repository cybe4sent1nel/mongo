# Title

CVE-2026-82075 / SERVER-132650's mongos fix (pre-auth streaming-`hello` minimum timeout) was never forward-ported to `master` — the unauthenticated CPU-exhaustion DoS is unfixed on the current development tip

## Summary

CVE-2026-82075 (CVSS 8.7) is an unauthenticated denial-of-service in `mongos`: a pre-auth client using the awaitable/streaming `hello` protocol (`topologyVersion` + `maxAwaitTimeMS`) can set `maxAwaitTimeMS` to `0` (or any tiny value), driving `mongos`'s topology-change-wait loop to return almost instantly instead of actually waiting — and, combined with the exhaust ("moreToCome") variant of the command, this lets an unauthenticated client force `mongos` into a tight, uncontrolled polling loop with no rate limit, consuming CPU with no admission control and no privilege required (`SERVER-132650`, fixed and shipped in `7.0.41`, `8.0.30`, `8.2.13`, `8.3.9`, and per the ticket's own Fix Version list, `9.0.0-rc2`/`9.1.0-rc0`/`9.1.0-rc1023`).

The fix itself (confirmed present in this repo's `r8.3.11` checkout) is a `minWaitForStreamingHelloMillis` server parameter, enforced identically on both `mongod` (pre-existing, via the earlier `SERVER-128517`) and `mongos` (the new part, `SERVER-132650`): if an **unauthenticated** client's `maxAwaitTimeMS` is below the configured minimum, the server either rejects the request (`InvalidOptions`) or clamps the effective wait up to the minimum, depending on `abortStreamingHelloWithSmallTimeout`. Authenticated clients are exempt (checked via `AuthorizationSession::isAuthenticated()`).

**On `mongodb/mongo`'s `master` branch (HEAD at the time of this audit, commit `aa0b12ef`, 2026-09-18), the mongos side of this fix does not exist at all.** `src/mongo/s/commands/cluster_hello_cmd.cpp` on master:

```cpp
// master, src/mongo/s/commands/cluster_hello_cmd.cpp:198-224 (current)
auto clientTopologyVersion = cmd.getTopologyVersion();
auto maxAwaitTimeMS = cmd.getMaxAwaitTimeMS();
auto curOp = CurOp::get(opCtx);
boost::optional<Date_t> deadline;
boost::optional<ScopeGuard<std::function<void()>>> timerGuard;
if (clientTopologyVersion && maxAwaitTimeMS) {
    uassert(51758, "topologyVersion must have a non-negative counter",
            clientTopologyVersion->getCounter() >= 0);

    uassert(51759, "maxAwaitTimeMS must be a non-negative integer", *maxAwaitTimeMS >= 0);
    // <-- nothing else. No minWaitForStreamingHelloMillis check, no auth-session
    //     check, no clamp, no reject. maxAwaitTimeMS = 0 sails straight through.

    deadline = opCtx->getServiceContext()->getPreciseClockSource()->now() +
        Milliseconds(*maxAwaitTimeMS);
    ...
```

Compare against the fixed `r8.3.11` release tag's exact same function:

```cpp
// r8.3.11 (fixed), src/mongo/s/commands/cluster_hello_cmd.cpp:219-251
if (clientTopologyVersion && maxAwaitTimeMS) {
    uassert(51758, "topologyVersion must have a non-negative counter",
            clientTopologyVersion->getCounter() >= 0);
    uassert(51759, "maxAwaitTimeMS must be a non-negative integer", *maxAwaitTimeMS >= 0);

    auto minWait = repl::minWaitForStreamingHelloMillis.load();
    if (minWait > 0 && *maxAwaitTimeMS < minWait) {
        auto* authSession = AuthorizationSession::get(opCtx->getClient());
        if (!authSession || !authSession->isAuthenticated()) {
            bool willAbort = repl::abortStreamingHelloWithSmallTimeout.load();
            ...
            uassert(ErrorCodes::InvalidOptions,
                    fmt::format("maxAwaitTimeMS of {} ms is below the minimum of {} ms",
                                *maxAwaitTimeMS, minWait),
                    !willAbort);
            maxAwaitTimeMS = minWait;   // clamp
        }
    }
    deadline = ...
```

Confirmed by direct string search: `grep -rln "minWaitForStreamingHelloMillis" src/mongo/` on master returns only `src/mongo/db/repl/replication_info.cpp` (the `mongod` side, which has always had this protection since `SERVER-128517`) and the IDL parameter definition itself — `src/mongo/s/commands/cluster_hello_cmd.cpp` is not in that list. `git log --oneline -- src/mongo/s/commands/cluster_hello_cmd.cpp` on master shows the file's most recent change is `SERVER-130148` (connection-backpressure metrics) — a ticket numbered well before `SERVER-132650`, and nothing referencing `132650`, `minWaitForStreamingHello`, or this CVE appears anywhere in the file's history on this branch. The fix landed on the four release branches this CVE was backported to, but the corresponding change to mainline appears to have been missed.

## Impact

Identical to CVE-2026-82075 itself: any network client with TCP access to a `mongos` port — no authentication, no prior handshake beyond the pre-auth-permitted `hello` command — can send a streaming/exhaust `hello` with `maxAwaitTimeMS: 0` repeatedly (or once, in exhaust mode, to get a sustained tight loop) and force `mongos` to spend CPU on topology-check iterations at an unbounded rate, degrading or denying service to legitimate clients of that router. This reproduces the exact CVE on any build of MongoDB compiled from the current `master` branch, and on any future minor/patch release cut from master before this gap is closed (the ticket's own Fix Version list already claims `9.0.0-rc2`/`9.1.0-rc0`/`9.1.0-rc1023` are fixed, which is inconsistent with what is actually present in `master`'s current history — either those RC tags were cut from a divergent branch that already had the fix and it was never merged back, or the merge-forward step was simply missed).

## Weakness

CWE-400 (Uncontrolled Resource Consumption), reachable pre-authentication — identical classification to the parent CVE, since this is not a new bug but the absence of its fix on this branch.

## Component / Version

- Repository: `mongodb/mongo`
- Branch: `master`, confirmed at commit `aa0b12ef37558f0cdd6e9d04c995abbe8010062` (dated 2026-09-18, the date of this audit)
- Contrast: tag `r8.3.11` (the CVE's actual fix, present and correctly enforced) and `src/mongo/db/repl/replication_info.cpp` (the `mongod`-side enforcement, present on both master and `r8.3.11`)

## Suggested fix

Forward-port the `SERVER-132650` change to `master`: add the same `minWaitForStreamingHelloMillis`/`abortStreamingHelloWithSmallTimeout` check (gated on `!AuthorizationSession::isAuthenticated()`) to `src/mongo/s/commands/cluster_hello_cmd.cpp`'s `runWithReplyBuilder`, mirroring `replication_info.cpp`'s existing logic exactly, as was done for the `7.0`/`8.0`/`8.2`/`8.3` release branches.

## Suggested repro (static analysis only — not executed against a live cluster in this environment)

1. Build `mongos` from `master` (or confirm via code review, as done here, since the guard is provably absent — a build was not attempted in this sandboxed environment).
2. Without authenticating, send: `{hello: 1, topologyVersion: {processId: ObjectId(), counter: 0}, maxAwaitTimeMS: 0, exhaustAllowed: true}` (or repeat non-exhaust calls with `maxAwaitTimeMS: 0`) against a `mongos` listening port.
3. Observe (via `mongostat`/CPU monitoring, or the request-handling admission control counters) that `mongos` processes these at an uncontrolled rate with no floor on the wait duration, unlike an authenticated client's behavior which is unaffected either way.

## Notes on scope

This audit was specifically directed at finding fresh, unpatched siblings of CVE-2026-82075 (SERVER-132650) and CVE-2026-82064 (SERVER-130759) on the latest `r8.3.11` tag and checking their presence on `master`. This finding is not a "sibling" in the usual sense — it is the parent bug itself, confirmed present, unmodified, on the tip of development. The `mongod`-side protection (`SERVER-128517`, the ticket SERVER-132650 explicitly extends) is intact on both branches; only the `mongos` extension is missing on `master`. The second requested bug, CVE-2026-82064 / SERVER-130759 (arbiter invariant), is covered in a separate report from the same audit pass, since its own Jira history already shows signs the fix may have been reverted on master independent of anything found here.
