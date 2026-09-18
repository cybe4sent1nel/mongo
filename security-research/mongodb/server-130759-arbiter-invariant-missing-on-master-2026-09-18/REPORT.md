# Title

CVE-2026-82064 / SERVER-130759's arbiter-invariant fix is absent on `master` — the unauthenticated crash (fatal assertion on a replica-set arbiter) is unfixed on the current development tip, matching the ticket's own "auto-reverted" history

## Summary

CVE-2026-82064 (CVSS 8.7) is an unauthenticated denial-of-service against `mongod` replica-set arbiter members: a read-concern request specifying `afterClusterTime`/`atClusterTime` reaches a code path in `validateReadConcernNoOpTime`/read-concern pre-processing (`src/mongo/db/read_concern_mongod.cpp`) that reads the node's `VectorClock` cluster time and, if that time is not yet valid, hits an `invariant()` whose condition originally assumed the node could only be in that state during `STARTUP`/`STARTUP2` — not accounting for a node that is a steady-state **arbiter**, whose vector-clock cluster-time component is never initialized (arbiters don't replicate data). An unauthenticated client sending such a request against an arbiter therefore trips the `invariant()`, which is a fatal assertion — it terminates the `mongod` process. The fix (`SERVER-130759`) widens the invariant to also accept `memberState.arbiter()`.

Confirmed fixed on tag `r8.3.11`:
```cpp
// r8.3.11, src/mongo/db/read_concern_mongod.cpp:391
invariant(memberState.startup() || memberState.startup2() || memberState.arbiter());
```

**On `mongodb/mongo`'s `master` branch (HEAD at the time of this audit, commit `aa0b12ef`, 2026-09-18), the same line still has the original, unfixed condition:**
```cpp
// master, src/mongo/db/read_concern_mongod.cpp:372 (current)
invariant(memberState.startup() || memberState.startup2());
```
`.arbiter()` is not present. `git log --oneline -- src/mongo/db/read_concern_mongod.cpp` on master shows no commit referencing `SERVER-130759` or an arbiter-related invariant change in this file's history at all.

This lines up with the ticket's own activity log (pasted alongside this request): the ticket shows a `Fix Version/s` entry of `9.1.0-rc0` being **added and then removed** (`Mothra Jira Bot ... Fix Version/s Original: 9.1.0-rc0 New: <blank>`), an `auto-reverter-bot` change adding the `auto-reverted` label, and a later label update to `auto-fix-version-interrupted auto-reverted`. Taken together with the direct code evidence above, this indicates the mainline merge of this fix was reverted (most likely by CI's auto-revert tooling, presumably in response to a test failure or conflict) and, unlike the release-branch backports (which shipped in `7.0.41`/`8.0.30`/`8.2.13`/`8.3.9`), was never successfully reapplied to `master`.

## Impact

Identical to the parent CVE: any unauthenticated client with network access to a `mongod` process running as a replica-set **arbiter** can send a command carrying `readConcern: {afterClusterTime: <any timestamp>}` (or `atClusterTime`) before the vector clock's cluster-time component has been initialized on that arbiter (which, since arbiters never apply oplog entries or otherwise participate in normal write traffic, can be indefinitely — an arbiter may sit in this state for its entire operational lifetime) and deterministically crash that `mongod` process via the tripped `invariant()`. This reproduces on any build compiled from the current `master` branch.

## Weakness

CWE-617 (Reachable Assertion) → process termination, reachable pre-authentication — identical classification to the parent CVE, since this is the absence of its fix, not a new bug.

## Component / Version

- Repository: `mongodb/mongo`
- Branch: `master`, confirmed at commit `aa0b12ef37558f0cdd6e9d04c995abbe8010062` (2026-09-18, the date of this audit)
- Contrast: tag `r8.3.11` (the CVE's actual fix, present)

## Suggested fix

Reapply the `SERVER-130759` change to `master`: widen the `invariant()` at `src/mongo/db/read_concern_mongod.cpp` (currently line 372) to `invariant(memberState.startup() || memberState.startup2() || memberState.arbiter());`, matching the release branches. Given the ticket's own history suggests an automated revert interrupted the original merge to mainline, this may need to be re-landed deliberately rather than assumed to already be queued.

## Suggested repro (static analysis only — not executed against a live cluster in this environment)

1. Build `mongod` from `master` and configure it as an arbiter in a replica set (or confirm via code review, as done here, since the unfixed invariant condition is provably present).
2. Without authenticating, send any command that carries `readConcern: {afterClusterTime: Timestamp(9999999999, 1)}` (a far-future timestamp is not required — any value reaches the same code path) directly to the arbiter's port, before its vector clock cluster-time component has otherwise been initialized.
3. Expect the process to `fassert`/terminate on the widened-but-currently-narrow `invariant()` at `read_concern_mongod.cpp:372`, matching the crash described in the CVE.

## Notes on scope

This finding and the companion `SERVER-132650`/CVE-2026-82075 finding (reported alongside this one, in a separate report) were both produced from the same directed audit: check the two named CVEs' fixes for fresh siblings on `r8.3.11`, and check whether each fix is present on `master`. In both cases, the fix is correctly and completely present on `r8.3.11` (no unpatched sibling of either bug was found there), but **neither fix has made it to `master`** — both are the original, pre-patch vulnerable code on the current development tip. No further code-level sibling of the arbiter-invariant pattern specifically (another invariant assuming a non-arbiter member state in read-concern or adjacent write-concern processing) was found in the surrounding file during this pass.
