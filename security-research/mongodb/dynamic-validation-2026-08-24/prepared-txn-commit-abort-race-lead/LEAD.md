# Lead: residual bypass of the prepared-transaction commit/abort authorization fix (SERVER-130544)

> **Recovery note (2026-08-28):** reconstructed verbatim after the working container was recycled
> before a successful push. A sharded-cluster reproduction attempt against this lead was in
> progress (config server + 2 shard replica sets + mongos, all stood up, `enableTestCommands`
> restart in flight) when the reset happened — no test result had been produced yet, so nothing
> substantive was lost on the *results* side of this lead, only the infrastructure setup work.

**Status before this pass:** static-only. This document is the plan; `RESULTS.md` in this
directory (once written) carries the live outcome.

## Background — what's already fixed

`58c8bdff08` (`SERVER-130544`, Copilot-Autofix-flagged, ancestor of `r8.3.8`) fixed a real bug: any
ordinary `readWrite` user could directly call `commitTransaction`/`abortTransaction` against an
individual shard holding a **prepared** cross-shard (2PC) transaction participant, bypassing the
transaction coordinator entirely. This could split-brain a distributed transaction — e.g. a client
commits one participant directly while the coordinator later tells the *other* participants to
abort (or vice versa), breaking atomicity across shards.

The fix (`src/mongo/db/commands/txn_cmds.cpp`):
```cpp
void verifyAuthorizedToAlterPreparedTransaction(OperationContext* opCtx,
                                                const DatabaseName& dbName) {
    auto txnParticipant = TransactionParticipant::get(opCtx);
    uassert(
        ErrorCodes::Unauthorized,
        "Only internal clients may commit or abort prepared transactions",
        !txnParticipant.transactionIsPrepared() ||
            AuthorizationSession::get(opCtx->getClient())
                ->isAuthorizedForActionsOnResource(
                    ResourcePattern::forClusterResource(dbName.tenantId()), ActionType::internal));
}
```
called from both `CmdCommitTxn::Invocation::typedRun` and `CmdAbortTxn::Invocation::typedRun`,
**after** the standard `NoSuchTransaction`/`transactionIsOpen()` checks and **before** the actual
commit/abort logic runs.

## What was checked statically (prior pass) and what's still open

Confirmed via static reading that the only two commands that can drive a participant into or out
of the "prepared" state on the client-observable surface — `PrepareTransactionCmd` and
`CoordinateCommitTransactionCmd` (`src/mongo/db/s/txn_two_phase_commit_cmds.cpp`) — both already
gate on `ActionType::internal` via their own `doCheckAuthorization()`, the same airtight pattern
already independently verified elsewhere in this program to reject even the `root` superuser.

**What static reading can't settle, and this pass is for:**

1. **Does the fix actually hold under the exact adversarial timing the vendor's own regression
   test constructs** — freezing the 2PC coordinator at `hangBeforeWritingDecision` (after every
   participant has prepared and voted, but before the coordinator's decision is written or sent),
   and having the low-privilege user attempt the direct commit/abort on the participant at that
   precise moment? This is the worst-case race window for a fix like this — if there's a TOCTOU gap
   between `verifyAuthorizedToAlterPreparedTransaction`'s check and the actual commit/abort
   proceeding, this is where it would show up.
2. Does the same rejection hold for **both** `commitTransaction` (with an attacker-chosen, wrong
   `commitTimestamp`) and `abortTransaction`?
3. Does atomicity actually hold end-to-end afterward — does the coordinator's own commit still
   land correctly on the participant once the coordinator is released, proving the attacker's
   direct attempt didn't leave the participant in a bad state even though it was rejected?

## Reproduction plan

Mirrors `jstests/sharding/txn_prepared_participant_unauthorized_commit_abort.js` (in the real
mongodb source tree, already read in full) exactly, but driven by hand via `pymongo` against raw
binaries (no `mongosh` available in this environment) rather than the JS test framework:

1. Stand up a 2-shard sharded cluster: 1-node config server replica set, 2 single-node shard
   replica sets, 1 `mongos` — all with `--auth` and a shared keyfile (so the coordinator/participant
   RPCs authenticate as the internal `__system` cluster user, matching how the vendor test does it).
2. Shard a collection with `_id` as the shard key, split so `_id < 0` lives on shard0 and
   `_id >= 0` lives on shard1 — this makes shard0's primary the natural 2PC coordinator for any
   transaction that writes to both chunks.
3. Create a low-privilege user (`readWrite` on the test db only, no `directShardOperations`, no
   cluster/internal privilege) on **both** the cluster (via mongos, so config-server-backed auth
   resolves it) and directly on the participant shard (a direct connection to a shard resolves
   users from that shard's own local user store, and the logical-session uid is
   `SHA256("user@db")` — purely name-based — so the same user created on both resolves to the
   identical session uid the coordinator used when it prepared that participant).
4. As that user, start a cross-shard, multi-statement transaction via `mongos` (one write to each
   chunk) and drive it toward commit in a background thread.
5. Enable the `hangBeforeWritingDecision` failpoint on the coordinator (shard0's primary) as the
   cluster user, and wait for the background commit thread to hit it — at that point every
   participant (including shard1) has prepared and voted, and the coordinator is frozen before
   deciding.
6. **The actual test**: open a direct connection to shard1 (the pure participant) as the
   low-privilege user and issue `commitTransaction`/`abortTransaction` directly against it, with the
   same `lsid`/`txnNumber` as the frozen transaction. Expect (per the fix): `Unauthorized`.
7. Release the coordinator failpoint, let the background commit finish through mongos, and verify
   both shards ended up in the same, coordinator-decided state (both writes visible, or in the
   abort variant, that a well-formed commit still went through unaffected by the direct-abort
   attempt).

## Infrastructure notes from the in-progress setup attempt (pre-reset)

- Both `configureFailPoint` and the `waitForFailPoint` command used to detect when the coordinator
  has actually reached the freeze point are `testOnly()` (`src/mongo/db/commands/fail_point_cmd.cpp`)
  — the whole cluster needs `--setParameter enableTestCommands=1` on every node, not just the one
  being queried, matching how `ShardingTest` always runs.
- Creating the low-privilege user directly on a shard (rather than via mongos) cannot rely on the
  localhost exception the way the config-server user creation can, because `authutil.asCluster` in
  the real JS test authenticates as the internal `__system` user first — confirmed by testing: a
  bare `createUser` against a shard with no prior auth is rejected `Unauthorized`, not accepted via
  the localhost exception. The working approach is to authenticate directly as `__system` using the
  keyfile's own contents (stripped of whitespace) as the SCRAM password against the `local` auth
  database — this mirrors what the server's own intracluster auth does (confirmed via `mongos`'s own
  log lines showing exactly this: `"Speculative authentication to remote host succeeded", "username":
  "__system", "targetDatabase": "local", "mechanism": "SCRAM-SHA-256"`).

## What a positive finding would look like

Any of: the direct commit/abort **succeeding** (not rejected) during the frozen window; the
rejection succeeding but the participant's on-disk state being altered anyway (checked via the
oplog entries and eventual document visibility, exactly as the vendor test does); or the
coordinator's own commit subsequently failing/diverging because of the attacker's interference.
Any of these would mean the fix doesn't fully hold and the atomicity-violation bug SERVER-130544
targeted is still reachable by an ordinary, low-privilege user.
