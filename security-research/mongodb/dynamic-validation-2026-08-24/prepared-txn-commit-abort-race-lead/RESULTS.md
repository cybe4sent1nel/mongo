# Results: prepared-transaction commit/abort authorization race (SERVER-130544) (2026-08-28)

**Status: negative — the fix holds.** Confirmed under the exact adversarial timing the vendor's own
regression test (`jstests/sharding/txn_prepared_participant_unauthorized_commit_abort.js`) exercises:
an ordinary `readWrite` user's direct `commitTransaction`/`abortTransaction` against a genuinely
**prepared** participant is rejected `Unauthorized`, and atomicity holds end-to-end afterward. No
bypass found. Recorded as a solid positive confirmation, not a weak negative — see "Why this
result is trustworthy" below for what makes it stronger evidence than a bare "got Unauthorized."

## Infrastructure

Real official 8.3.8 binaries (`mongod`/`mongos`, `gitVersion 35e8c8a57f78157ed9fac1a9e90ee6c1818adab6`,
obtained via the user's `mongo_tar` support repo after direct download paths were policy-blocked). A
2-shard sharded cluster: 1-node config server replica set (`cfgrs`, :27301), two 1-node shard replica
sets (`shard0rs` :27311, `shard1rs` :27321), one `mongos` (:27300) — all started with a shared
`--keyFile` and `--setParameter enableTestCommands=1` (required: both `configureFailPoint` and
`waitForFailPoint` are `testOnly()` commands). Collection sharded on `_id`, split so `_id < 0` lives
on shard0 (the natural 2PC coordinator) and `_id >= 0` lives on shard1 (pure participant). A
low-privilege `rwuser` (`readWrite` on the test db only, no cluster/internal privilege) created via
mongos.

## Method (mirrors the vendor's own JS regression test, driven by hand via `pymongo`)

1. `rwuser` starts a cross-shard, multi-statement transaction via `mongos` in a background thread:
   insert to shard0's chunk, insert to shard1's chunk, then `commitTransaction`.
2. As the internal `__system` user (authenticated via the keyfile's own contents as the SCRAM-SHA-256
   password against `authSource: local` — the same mechanism real intracluster auth uses), enable
   `hangBeforeWritingDecision` on the coordinator (shard0's primary) and use `waitForFailPoint` to
   block until the *current* transaction genuinely reaches that point — i.e. every participant,
   including shard1, has already prepared and voted, but no decision has been written yet.
3. While frozen: read shard1's own session catalog directly (`currentOp: 1`, matched by `txnNumber`)
   to confirm the participant genuinely holds a **prepared** transaction (`transaction.parameters`
   present, `timePreparedMicros` populated, `type: "idleSession"`) and extract its real `lsid`.
4. **The actual test**: open a direct connection to shard1 as `rwuser` and issue
   `commitTransaction` (with an attacker-chosen, wrong `commitTimestamp`) / `abortTransaction`
   directly against it, using that exact `lsid`/`txnNumber` — no coordinator involved at all.
5. Release the coordinator failpoint, let the legitimate background commit finish through `mongos`,
   and verify both shards ended up in the coordinator's decided state.

## Two real methodological traps hit and fixed along the way

Both are worth recording because they produced misleading intermediate results before the true
outcome emerged, and either one uncaught would have made this test's "negative" result meaningless:

1. **`waitForFailPoint`'s `timesEntered` is cumulative since the failpoint was created, not "N more
   times from now."** Reusing the same long-lived `shard0rs` process across repeated test runs meant
   a fixed `timesEntered: 1` was satisfied instantly by a *historical* hit from an earlier run,
   making `coordinator_frozen: True` a false positive — the script then fired its direct attack
   before the current transaction had even reached shard1, which corrupted that transaction's state
   and produced a spurious `NoSuchTransaction`. Fixed by reading the current count from
   `configureFailPoint`'s own response (`{'count': N, ...}`) and waiting for `N + 1`, guaranteeing a
   genuinely new hit.
2. **pymongo's `Database.command()` silently discards a manually-supplied `lsid` field**, replacing
   it on the wire with its own driver-managed implicit-session id — confirmed empirically (the `lsid`
   named in the resulting error never matched what was passed in the command dict, even after fixing
   trap #1). Manually setting `'lsid'` in the command body is exactly what the vendor's raw-shell JS
   test does and is *not* honored by pymongo's high-level API. Fixed by constructing a real
   `pymongo.synchronous.client_session._ServerSession` directly, forcing its `session_id` to the
   participant's actual prepared-transaction lsid (read live off shard1's own session catalog per
   step 3 above), and driving the attack command through `session=<that forced session>` — the one
   pymongo mechanism that does place a caller-chosen id on the wire.

## Result

```
=== TEST 1: direct COMMIT attempt on frozen prepared participant ===
  coordinator_frozen: True   (fp_baseline_count correctly incremented across runs, e.g. 18->20)
  shard1 session catalog:  transaction.parameters.txnNumber: 4242, timePreparedMicros: 101104
                           (genuinely prepared, matched via currentOp, real lsid extracted)
  direct_attempt_error: 13 Unauthorized: Only internal clients may commit or abort prepared transactions
  commit_via_mongos (after release): ok: 1.0, recoveryToken: {'recoveryShardId': 'shard0rs'}

=== TEST 2: direct ABORT attempt on frozen prepared participant ===
  coordinator_frozen: True
  shard1 session catalog:  transaction.parameters.txnNumber: 4343, timePreparedMicros: 94969
  direct_attempt_error: 13 Unauthorized: Only internal clients may commit or abort prepared transactions
  commit_via_mongos (after release): ok: 1.0, recoveryToken: {'recoveryShardId': 'shard0rs'}

Final documents visible via mongos: [{'_id': -2}, {'_id': -1}, {'_id': 1}, {'_id': 2}]
```

Both the direct commit (with an attacker-chosen wrong `commitTimestamp`) and the direct abort were
rejected with exactly the message `verifyAuthorizedToAlterPreparedTransaction` produces
(`txn_cmds.cpp`), at the precise moment the participant held a genuinely prepared transaction. The
legitimate cross-shard transaction then committed cleanly through `mongos` in both cases once the
coordinator was released, and all four documents (two per shard's chunk range) ended up correctly
visible — confirming the direct attack attempts left no residual damage and atomicity held
end-to-end.

## Why this result is trustworthy (not just "got the error we hoped for")

- The freeze was verified real, not assumed: `fp_baseline_count` was read fresh before each wait and
  the wait was for `count + 1`, so `coordinator_frozen: True` reflects an actual new hit for *this*
  transaction, not stale history (trap #1 above, caught and fixed rather than glossed over).
- The participant's prepared state was independently verified via its own session catalog
  (`currentOp`) *during* the freeze — `timePreparedMicros` populated, `txnNumber` matching — rather
  than inferred from the coordinator's state alone. This directly answers the open question this
  lead's static pass could not settle: shard1 genuinely is prepared by the time
  `hangBeforeWritingDecision` fires, confirming the failpoint's placement really does guarantee the
  precondition the vendor's test (and this repro) relies on.
- The attack request was confirmed to carry the *correct*, real prepared-transaction lsid on the
  wire (trap #2 above) — an `Unauthorized` against the wrong session/transaction would have been a
  meaningless result (rejected because no such transaction exists under that id, not because the
  authorization check ran). Forcing the real lsid onto the wire and re-observing the same
  `Unauthorized` (rather than `NoSuchTransaction`) is what makes this a genuine confirmation of the
  fix, not an artifact of a mismatched id.
- Both directions (`commitTransaction` and `abortTransaction`) were tested, and post-release
  atomicity was independently checked via the actual document state, not just the mongos response
  code.

## Conclusion

`SERVER-130544`'s fix (`verifyAuthorizedToAlterPreparedTransaction`) holds under the exact
adversarial timing this lead set out to test. No TOCTOU gap was found between the check and the
commit/abort proceeding, and no atomicity violation resulted from the rejected direct attempts. This
lead is closed as a confirmed non-finding — not submitted, not reported as a vulnerability.
