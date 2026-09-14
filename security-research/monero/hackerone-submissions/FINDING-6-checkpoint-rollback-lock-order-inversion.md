# Checkpoint enforcement/rollback path violates the codebase's own documented lock ordering (`blockchain_lock` → `tx_pool_lock`), creating a real deadlock cycle against the normal transaction-verification path

## Summary

`Blockchain` and `tx_memory_pool` each guard their state with their own recursive mutex (`m_blockchain_lock`, `m_transactions_lock`). Because almost every code path in the codebase needs both at once, the project documents and enforces a strict global ordering directly in a comment in `blockchain.cpp`: the transaction-pool lock must always be acquired *before* the blockchain lock, never the reverse. I traced every multi-lock call site in `blockchain.cpp`/`tx_pool.cpp`/`cryptonote_core.cpp` and found this order correctly followed everywhere — except one path: the periodic checkpoint-enforcement mechanism (triggered automatically by ordinary P2P block relay) takes `m_blockchain_lock` first and, on a checkpoint mismatch, calls all the way down into code that acquires `m_transactions_lock` second — the exact reverse of the documented rule, and the exact reverse of the order used by ordinary transaction verification (an RPC `send_raw_transaction` call, or a P2P-relayed transaction). Two threads hitting these two paths at the same time — one enforcing a checkpoint, one verifying an incoming transaction — can deadlock each other permanently.

## Severity

Monero severity: **MEDIUM**, per the project's own explicit precedent on the closest comparable report. Suggested CVSS v3.1: `4.8` with `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H`.

Rationale, referencing the project's own stated criteria from a very similar, already-resolved report (a JSON-RPC-triggered deadlock that fully paralyzed a node, requiring `kill -9`): the maintainers classified that report as Medium despite the reporter arguing for Critical/High, explaining that "remote RPC crash vulnerabilities are consistently classified as Medium... High severity is reserved for issues that affect the network as a whole, enable loss of funds, or pose systemic/catastrophic risk." This finding is the same *class* of consequence (a full node hang requiring a forced restart, not a fund-loss or network-wide issue), so I'm applying the same severity floor rather than arguing for something higher than the project's own precedent supports.

What pushes `AC:H` (high attack complexity) here rather than trivial: reaching the vulnerable side of the cycle requires the node's checkpoint-verification to actually detect a mismatch at one of the embedded/hardcoded checkpoint heights — this happens automatically and periodically (gated to roughly once per 10 minutes per node) as a side effect of ordinary block relay, but it only takes the problematic lock path when a mismatch is *found*, which does not happen in healthy, correctly-synced operation. It is a real, live, unconditionally-reachable code path (this is precisely the mechanism that punishes a node that got tricked onto an invalid chain past a checkpoint), just not a trigger an external attacker can force at will without first getting the target node onto a bad chain by some other means.

## Affected Versions

Confirmed present, by direct source comparison, in:

**`master`, commit `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f`** (the actively maintained branch):
- The documented lock-order rule: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_core/blockchain.cpp#L4886-L4899
- The violating function: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_core/blockchain.cpp#L4547-L4580
- Where it descends into the tx-pool lock while still holding the blockchain lock: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_core/blockchain.cpp#L680-L695

Also confirmed present in **`v0.18.5.1`**, the latest tagged release, commit `4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5` — same functions, same structure, only line numbers differ (`check_against_checkpoints` at line 4701, the documented order comment at line 5040, the `m_tx_pool.add_tx` call inside the `keep_txs` branch of `pop_block_from_blockchain` at line 655). This is not a recent regression; it appears to be a long-standing gap in an otherwise carefully-followed convention.

## Root Cause

The documented invariant, `src/cryptonote_core/blockchain.cpp` (inside `Blockchain::prepare_handle_incoming_blocks`):
```cpp
// Order of locking must be:
//  m_incoming_tx_lock (optional)
//  m_tx_pool lock
//  blockchain lock
//
//  Something which takes the blockchain lock may never take the txpool lock
//  if it has not provably taken the txpool lock earlier
//
//  The txpool lock is now taken in prepare_handle_incoming_blocks
//  and released in cleanup_handle_incoming_blocks. This avoids issues
//  when something uses the pool, which now uses the blockchain and
//  needs a batch, since a batch could otherwise be active while the
//  txpool and blockchain locks were not held

m_tx_pool.lock();
CRITICAL_REGION_LOCAL1(m_blockchain_lock);
```

**Side A — the violating path, blockchain lock acquired first:**

`Blockchain::check_against_checkpoints`:
```cpp
void Blockchain::check_against_checkpoints(const checkpoints& points, bool enforce)
{
  const auto& pts = points.get_points();
  bool stop_batch;

  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  stop_batch = m_db->batch_start();
  const uint64_t blockchain_height = m_db->height();
  for (const auto& pt : pts)
  {
    if (pt.first >= blockchain_height)
      continue;

    if (!points.check_block(pt.first, m_db->get_block_hash_from_height(pt.first)))
    {
      if (enforce)
      {
        LOG_ERROR("Local blockchain failed to pass a checkpoint, rolling back!");
        std::list<block> empty;
        rollback_blockchain_switching(empty, pt.first - 2);
      }
      ...
```
Note `m_blockchain_lock` is acquired at the very top, with no `m_tx_pool` lock taken first — already a violation of the documented rule by itself, before anything else happens.

`Blockchain::update_checkpoints` calls this with `enforce` hardcoded `true` for the embedded checkpoint list (not gated behind any command-line flag — only the *DNS* checkpoint check a few lines earlier is conditional):
```cpp
  if (m_enforce_dns_checkpoints && check_dns && !m_offline)
  {
    ...
    check_against_checkpoints(dns_points, false);
    ...
  }
  ...
  check_against_checkpoints(m_checkpoints, true);
```

`Blockchain::rollback_blockchain_switching` (called from the `enforce` branch above) also only takes `m_blockchain_lock` (recursive — fine on its own, but it's the *same* lock already held, still no tx-pool lock anywhere in this call chain):
```cpp
bool Blockchain::rollback_blockchain_switching(std::list<block>& original_chain, uint64_t rollback_height)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  ...
  while (m_db->height() != rollback_height)
  {
    pop_block_from_blockchain(/*keep_txs=*/true);
  }
  ...
```

`Blockchain::pop_block_from_blockchain`, with `keep_txs=true`, puts every non-coinbase transaction from the popped block(s) back into the mempool — and *this* is where `m_transactions_lock` finally gets acquired, second, while `m_blockchain_lock` is still held from every frame above:
```cpp
  if (keep_txs) for (transaction& tx : popped_txs)
  {
    ...
    const bool r = m_tx_pool.add_tx(tx, tvc, relay_method::block, true, version, version, valid_input_verification_id);
    ...
```
`tx_memory_pool::add_tx`'s very first action is `CRITICAL_REGION_LOCAL(m_transactions_lock)`. Realized order on this thread: **blockchain lock → tx-pool lock.**

This whole chain is reachable from ordinary P2P block relay: `t_cryptonote_protocol_handler<t_core>::handle_notify_new_fluffy_block` (`src/cryptonote_protocol/cryptonote_protocol_handler.inl`), the handler for `NOTIFY_NEW_FLUFFY_BLOCK` sent by any peer, does:
```cpp
    // load json & DNS checkpoints every 10min/hour respectively,
    // and verify them with respect to what blocks we already have
    CHECK_AND_ASSERT_MES(m_core.update_checkpoints(), 1, "One or more checkpoints loaded from json or dns conflicted with existing checkpoints.");
```
— unconditionally, on the P2P connection-handler thread that processed the relayed block, subject only to `update_checkpoints`'s own internal 10-minute/1-hour throttling and an atomic re-entrancy guard (`m_checkpoints_updating`), not to any external trigger the connecting peer controls.

**Side B — the normal path, tx-pool lock acquired first (the majority, documented-order-compliant path):**

Reachable via either the `send_raw_transaction` RPC handler or P2P relay of a new transaction:
```cpp
// core::handle_incoming_tx -> core::add_new_tx -> tx_memory_pool::add_tx
```
`tx_memory_pool::add_tx` takes `m_transactions_lock` first, then — during its verification of the transaction's inputs — calls `Blockchain::check_tx_inputs`, which does:
```cpp
bool Blockchain::check_tx_inputs(...)
{
  ...
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  ...
```
Realized order on this thread: **tx-pool lock → blockchain lock** — the documented, correct order, and the order followed everywhere else in the codebase I checked (`Blockchain::init`, `pop_blocks`, `create_block_template`, `add_new_block`, the pruning functions, `prepare_handle_incoming_block_no_preprocess`).

**The cycle:** if a P2P worker thread is on Side A, blocked waiting for `m_transactions_lock` (held by a second thread on Side B), while that second thread is blocked waiting for `m_blockchain_lock` (held by the first thread since the very start of Side A), neither can make progress. Each lock is individually recursive (safe against same-thread re-acquisition), which is irrelevant here since the two threads hold *different* mutexes and are waiting on each other's — the standard two-lock inversion deadlock.

## Steps to Reproduce

I want to be direct about the limits of what I can hand you as a turnkey trigger: the deadlock's Side A only proceeds past the lock-order violation when `check_against_checkpoints` actually finds a mismatch against one of the embedded checkpoint heights, which does not happen in normal, correctly-synced operation — reaching it requires the target node's local chain to have already diverged from Monero's hardcoded checkpoints at some point below its current height, which is not something a remote peer can force directly through a single crafted message. I'm reporting the mechanism precisely rather than presenting a one-shot remote PoC I don't have. Two realistic ways to actually exercise this for verification:

### Option A — direct unit/integration-level reproduction (recommended)

Since both `Blockchain::check_against_checkpoints` and `tx_memory_pool::add_tx`/`Blockchain::check_tx_inputs` are directly callable C++ APIs, the cleanest way to prove the deadlock is a small harness (in the style of this project's own `tests/unit_tests/`) that:
1. Constructs a `Blockchain`/`tx_memory_pool` pair against a small local test chain (mirroring the setup in `tests/unit_tests/`'s existing blockchain-backed tests).
2. Inserts a *wrong* hardcoded checkpoint for a low height into the `checkpoints` object passed to `check_against_checkpoints` (simulating the "local chain disagrees with a checkpoint" condition directly, without needing to actually desync a real chain).
3. Spawns two threads: Thread 1 calls `blockchain.check_against_checkpoints(bad_checkpoints, /*enforce=*/true)` directly; Thread 2 concurrently calls `mempool.add_tx(...)` with any valid, unrelated transaction, timed (e.g. via a small `sleep`/barrier, or by instrumenting a breakpoint) to land inside `Blockchain::check_tx_inputs` at the moment Thread 1 is inside `pop_block_from_blockchain`'s `m_tx_pool.add_tx` call.
4. Observe both threads permanently blocked (neither `check_against_checkpoints` nor `add_tx` returns), confirmed via `gdb`'s `info threads`/`thread apply all bt`, the same diagnostic method used in the disclosed report this finding is patterned after.

### Option B — live node reproduction (harder to guarantee timing)

1. Run a `monerod` node on a network (testnet/regtest is easiest to control) where you can arrange for the node's local chain, at some point already below its current height, to conflict with an embedded checkpoint entry — for example by modifying `src/checkpoints/checkpoints.cpp`'s hardcoded list for your own private test build to include a checkpoint hash that does *not* match your locally-built test chain at that height (this simulates, without waiting for a real-world desync, the condition `check_against_checkpoints` is designed to catch).
2. Once the node is running and synced past that height, relay a new block to it from a peer (satisfying `handle_notify_new_fluffy_block`'s trigger for `update_checkpoints`) at a moment you've also flooded the node with `send_raw_transaction` RPC calls or peer-relayed transactions, to maximize the chance a Side-B thread is inside `check_tx_inputs` at the same moment the Side-A thread reaches `pop_block_from_blockchain`'s tx-pool lock acquisition.
3. Watch for the node becoming unresponsive to further RPC/P2P activity, and confirm via `gdb -p <pid>` / `info threads` that two threads are blocked exactly as described above (one inside `tx_memory_pool::add_tx`'s lock acquisition, one inside `Blockchain::check_tx_inputs`'s).

## Possible Solution

`check_against_checkpoints` (and, transitively, `rollback_blockchain_switching`) should acquire `m_tx_pool`'s lock *before* `m_blockchain_lock`, exactly as `prepare_handle_incoming_blocks` already does, given that its `enforce` branch can end up mutating the pool via `pop_block_from_blockchain(keep_txs=true)`. Since `check_against_checkpoints` is called in a couple of different contexts (including from `update_checkpoints`, itself called both at startup and periodically from block relay), the safest fix is likely to take the tx-pool lock unconditionally at the top of `check_against_checkpoints` itself (mirroring the `m_tx_pool.lock(); CRITICAL_REGION_LOCAL1(m_blockchain_lock);` pattern in `prepare_handle_incoming_blocks`), rather than trying to make it conditional on whether the `enforce` branch will actually fire.

## Impact

A cryptocurrency full node (`monerod`) can enter a permanent, unrecoverable deadlock — requiring a forced kill and restart, exactly like the disclosed logging-lock deadlock this report is patterned after — if the automatic, periodic checkpoint-enforcement path (triggered by ordinary P2P block relay, roughly every 10 minutes) detects a mismatch against an embedded checkpoint at the same moment another thread is verifying an incoming transaction. This is a genuine violation of the codebase's own explicitly documented locking invariant, not a stretch interpretation of ambiguous code, and it is present in both the current release and the actively-maintained development branch.

## Note on AI usage

Source-code analysis (systematically tracing every multi-lock call site against the documented ordering rule, across `blockchain.cpp`, `tx_pool.cpp`, `cryptonote_core.cpp`, and `cryptonote_protocol_handler.inl`) and drafting of this report were done with AI assistance, working directly against the `master` and `v0.18.5.1` source, with every call-chain link in this report independently re-verified against the actual file contents (not taken on faith from a single pass) before inclusion. **This has been verified by exhaustive static call-chain tracing, not by a live reproduction** — I have not run either of the two reproduction approaches described above, and I do not have a demonstrated live hang to attach. Please attempt Option A (the more tractable of the two) and attach the actual thread-state output before submitting, per this program's requirement for a working PoC with logs.
