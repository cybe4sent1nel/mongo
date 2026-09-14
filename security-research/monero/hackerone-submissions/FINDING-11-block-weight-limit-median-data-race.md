# `Blockchain::get_current_cumulative_block_weight_limit()`/`get_current_cumulative_block_weight_median()` read shared, non-atomic state with no lock — sibling of a recently-fixed data race in the same file

## Summary

A recent commit ("Blockchain: fix data race in get_dynamic_base_fee_estimate") added the missing `m_blockchain_lock` acquisition to a read-only accessor in `blockchain.cpp` that had been reading blockchain-cache state concurrently with the block-processing path's locked writes to that same state.

Two more accessors in the identical file, `Blockchain::get_current_cumulative_block_weight_limit()` and `Blockchain::get_current_cumulative_block_weight_median()`, have the exact same shape — reading plain, non-atomic `size_t` member variables with **no lock at all** — and were not touched by that fix. These two are called, unlocked, from a live daemon RPC handler that runs concurrently with normal block processing, and from the incoming-block-size sanity check on the p2p/RPC block-submission path.

## Severity

Monero severity: **LOW-to-MEDIUM** (data race / undefined-behavior-per-the-C++-memory-model on individual node state; the maintainers already judged the identical bug shape in the same file worth a dedicated fix).
Suggested CVSS v3.1: `3.7` with `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N`.

Rationale:
1. Reachable via ordinary, unauthenticated RPC (`get_info`) on any publicly reachable daemon, concurrent with the node's own normal block-processing activity — no special access needed beyond ordinary RPC availability (`AV:N/PR:N/UI:N`).
2. Requires precise timing (a read racing a concurrent locked write) to actually observe a torn/stale value, and the practical consequence on common 64-bit platforms (where an aligned `size_t` load/store is typically a single atomic bus operation at the hardware level even though the C++ standard does not guarantee this) is most likely a momentarily stale rather than a torn value — so I am scoring this conservatively (`AC:H`, `I:L`, `A:N`) rather than claiming a demonstrated crash or memory-corruption outcome.
3. This is formally a data race (undefined behavior under the C++ memory model, and a genuine ThreadSanitizer-detectable bug) regardless of the practical hardware-dependent outcome, which is exactly the class of issue the sibling fix in this same file was written to close.

## Affected Versions

Confirmed present, identically, in both:
- **`master`**, commit `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f` (the actively maintained branch):
  - Unlocked getters: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_core/blockchain.cpp#L1498-L1508
  - Locked writer (for comparison): https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_core/blockchain.cpp#L4440
  - Unlocked RPC call site: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.cpp#L326-L327
- **`v0.18.5.1`**, the latest tagged release, commit `4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5`:
  https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/cryptonote_core/blockchain.cpp#L1456-L1466

## Root Cause

`src/cryptonote_core/blockchain.h`:
```cpp
mutable epee::critical_section m_blockchain_lock; // TODO: add here reader/writer lock
...
size_t m_current_block_cumul_weight_limit;
size_t m_current_block_cumul_weight_median;
```
(`epee::critical_section` is a `boost::recursive_mutex` — same-thread re-entry is safe, but concurrent cross-thread access to the plain `size_t` members it's meant to protect is not, when one side doesn't take the lock at all.)

`src/cryptonote_core/blockchain.cpp` — the two unlocked getters:
```cpp
uint64_t Blockchain::get_current_cumulative_block_weight_limit() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  return m_current_block_cumul_weight_limit;
}
uint64_t Blockchain::get_current_cumulative_block_weight_median() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  return m_current_block_cumul_weight_median;
}
```

The write side, `Blockchain::update_next_cumulative_weight_limit()`, sets both members and is called only from functions that already hold `m_blockchain_lock` at the time of the call:
```cpp
bool Blockchain::update_next_cumulative_weight_limit(uint64_t *long_term_effective_median_block_weight)
{
  ...
  m_current_block_cumul_weight_median = median;
  ...
  m_current_block_cumul_weight_limit = ...;
  ...
}
```
Call sites, all inside functions that take `CRITICAL_REGION_LOCAL(m_blockchain_lock)` (directly or via `CRITICAL_REGION_LOCAL1`) before reaching this call: `init()` (`blockchain.cpp:454`), the block-pop path (`:565`), `handle_alternative_block` (`:732`), `rollback_blockchain_switching` (`:1109`), `switch_to_alternative_blockchain` (`:1160`), and `handle_block_to_main_chain` (`:4325`, reached from `add_new_block`, which takes the lock at its own entry).

**Concrete, concurrently-running read side, no lock at all:**
```cpp
// src/rpc/core_rpc_server.cpp, on_get_info() -- runs on an RPC-server worker thread
res.block_size_limit = res.block_weight_limit = m_core.get_blockchain_storage().get_current_cumulative_block_weight_limit();
res.block_size_median = res.block_weight_median = m_core.get_blockchain_storage().get_current_cumulative_block_weight_median();
```
`on_get_info()` (and its ZMQ-RPC equivalent, `daemon_handler.cpp:578-579`) is invoked on ordinary, unauthenticated `get_info` RPC requests — served continuously by the RPC server's worker thread(s) — while a completely separate thread (the p2p protocol handler processing an incoming block, or the RPC/miner block-submission path) can concurrently be inside `add_new_block`, holding `m_blockchain_lock`, and calling `update_next_cumulative_weight_limit()` to write these same two members. These two threads genuinely run concurrently on any live daemon under normal operation — RPC service and block processing are not serialized against each other except through this specific lock, which the read side simply doesn't take.

A second, more consequential unlocked read site exists in the incoming-block sanity check:
```cpp
// src/cryptonote_core/cryptonote_core.cpp
bool core::check_incoming_block_size(const blobdata& block_blob) const
{
  if(block_blob.size() > m_blockchain_storage.get_current_cumulative_block_weight_limit() + BLOCK_SIZE_SANITY_LEEWAY)
  {
    LOG_PRINT_L1("WRONG BLOCK BLOB, sanity check failed on size " << block_blob.size() << ", rejected");
    return false;
  }
  return true;
}
```
and in `tx_memory_pool`'s fee/backlog estimation:
```cpp
// src/cryptonote_core/tx_pool.cpp
const uint64_t median_weight = m_blockchain.get_current_cumulative_block_weight_median();
```
— both reading the identical unsynchronized state from code paths that run independently of whichever thread is currently inside `update_next_cumulative_weight_limit()`.

## Steps to Reproduce

### Static confirmation (what I verified directly)

1. `m_current_block_cumul_weight_limit`/`m_current_block_cumul_weight_median` are declared as plain `size_t`, not `std::atomic<size_t>` (`blockchain.h:1178-1179`).
2. Every write to them happens only inside `update_next_cumulative_weight_limit()`, itself only called from functions holding `m_blockchain_lock` (traced call sites above).
3. `get_current_cumulative_block_weight_limit()`/`get_current_cumulative_block_weight_median()` take no lock (quoted above) — contrast directly with the sibling `get_dynamic_base_fee_estimate_2021_scaling()` a few hundred lines away in the same file, which now explicitly takes `CRITICAL_REGION_LOCAL(m_blockchain_lock)` as its first statement after the fix this report's finding was left out of.
4. `on_get_info()`, an ordinary unauthenticated RPC handler, calls both unlocked getters directly (`core_rpc_server.cpp:326-327`).

### Dynamic confirmation (suggested, not run by me — see disclosure note)

Building `monerod` with `-fsanitize=thread` (Clang/GCC ThreadSanitizer) and running a regtest node while concurrently (a) mining/submitting blocks in a loop and (b) hammering `get_info` via RPC in a tight loop from a second process should produce a TSan data-race report naming `Blockchain::get_current_cumulative_block_weight_limit()`/`get_current_cumulative_block_weight_median()` against `Blockchain::update_next_cumulative_weight_limit()`, analogous to how the sibling bug in `get_dynamic_base_fee_estimate_2021_scaling()` would have been caught:

```
cmake -D CMAKE_BUILD_TYPE=Debug -D SANITIZE_THREAD=ON -D BUILD_TESTS=OFF ../..
make -j"$(nproc)" daemon
./bin/monerod --regtest --fixed-difficulty 1 --offline --non-interactive \
  --data-dir /tmp/monero-poc-race/chain --rpc-bind-port 38081 --confirm-external-bind &

# Loop A: keep mining/submitting blocks to keep update_next_cumulative_weight_limit() hot
while true; do curl -s -X POST http://127.0.0.1:38081/json_rpc -d \
  '{"jsonrpc":"2.0","id":"0","method":"generateblocks","params":{"amount_of_blocks":1,"wallet_address":"<any-regtest-address>"}}' \
  -H 'Content-Type: application/json' >/dev/null; done &

# Loop B: keep the unlocked read path hot
while true; do curl -s http://127.0.0.1:38081/get_info >/dev/null; done
```

## Possible Solution

Add the same guard the sibling fix already applied:
```cpp
uint64_t Blockchain::get_current_cumulative_block_weight_limit() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_current_block_cumul_weight_limit;
}
uint64_t Blockchain::get_current_cumulative_block_weight_median() const
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_current_block_cumul_weight_median;
}
```
or, more cheaply given `m_blockchain_lock` is already a hot, coarse-grained lock, change the two members to `std::atomic<size_t>` and use relaxed loads/stores, which avoids adding lock contention to a `get_info`-hot-path RPC call while still eliminating the formal data race.

## Impact

A daemon under normal operation — serving ordinary `get_info` RPC requests while processing incoming blocks, an unavoidable combination for any node that is both RPC-reachable and syncing/relaying — has two of its shared cache fields read and written without synchronization, a data race and undefined behavior under the C++ memory model, in the exact same file and following the exact same pattern the project already fixed once. Practical consequences range from returning a momentarily stale `block_weight_limit`/`block_weight_median` value via RPC, to (in the less likely case a compiler/platform does not treat aligned `size_t` load/store as atomic) a torn read feeding into the block-size sanity check or mempool fee/backlog estimation.

## Note on AI usage

Source-code analysis (recognizing this as the same bug shape as the recently-fixed `get_dynamic_base_fee_estimate_2021_scaling()` race, in the same file, and tracing every write call site's locking discipline against every read call site's lack of it) and drafting of this report were done with AI assistance, working directly against the `v0.18.5.1` and `master` source. **This has been verified by static code reading only, including confirming the exact declared type of `m_blockchain_lock` and the two member variables, and tracing every writer and reader call site against the actual current source — it has not been verified with a live ThreadSanitizer run.** Please run the suggested TSan reproduction (or an equivalent one) and attach the resulting race report before submitting, per this program's requirement for a working PoC with logs.
