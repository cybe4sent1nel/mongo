# `NOTIFY_GET_TXPOOL_COMPLEMENT` (p2p levin command): any unauthenticated peer can force `monerod` to serialize and send its *entire* transaction pool, with no size cap, no deduplication guard, and no per-connection cooldown — independent of `--restricted-rpc` entirely, since this is not an RPC endpoint at all

## Summary

`t_cryptonote_protocol_handler<t_core>::handle_notify_get_txpool_complement()` implements the `NOTIFY_GET_TXPOOL_COMPLEMENT` levin command of Monero's **peer-to-peer protocol** — the protocol every `monerod` speaks with every other node it connects to, ordinary or malicious, with no notion of "restricted" access at all (`--restricted-rpc` only gates the HTTP/JSON-RPC layer; it has no equivalent on the p2p wire). Any peer that completes the standard, unauthenticated p2p handshake may send this single levin *notify* message — carrying nothing but a (possibly empty) list of transaction-id hashes it claims to already have — and the receiving daemon responds by scanning its **entire local transaction pool**, copying the full raw blob of **every broadcastable transaction currently in the pool that is not in the sender's list** into memory, and serializing that whole set into one outbound `NOTIFY_NEW_TRANSACTIONS` message.

There is no cap anywhere in this path on how much pool data a single such request can force to be gathered and serialized (the honest limiting factor is simply "how large the responding node's own mempool currently is"), no requirement that the sender's claimed hash list overlap the real pool (an **empty** list yields the maximum possible response — literally the whole pool), and no per-connection rate limit or cooldown preventing the same already-established connection from sending this exact message again immediately, as many times as it likes, for free. Because the daemon's own architectural mempool-size ceiling (`DEFAULT_TXPOOL_MAX_WEIGHT = 648,000,000` bytes, ≈618 MiB) is far larger than what any single small notify message ought to be able to trigger, a peer can repeatedly force multi-hundred-megabyte allocations and full-pool-lock scans from a message that is, at minimum, under 100 bytes on the wire.

## Severity

Monero severity: **HIGH** (unauthenticated, single-connection, repeatable remote memory-exhaustion / CPU- and lock-contention denial-of-service against `monerod`'s p2p layer, present regardless of any RPC hardening flag).
Suggested CVSS v3.1: `7.5` with `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`.

Rationale:
1. `NOTIFY_GET_TXPOOL_COMPLEMENT` is a core p2p levin command, dispatched to any connection that has completed the ordinary (unauthenticated, no proof-of-work, no accountability) p2p handshake and reached `state_normal` — every `monerod` accepts inbound p2p connections from the public internet by default, and this is true **whether or not `--restricted-rpc` is set**, because `--restricted-rpc` is exclusively an RPC-server (HTTP/JSON) hardening flag and has no bearing on the p2p protocol at all (`AV:N/PR:N/UI:N/AC:L`).
2. The request that triggers the worst case is a single, tiny, entirely well-formed message (an empty `hashes` array) — a pure amplification vector whose cost to the sender is essentially free and independent of the server-side cost it triggers.
3. The same message can be resent on the same connection with no cooldown, no state tracking of "already synced," and no generic anti-flood mechanism anywhere in epee's levin dispatch layer (confirmed by direct source inspection — see Root Cause), so a single peer can repeat the trigger indefinitely.
4. Impact is memory exhaustion (up to the architectural mempool-weight ceiling, per triggered response, repeatable) plus CPU cost (a full pool scan) and lock contention (the entire tx-pool lock is held for the scan, stalling all other mempool-touching daemon operations meanwhile) — `A:H`, `C:N`, `I:N`.

## Affected Versions

Confirmed present, identically, in both:

- **`master`**, commit `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f` (the actively maintained branch):
  - Levin command dispatch registration (unauthenticated, unconditional — no `_IF`/restricted-style gate exists for any p2p command): https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_protocol/cryptonote_protocol_handler.h#L98
  - Handler declaration: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_protocol/cryptonote_protocol_handler.h#L157
  - Handler implementation, no size cap on the derived response: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_protocol/cryptonote_protocol_handler.inl#L878-L905
  - `post_notify()` — the generic p2p reply path used here, which serializes the *entire* argument (a second full in-memory copy of whatever was gathered) before handing it to the network layer, with no size check of its own: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_protocol/cryptonote_protocol_handler.h#L226-L234
  - `invoke_notify_to_peer()` — no outbound size/backpressure check before queuing the send: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/p2p/net_node.inl#L2489-L2497
  - `NOTIFY_GET_TXPOOL_COMPLEMENT::request` wire struct — a bare, unbounded `std::vector<crypto::hash>`, no size annotation or limit anywhere: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_protocol/cryptonote_protocol_defs.h#L366-L379
  - `core::get_txpool_complement()`: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_core/cryptonote_core.cpp#L1848-L1851
  - `tx_memory_pool::get_complement()` — the actual full-pool scan and blob-copy, unbounded, whole-pool lock held throughout: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_core/tx_pool.cpp#L668-L706
  - `DEFAULT_TXPOOL_MAX_WEIGHT = 648,000,000` (the architectural ceiling on how much pool data a single worst-case triggered response can contain): https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_config.h#L203
  - `max_in_connection_count` default: `arg_in_peers` defaults to `-1`: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/p2p/net_node.cpp#L155 , assigned directly (unchecked, no `-1`→"unlimited" special-case) into the `uint32_t` field, i.e. wraps to `4294967295`: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/p2p/net_node.inl#L2910-L2914 , field type: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/p2p/p2p_protocol_defs.h#L141 , the comparison that this effectively disables: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/p2p/net_node.inl#L321
  - `arg_max_connections_per_ip` default `1` (the real per-attacker-IP concurrency limit, discussed under Root Cause): https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/p2p/net_node.cpp#L165
  - No flood/rate-limit logic anywhere in the generic levin dispatcher (confirmed by direct inspection, no matches for any such mechanism): `contrib/epee/include/net/levin_protocol_handler_async.h` (whole file read)
  - For context/comparison — the one sibling levin handler that *does* defend against this exact repeat/duplicate-amplification pattern for a hash/index list, `handle_request_fluffy_missing_tx`, which bounds indices to the requested block's own transaction count and explicitly detects and drops connections that ask for a duplicate index: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_protocol/cryptonote_protocol_handler.inl#L780-L840

- **`v0.18.5.1`**, the latest tagged release, commit `4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5`:
  - Levin command dispatch registration: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/cryptonote_protocol/cryptonote_protocol_handler.h#L97
  - Handler declaration: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/cryptonote_protocol/cryptonote_protocol_handler.h#L145
  - Handler implementation, identical to master: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/cryptonote_protocol/cryptonote_protocol_handler.inl#L853-L880
  - `post_notify()`: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/cryptonote_protocol/cryptonote_protocol_handler.h#L210-L218
  - `invoke_notify_to_peer()`: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/p2p/net_node.inl#L2404-L2412
  - `NOTIFY_GET_TXPOOL_COMPLEMENT::request` wire struct: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/cryptonote_protocol/cryptonote_protocol_defs.h#L364-L378
  - `core::get_txpool_complement()`: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/cryptonote_core/cryptonote_core.cpp#L1863-L1866
  - `tx_memory_pool::get_complement()`, identical to master: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/cryptonote_core/tx_pool.cpp#L671-L707
  - `DEFAULT_TXPOOL_MAX_WEIGHT = 648,000,000`: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/cryptonote_config.h#L201
  - `arg_in_peers` default `-1` / `arg_max_connections_per_ip` default `1`: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/p2p/net_node.cpp#L169 , https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/p2p/net_node.cpp#L179
  - `set_max_in_peers()` / comparison: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/p2p/net_node.inl#L2838-L2842 , https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/p2p/net_node.inl#L231

## Root Cause

`src/cryptonote_protocol/cryptonote_protocol_handler.inl` (master, `L878-L905`):
```cpp
int t_cryptonote_protocol_handler<t_core>::handle_notify_get_txpool_complement(int command, NOTIFY_GET_TXPOOL_COMPLEMENT::request& arg, cryptonote_connection_context& context)
{
  MLOG_P2P_MESSAGE("Received NOTIFY_GET_TXPOOL_COMPLEMENT (" << arg.hashes.size() << " txes)");
  if(context.m_state != cryptonote_connection_context::state_normal)
    return 1;

  std::vector<std::pair<cryptonote::blobdata, block>> local_blocks;
  std::vector<cryptonote::blobdata> local_txs;

  std::vector<cryptonote::blobdata> txes;
  if (!m_core.get_txpool_complement(std::move(arg.hashes), txes))
  {
    LOG_ERROR_CCONTEXT("failed to get txpool complement");
    return 1;
  }

  NOTIFY_NEW_TRANSACTIONS::request new_txes;
  new_txes.txs = std::move(txes);

  MLOG_P2P_MESSAGE
  (
      "-->>NOTIFY_NEW_TRANSACTIONS: "
      << ", txs.size()=" << new_txes.txs.size()
  );

  post_notify<NOTIFY_NEW_TRANSACTIONS>(new_txes, context);
  return 1;
}
```
The **only** gate here is `context.m_state != state_normal` — i.e., "has this connection finished the ordinary p2p handshake/sync handoff." That is not an authentication or authorization check; it is simply "is this a fully-connected peer," which is true for any TCP connection that speaks the (unauthenticated, public, documented) p2p wire protocol. There is no check on `arg.hashes.size()`, no check on the resulting `txes`/`new_txes.txs` size, and no per-connection flag remembering that this command was already served once.

`src/cryptonote_core/tx_pool.cpp` (master, `L668-L706`):
```cpp
bool tx_memory_pool::get_complement(std::vector<crypto::hash> hashes, std::vector<cryptonote::blobdata> &txes) const
{
  CRITICAL_REGION_LOCAL(m_transactions_lock);
  CRITICAL_REGION_LOCAL1(m_blockchain);

  // Sort so we can do binary search later
  std::sort(hashes.begin(), hashes.end());

  m_blockchain.for_all_txpool_txes([this, &hashes, &txes](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref*) {
    const auto tx_relay_method = meta.get_relay_method();
    if (tx_relay_method != relay_method::block && tx_relay_method != relay_method::fluff)
      return true;

    // Do binary search for our pool TXID in given list, skip to next if already present
    const auto hash_it = std::lower_bound(hashes.cbegin(), hashes.cend(), txid);
    if (hash_it != hashes.cend() && *hash_it == txid)
      return true;

    {
      cryptonote::blobdata bd;
      try
      {
        if (!m_blockchain.get_txpool_tx_blob(txid, bd, cryptonote::relay_category::broadcasted))
        {
          MERROR("Failed to get blob for txpool transaction " << txid);
          return true;
        }
        txes.emplace_back(std::move(bd));
      }
      catch (const std::exception &e)
      {
        MERROR("Failed to get blob for txpool transaction " << txid << ": " << e.what());
        return true;
      }
    }
    return true;
  }, false);
  return true;
}
```
This iterates the daemon's **entire** local tx pool (`for_all_txpool_txes`, no early exit, no byte/entry budget), and for every entry whose relay method is `block` or `fluff` — i.e. `relay_category::broadcasted`, the category that covers every transaction that has completed Dandelion++'s brief "stem" phase and is now visible/announced on the public network, which in ordinary operation is effectively the entire externally-visible content of the pool — and whose hash is **not** present in the caller-supplied `hashes` list, it fetches and copies the **full raw transaction blob** into `txes`. If the caller supplies an **empty** `hashes` list (a perfectly well-formed, zero-effort request — `KV_SERIALIZE_CONTAINER_POD_AS_BLOB(hashes)` with a zero-length container, per the wire struct at `cryptonote_protocol_defs.h:366-379`), `std::lower_bound` against an empty range never matches, so **every** broadcastable transaction in the pool is copied.

**1. The response size is architecturally uncapped except by the pool's own configured maximum weight, which is large.**

```cpp
// src/cryptonote_config.h
#define DEFAULT_TXPOOL_MAX_WEIGHT               648000000ull // 3 days at 300000, in bytes
```
This is the daemon's own steady-state ceiling on total mempool blob weight — currently 648,000,000 bytes (≈618 MiB). Nothing in `get_complement()`, `handle_notify_get_txpool_complement()`, or `post_notify()` imposes any smaller limit on a single triggered response; the worst case is bounded only by how much data the target's own live mempool currently holds, up to that architectural ceiling.

**2. The reply path performs a second full-size copy with no size check of its own.**

```cpp
// src/cryptonote_protocol/cryptonote_protocol_handler.h
template<class t_parameter>
  bool post_notify(typename t_parameter::request& arg, cryptonote_connection_context& context)
  {
    ...
    epee::levin::message_writer out{256 * 1024}; // optimize for block responses
    epee::serialization::store_t_to_binary(arg, out.buffer);
    ...
    return m_p2p->invoke_notify_to_peer(t_parameter::ID, std::move(out), context);
  }
```
`store_t_to_binary` serializes `new_txes` (the moved-in `txes` vector of raw blobs) into a **new** contiguous `out.buffer` — a second, independent allocation holding effectively the same bytes again, so peak transient memory for one worst-case triggered response is on the order of **2×** the copied pool weight, not 1×. `invoke_notify_to_peer()` (`src/p2p/net_node.inl:2489-2497`, master) then hands this buffer straight to the connection's `send()` with **no** size or backpressure check of any kind before queuing it — there is no p2p-layer analog of the RPC HTTP server's `--rpc-response-soft-limit` mechanism (itself only a send-queue backpressure check across multiple *already-completed* responses, as established in FINDING-16, and which in any case does not exist at all on this code path).

**3. There is no cooldown, no "already served" flag, and no generic anti-flood mechanism anywhere in the levin dispatch layer.**

`NOTIFY_GET_TXPOOL_COMPLEMENT` is a levin *notify* — a fire-and-forget message with no request/response correlation (`context.m_expect_response` is never set for it, unlike, e.g., `NOTIFY_REQUEST_GET_OBJECTS`/`NOTIFY_RESPONSE_GET_OBJECTS`). A search of `contrib/epee/include/net/levin_protocol_handler_async.h` — the generic levin command dispatcher shared by every p2p command — finds no flood-detection, rate-limiting, or per-command repeat-cooldown logic of any kind; the only size-related check that exists there (`m_max_packet_size`, `LEVIN_DEFAULT_MAX_PACKET_SIZE = 100000000` in `contrib/epee/include/net/levin_base.h:64`) governs how large an **incoming** packet the parser will accept, and has no bearing on how large a packet this handler is permitted to construct and attempt to **send**. Consequently, once a connection has reached `state_normal` (the normal, one-time cost of being any p2p peer at all — no proof-of-work, no fee, no identity requirement), it may resend the identical zero-effort `NOTIFY_GET_TXPOOL_COMPLEMENT{hashes: []}` message as many times, as fast, as the connection's own send buffer allows, and the handler will redo the full pool scan and copy every single time.

**4. The entire pool is locked for the whole scan, so this also stalls every other pool operation on the daemon meanwhile.**

`CRITICAL_REGION_LOCAL(m_transactions_lock)` and `CRITICAL_REGION_LOCAL1(m_blockchain)` are held for the full duration of `for_all_txpool_txes()`'s traversal of the entire pool — meaning ordinary transaction relay, new-transaction acceptance, and any RPC call that touches the mempool (`get_transaction_pool`, `get_transaction_pool_hashes`, `send_raw_transaction`, `is_key_image_spent`'s pool check, etc.) all contend on the same lock and are delayed for as long as this handler's scan takes, compounding the memory-exhaustion impact with a CPU/latency denial-of-service on the rest of the node's normal operation.

**5. Why "restricted" is not relevant here at all.**

`--restricted-rpc` is a flag on `core_rpc_server` (`m_restricted`), consulted only inside HTTP/JSON-RPC handlers in `core_rpc_server.cpp`/`.h`. `t_cryptonote_protocol_handler` (the class implementing `handle_notify_get_txpool_complement`) has no concept of `m_restricted` whatsoever — it is a different subsystem entirely (`src/cryptonote_protocol/`, not `src/rpc/`), wired directly into the levin p2p command dispatcher (`src/cryptonote_protocol/cryptonote_protocol_handler.h:98`/`97`). A daemon operator who runs `monerod --restricted-rpc` — precisely the documented "safe for public exposure" hardened configuration — gets **zero** additional protection against this vector, because there is nothing in this code path for that flag to gate. This satisfies the "survives `--restricted-rpc`" bar by construction, not by any subtlety of a cap being merely insufficient: no cap of any kind, restricted or otherwise, exists on this path at all.

## Steps to Reproduce

### Static confirmation (what I verified directly)

1. Confirmed `NOTIFY_GET_TXPOOL_COMPLEMENT` is registered as an ordinary levin command (`cryptonote_protocol_handler.h:98`, master) dispatched to `handle_notify_get_txpool_complement`, gated only by `context.m_state == state_normal` (`cryptonote_protocol_handler.inl:881`) — no authentication, no `m_restricted` check anywhere in this class.
2. Confirmed `NOTIFY_GET_TXPOOL_COMPLEMENT::request::hashes` (`cryptonote_protocol_defs.h:366-379`) is an unbounded `std::vector<crypto::hash>` with no size limit anywhere in its definition or in the handler that consumes it.
3. Confirmed `tx_memory_pool::get_complement()` (`tx_pool.cpp:668-706`) performs a full, unbudgeted scan of every pool entry, copying the complete raw blob of every entry whose `relay_method` is `block` or `fluff` and whose hash is absent from the (attacker-controlled, possibly empty) `hashes` list — with an empty list, this is the entire broadcastable pool.
4. Confirmed the daemon's own architectural ceiling on total pool blob weight is `DEFAULT_TXPOOL_MAX_WEIGHT = 648,000,000` bytes (`cryptonote_config.h:203`, master) — i.e. the theoretical per-triggered-response maximum this vector can force.
5. Confirmed `post_notify()` (`cryptonote_protocol_handler.h:226-234`) performs a second, independent full serialization of the gathered data (`epee::serialization::store_t_to_binary`) with no size check, and `invoke_notify_to_peer()` (`net_node.inl:2489-2497`) queues the resulting buffer for send with no backpressure or size check of any kind.
6. Confirmed, by reading the entirety of `contrib/epee/include/net/levin_protocol_handler_async.h`, that no generic flood-control, rate-limiting, or repeat-suppression mechanism exists anywhere in the levin dispatch layer that would prevent the same connection from resending this notify message immediately and repeatedly.
7. Confirmed, for contrast, that a sibling p2p handler handling a very similar shape of input — `handle_request_fluffy_missing_tx` (`cryptonote_protocol_handler.inl:780-840`) — *does* defend against duplicate/out-of-range requests within a single message (bounding indices to the requested block's own transaction count, explicitly detecting and dropping the connection on a repeated index), demonstrating that the project is capable of, and does elsewhere apply, exactly this class of defense — just not on this path.
8. Confirmed `--restricted-rpc` (`core_rpc_server::m_restricted`) is consulted only within `src/rpc/core_rpc_server.{h,cpp}` HTTP/JSON-RPC handlers, and has no reference anywhere in `src/cryptonote_protocol/` or `src/p2p/`, confirming this vector is entirely independent of that flag.
9. Confirmed the default per-source-IP p2p connection limit is `1` (`arg_max_connections_per_ip`, default `1`, `net_node.cpp:165` master / `net_node.cpp:179` v0.18.5.1) — this is the realistic bound on how many *concurrent* connections a single attacker IP can hold open against a default daemon, discussed in the arithmetic below — and that the default *inbound* connection limit across all IPs (`arg_in_peers`, default `-1`) is effectively unlimited: the `-1` sentinel is assigned directly, with no wrap-around guard, into the `uint32_t max_in_connection_count` field (`net_node.inl:2910-2914` master / `2838-2842` v0.18.5.1), which is bit-for-bit `4294967295` — a value the connection counter (`m_current_number_of_in_peers`) will never reach in practice — so the total number of *distinct* attacker IPs that may each hold their one connection open concurrently is unbounded by this setting.

### Worst-case arithmetic

- **Trigger cost**: one levin `NOTIFY_GET_TXPOOL_COMPLEMENT` message with `hashes = []`. The wire payload is the epee-portable-storage encoding of a single field holding a zero-length byte blob, plus the fixed levin packet header — on the order of a few dozen to under 100 bytes total, requiring nothing beyond an already-established, unauthenticated p2p connection.
- **Triggered allocation, single request, worst case**: up to `DEFAULT_TXPOOL_MAX_WEIGHT = 648,000,000` bytes (≈618 MiB) of raw transaction blob data copied out of the pool into `txes`/`new_txes.txs`, plus a second, independent ≈ equal-sized allocation when `post_notify()` serializes it into `out.buffer` for transmission — **≈1.24 GB of peak transient allocation from a single sub-100-byte message**, an amplification ratio on the order of **13,000,000-to-1** at the architectural ceiling (and a very substantial, if smaller, amplification even at realistic day-to-day mempool sizes well under that ceiling, since the request cost is fixed and near-zero regardless of how large the pool happens to be at the moment it is asked).
- **Repetition, single connection**: because there is no cooldown, no "already served" flag, and no generic flood control anywhere on this path (see Root Cause, points 3 and 6 above), the same already-open connection may resend this identical message as fast as the responding daemon can process notify commands from it, forcing the full ≈1.24 GB (worst case) transient allocation-and-lock-hold cycle again and again, indefinitely, from a single TCP connection that a single attacker IP is entitled to hold open by default (`max-connections-per-ip = 1`).
- **Repetition, multiple connections**: an attacker controlling more than one source IP (trivially available via any cheap multi-IP hosting, and in any case not gated by any *daemon-side* configuration change beyond the default `--in-peers` setting, which is effectively unlimited as established above) may hold open one such connection per IP concurrently, each independently triggering its own up-to-≈1.24 GB transient allocation cycle at will, multiplying the concurrent memory pressure on the target daemon by the number of distinct attacker IPs used.

This entire chain is exercised purely over the p2p protocol. No RPC request of any kind is involved, `--restricted-rpc` is never consulted, and there is no config flag beyond the daemon's own default p2p listener (on by default, unauthenticated by design, exactly as documented) that a normal operator would need to have enabled for this to apply.

### Suggested dynamic reproduction (not run by me — see disclosure note)

```python
#!/usr/bin/env python3
# poc_txpool_complement_dump.py
#
# Demonstrates that a minimal, unauthenticated Monero p2p peer can force a
# target monerod to repeatedly scan and serialize its entire transaction
# pool by sending NOTIFY_GET_TXPOOL_COMPLEMENT with an empty hash list,
# on a single connection, with no cooldown -- independent of whether the
# target daemon is running --restricted-rpc (this is a p2p-layer bug, not
# an RPC-layer one, so restricted-rpc has no bearing on it at all).
#
# Usage:
#   python3 poc_txpool_complement_dump.py <daemon_host> <daemon_p2p_port> [--repeat N]
#
# Procedure this script should implement (left as a sketch: a full
# implementation needs a levin/epee "portable storage" binary codec and a
# minimal p2p handshake client -- e.g. adapted from monero's own p2p test
# harness or a third-party levin client library):
#
#   1. Open a TCP connection to <daemon_host>:<daemon_p2p_port>.
#   2. Perform the standard, unauthenticated NOTIFY_HANDSHAKE exchange
#      (COMMAND_HANDSHAKE, levin command id per p2p_protocol_defs.h) to
#      reach a state where the target daemon accepts further levin
#      notify commands from this connection (cryptonote_connection_context
#      reaching state_normal server-side, per cryptonote_protocol_handler.inl).
#   3. Construct and send a NOTIFY_GET_TXPOOL_COMPLEMENT levin notify
#      (command id BC_COMMANDS_POOL_BASE + 10, see cryptonote_protocol_defs.h)
#      whose body is the epee-portable-storage encoding of:
#          { "hashes": b"" }   # zero-length container -> matches nothing
#   4. Record wall-clock time and (if testing against a daemon you control)
#      sample the daemon process's RSS (e.g. /proc/<pid>/status VmRSS)
#      immediately before and during the response.
#   5. Repeat step 3 on the SAME connection, back-to-back, N times (e.g.
#      --repeat 50), and observe whether RSS grows roughly linearly with
#      each repetition and whether CPU/latency on other daemon RPC calls
#      (e.g. get_info) visibly degrades while a scan is in flight.
#   6. Optionally, do not read from the socket after sending the request,
#      to additionally test whether the daemon holds the serialized
#      response buffer in memory while waiting for this (attacker-
#      controlled, non-draining) connection to accept it.

import socket
import sys

def main():
    host = sys.argv[1]
    port = int(sys.argv[2])
    repeat = 1
    if "--repeat" in sys.argv:
        repeat = int(sys.argv[sys.argv.index("--repeat") + 1])
    print(f"[poc] target: {host}:{port} (p2p)")
    print(f"[poc] would perform p2p handshake, then send NOTIFY_GET_TXPOOL_COMPLEMENT{{hashes: []}} x{repeat}")
    print("[poc] see script comments: requires a levin/epee portable-storage binary codec and minimal p2p handshake client to complete")

if __name__ == "__main__":
    main()
```

### Expected result on the vulnerable build

Against a `monerod` (with or without `--restricted-rpc` — it makes no difference to this path) that has a non-trivial mempool (any daemon that has been running on mainnet/testnet for more than a few minutes under normal conditions will have at least some fluff-relayed transactions in its pool), a single connection completing the standard p2p handshake and then sending `NOTIFY_GET_TXPOOL_COMPLEMENT{hashes: []}` should be observed to cause: (a) the daemon's RSS to climb by an amount consistent with the current pool's total blob weight (up to the ≈618 MiB architectural ceiling), (b) a `NOTIFY_NEW_TRANSACTIONS` message roughly that size sent back to the connection, and (c) repeating the same message on the same connection immediately re-triggering the same cost, with no rejection, no cooldown, and no degradation of the attack's per-message cheapness.

## Possible Solution

1. Cap the total blob weight (not just an entry count) that a single `NOTIFY_GET_TXPOOL_COMPLEMENT` response may contain — analogous to the daemon's own `--rpc-response-soft-limit` concept, but enforced *before* the full-pool copy is made in `tx_memory_pool::get_complement()`, aborting/truncating the scan once a reasonable byte budget (far below `DEFAULT_TXPOOL_MAX_WEIGHT`) is exceeded, rather than only after the fact.
2. Track, per connection, whether a full (or empty-hash) txpool-complement request has already been served recently, and reject or heavily rate-limit repeat requests from the same peer within a short window — mirroring the kind of per-connection abuse detection already applied to `handle_request_fluffy_missing_tx`'s duplicate-index case.
3. Consider adding a generic, connection-level flood/rate-limit primitive to the levin dispatch layer (`levin_protocol_handler_async.h`) that any expensive notify handler — this one included — can opt into, rather than requiring every individual handler to reinvent per-command throttling from scratch.
4. Add an explicit size check on the incoming `hashes` list too (defense in depth): while the worst case here comes from a *small* list, an attacker could equally send a very large, junk `hashes` list to inflate the cost of the `std::sort`/binary-search step, and a sane upper bound (e.g. the daemon's own current pool entry count) costs nothing to enforce.

## Impact

An attacker needs nothing more than the ability to open one ordinary, unauthenticated p2p connection to a `monerod` instance — the daemon's default, always-on listening service, regardless of any RPC hardening flag — to repeatedly force that daemon to scan its entire transaction pool under an exclusive lock and materialize (twice, once for the copy and once for wire serialization) an in-memory buffer that can reach hundreds of megabytes, from a message that costs the attacker well under 100 bytes and can be resent instantly and indefinitely on the same connection. Because this lives entirely in the p2p protocol handler (`src/cryptonote_protocol/`), it has no relationship whatsoever to `core_rpc_server::m_restricted` — `--restricted-rpc`, the daemon's own documented "safe for public exposure" hardened configuration, provides **no** mitigation for this vector, because there is no restricted/unrestricted distinction anywhere on this code path to begin with. This is a stronger result than a cap merely being insufficient once restricted mode is enabled (the FINDING-16 pattern): here, no cap exists in either mode, because the concept of "mode" does not apply to the p2p layer at all.

## Note on AI usage

Source-code analysis (enumerating levin p2p command handlers in `cryptonote_protocol_handler.inl`/`.h` that consume a client-supplied hash/count list, per the task's explicit direction to audit `NOTIFY_REQUEST_GET_OBJECTS` and "any other levin command"; identifying `NOTIFY_GET_TXPOOL_COMPLEMENT` as lacking any response-size cap or repeat-request throttling, in contrast with `NOTIFY_REQUEST_GET_OBJECTS`'s `CURRENCY_PROTOCOL_MAX_OBJECT_REQUEST_COUNT` cap and `handle_request_fluffy_missing_tx`'s duplicate-index defense, both of which were read and found adequate/well-defended and are explicitly not being reported; tracing the full call chain from the levin dispatch table through `tx_memory_pool::get_complement()`, `post_notify()`, and `invoke_notify_to_peer()`; confirming the complete absence of any generic flood-control mechanism by reading the entirety of `levin_protocol_handler_async.h`; confirming `core_rpc_server::m_restricted` has no reference anywhere in `src/cryptonote_protocol/` or `src/p2p/`; deriving the default in-peer/per-IP connection-limit values and the `int64_t -1` → `uint32_t` truncation behavior in `set_max_in_peers()`; and drafting of this report) was done with AI assistance, working directly against the `v0.18.5.1` and `master` source. **This has been verified by static code reading only — every code excerpt quoted above was read directly from the actual current source at the cited file/line on both trees, and the memory-amplification arithmetic was derived by hand from those exact code paths and from the `DEFAULT_TXPOOL_MAX_WEIGHT`, `LEVIN_DEFAULT_MAX_PACKET_SIZE`, `arg_in_peers`, and `arg_max_connections_per_ip` constants, also read directly from source.** No dynamic reproduction, build, or PoC execution was performed, and no attempt was made to measure any live daemon's actual current mempool size or process memory. The "≈618 MiB" and "≈1.24 GB" figures are the code-provable architectural ceiling and its serialization-doubled worst case, not a claimed real-world measurement — actual impact on any given running daemon will scale with whatever that daemon's live mempool weight happens to be at the moment of attack, which is normally well under the architectural maximum but is, by design, entirely outside the attacker's control to know in advance and entirely outside the daemon's control to prevent this handler from copying in full. The PoC script above is a structural sketch, not a runnable byte-for-byte levin/epee client (this protocol uses epee's binary "portable storage" format over a raw TCP levin transport, including its own handshake sequence, neither of which is a JSON/HTTP concern); it has not been run against any live daemon. Please complete it with a levin/epee-compatible binary client and a minimal p2p handshake implementation, and run it only against a disposable/regtest or testnet `monerod` instance (or a mainnet node you control and can afford to stress), and attach the observed memory/timing/lock-contention behavior before submitting, per this program's requirement for a working PoC with logs.
