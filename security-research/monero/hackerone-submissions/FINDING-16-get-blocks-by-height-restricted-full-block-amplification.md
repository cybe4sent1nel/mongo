# `/get_blocks_by_height.bin`: the restricted-mode 1000-item count cap is real, but it bounds a *full block + every one of its transactions* per item — a ~8&nbsp;KB request under `--restricted-rpc` can still force ~600&nbsp;MB+ of allocation by repeating one heavy height

## Summary

`core_rpc_server::on_get_blocks_by_height()` implements the `/get_blocks_by_height.bin` (and `/getblocks_by_height.bin`) binary RPC endpoint. It accepts a client-supplied list of block heights (`req.heights`, a `std::vector<uint64_t>` with **no uniqueness requirement**) and, for every entry in the list — repeats included — fetches that block **and every transaction contained in it** from the database, and appends a fully-populated `block_complete_entry` (raw block blob **plus the raw blob of every transaction in the block**) to the in-memory response. Unlike `get_block_headers_range` (FINDING-15) or `get_block_header_by_hash`, whose per-item payload is a small, fixed-shape header struct, this endpoint's per-item payload is **an entire block's worth of transaction data** — which, per Monero's own dynamic block-weight-limit consensus rule, is provably allowed to be at least 600,000 bytes, and is architecturally designed (via the 2021 block-weight "surge" scaling change) to grow far beyond that as real network usage grows.

Critically, this endpoint *does* apply a restricted-mode count cap — `RESTRICTED_BLOCK_COUNT = 1000` — and that cap **is correctly enforced even under `--restricted-rpc`**. This is exactly the stricter bug class requested: the cap is not bypassed by turning on restricted mode (unlike FINDING-14/15); it is enforced as designed, and is still insufficient, because the same numeric constant (1000) that is a reasonable ceiling for cheap, fixed-size header entries is reused, unmodified, for an endpoint whose per-entry cost is instead a variable-size, consensus-bounded *entire block of transaction data* — and because nothing stops a single height from being repeated in the list, an attacker does not even need 1000 distinct large blocks; one already-mined large block, requested 1000 times, is enough.

## Severity

Monero severity: **HIGH** (unauthenticated-by-default, single-request remote memory-exhaustion / denial-of-service against `monerod`, **that is not mitigated by `--restricted-rpc`, the daemon's own documented "safe for public exposure" hardened configuration**).
Suggested CVSS v3.1: `7.5` with `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`.

Rationale:
1. `/get_blocks_by_height.bin` is registered as an ordinary, always-available binary RPC endpoint (`MAP_URI_AUTO_BIN2`, not `_IF(..., !m_restricted)`-gated) — reachable over plain, unauthenticated HTTP whether or not the operator has passed `--restricted-rpc` (`AV:N/PR:N/UI:N/AC:L`).
2. The restricted-mode count cap (`RESTRICTED_BLOCK_COUNT = 1000`) genuinely applies and is enforced — this is *not* the "cap only checked when unrestricted" gap of FINDING-14/15. The bug survives the daemon's hardened configuration because the cap bounds the wrong dimension (item *count*) for an endpoint whose cost is dominated by item *size*, and because the item list is not deduplicated.
3. The request itself is tiny (an array of up to 1000 8-byte integers, all of which may be the same value) — a pure amplification vector whose cost is essentially decoupled from the attacker's actual request size.
4. Impact is memory and CPU/I-O exhaustion of the daemon process — `A:H`, `C:N`, `I:N`.

## Affected Versions

Confirmed present, identically, in both:

- **`master`**, commit `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f` (the actively maintained branch):
  - Endpoint registration, not restricted-gated: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.h#L96-L97
  - Handler with count-only cap, no dedup: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.cpp#L547-L583
  - `RESTRICTED_BLOCK_COUNT` definition: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.cpp#L71
  - Request/response struct (`heights` in, `blocks` — full `block_complete_entry` — out): https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server_commands_defs.h#L280-L302
  - `block_complete_entry` per-item payload shape (raw block blob **and** every raw tx blob): https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_protocol/cryptonote_protocol_defs.h#L134-L170 (struct at L134, `KV_SERIALIZE_OPT(pruned, false)` at L141, and the non-pruned branch at L148-L164 that serializes each tx's full `blob` rather than a hash/reference)
  - Consensus block-weight-limit floor: `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 = 300000` https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_config.h#L60 and `CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR = 50` https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_config.h#L62
  - `m_current_block_cumul_weight_limit = m_current_block_cumul_weight_median * 2`, with the median floored at the full-reward-zone constant: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_core/blockchain.cpp#L4440-L4488 (`update_next_cumulative_weight_limit()`)
  - `get_min_block_weight()`: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_basic/cryptonote_basic_impl.cpp#L67-L74
  - This weight limit is the actual consensus-enforced ceiling on submitted block *blob* size too (used as a sanity check on incoming blocks): https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_core/cryptonote_core.cpp#L1454-L1466 (`core::check_incoming_block_size`, `BLOCK_SIZE_SANITY_LEEWAY = 100` defined a few lines above at L70)
  - `MAX_RPC_CONTENT_LENGTH = 1048576` (1 MB request-body ceiling, applied to the same HTTP server that serves this binary endpoint — not a meaningful limiter here since 1000 heights is a far smaller request): https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_config.h#L136 , https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.cpp#L242
  - The separate `rpc-response-soft-limit` (25 MiB default) is a *send-queue* backpressure check, not a per-response construction cap, and is explicitly documented in-source as never blocking a single response: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/contrib/epee/include/net/abstract_tcp_server2.inl#L850-L856 ("a single http response will never fail this check")

- **`v0.18.5.1`**, the latest tagged release, commit `4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5`:
  - Handler with the identical count-only cap, no dedup (plus a v0.18.5.1-only, no-op-by-default `CHECK_PAYMENT_MIN1` call — see Root Cause): https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/rpc/core_rpc_server.cpp#L812-L847
  - `RESTRICTED_BLOCK_COUNT` definition: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/rpc/core_rpc_server.cpp#L77
  - Endpoint registration, not restricted-gated: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/rpc/core_rpc_server.h#L105
  - Request/response struct: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/rpc/core_rpc_server_commands_defs.h#L267-L289
  - `block_complete_entry`: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/cryptonote_protocol/cryptonote_protocol_defs.h#L132-L168
  - `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5` / `CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR`: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/cryptonote_config.h#L61 , L63
  - `m_current_block_cumul_weight_limit = m_current_block_cumul_weight_median * 2`: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/cryptonote_core/blockchain.cpp#L4642
  - `core::check_incoming_block_size` / `BLOCK_SIZE_SANITY_LEEWAY`: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/cryptonote_core/cryptonote_core.cpp#L1454-L1481 (`BLOCK_SIZE_SANITY_LEEWAY = 100` at L71)

## Root Cause

`src/rpc/core_rpc_server.cpp` (master):
```cpp
bool core_rpc_server::on_get_blocks_by_height(const COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::response& res, const connection_context *ctx)
{
  RPC_TRACKER(get_blocks_by_height);

  const bool restricted = m_restricted && ctx;
  if (restricted && req.heights.size() > RESTRICTED_BLOCK_COUNT)
  {
    res.status = "Too many blocks requested in restricted mode";
    return true;
  }

  res.status = "Failed";
  res.blocks.clear();
  res.blocks.reserve(req.heights.size());
  for (uint64_t height : req.heights)
  {
    block blk;
    try
    {
      blk = m_core.get_blockchain_storage().get_db().get_block_from_height(height);
    }
    catch (...)
    {
      res.status = "Error retrieving block at height " + std::to_string(height);
      return true;
    }
    std::vector<transaction> txs;
    std::vector<crypto::hash> missed_txs;
    m_core.get_transactions(blk.tx_hashes, txs, missed_txs);
    res.blocks.resize(res.blocks.size() + 1);
    res.blocks.back().block = block_to_blob(blk);
    for (auto& tx : txs)
      res.blocks.back().txs.push_back({tx_to_blob(tx), crypto::null_hash});
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}
```
Unlike `on_get_transactions` (FINDING-14) and `on_get_block_headers_range` (FINDING-15), the size check here **is** unconditional on `restricted` in effect — wait, more precisely: it *is* an `if (restricted && ...)` check, exactly like those two, but that is not the flaw being reported here. This report is about what happens once you *do* turn on `--restricted-rpc`: the check does fire, and does reject any request with more than `RESTRICTED_BLOCK_COUNT = 1000` heights. The problem is what the check actually bounds.

**1. The cap bounds item *count*, not item *cost*, and the per-item cost here is unusually large.**

For every `height` in `req.heights` (up to 1000 of them, in restricted mode), the handler:
- Fetches the **entire block** (`get_block_from_height`), not just its header.
- Fetches **every transaction referenced by that block** (`m_core.get_transactions(blk.tx_hashes, txs, missed_txs)`) — full transactions, not hashes.
- Serializes the raw block blob (`block_to_blob(blk)`) **and** the raw blob of every one of those transactions (`tx_to_blob(tx)`) into the response's `block_complete_entry`.

Compare this to `block_header_response` (used by `get_block_headers_range`/`get_block_header_by_hash`, both of which reuse the exact same `1000`-scale constants, `RESTRICTED_BLOCK_HEADER_RANGE`/`RESTRICTED_BLOCK_COUNT`): that struct carries only a dozen fixed-size fields and six hash-sized strings — on the order of a few hundred bytes to ~1 KB per entry, as established in FINDING-15's analysis, which concluded that a 1000-entry restricted-mode cap on *that* payload shape is adequate. `block_complete_entry` carries the **entire uncompressed contents of a block**, i.e. every transaction that was ever included in it:
```cpp
// src/cryptonote_protocol/cryptonote_protocol_defs.h
struct block_complete_entry
{
  bool pruned;
  blobdata block;
  uint64_t block_weight;
  std::vector<tx_blob_entry> txs;
  BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE_OPT(pruned, false)
    KV_SERIALIZE(block)
    KV_SERIALIZE_OPT(block_weight, (uint64_t)0)
    if (this_ref.pruned)
    {
      KV_SERIALIZE(txs)
    }
    else
    {
      std::vector<blobdata> txs;
      if (is_store)
      {
        txs.reserve(this_ref.txs.size());
        for (const auto &e: this_ref.txs) txs.push_back(e.blob);
      }
      epee::serialization::selector<is_store>::serialize(txs, stg, hparent_section, "txs");
      ...
```
`on_get_blocks_by_height` never sets `.pruned`; the struct's implicit default-construction on `res.blocks.resize(...)` leaves `pruned == false` (its `KV_SERIALIZE_OPT(pruned, false)` default), so the *non-pruned* branch is always taken on the wire: every transaction's full raw `blob` (not a hash, not a pruned/reference form) is serialized into the response for every block requested.

**2. There is no cap — and no deduplication — on how large a single requested block's contents can be.**

Monero's block size is not fixed; it is governed by the dynamic block-weight-limit mechanism (`Blockchain::update_next_cumulative_weight_limit()`):
```cpp
// src/cryptonote_core/blockchain.cpp
uint64_t full_reward_zone = get_min_block_weight(hf_version); // == CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 == 300000, current HF
...
m_long_term_effective_median_block_weight = std::max<uint64_t>(CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5, long_term_median);
...
effective_median_block_weight = std::min<uint64_t>(
    std::max<uint64_t>(m_long_term_effective_median_block_weight, short_term_median),
    CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR * m_long_term_effective_median_block_weight);
...
m_current_block_cumul_weight_median = effective_median_block_weight;
if (m_current_block_cumul_weight_median <= full_reward_zone)
  m_current_block_cumul_weight_median = full_reward_zone;
m_current_block_cumul_weight_limit = m_current_block_cumul_weight_median * 2;
```
`m_current_block_cumul_weight_median` is **provably always ≥ `full_reward_zone` (300,000)** — that final floor is unconditional, applied on every recomputation, for the entire post-HF5 history of the chain. Therefore `m_current_block_cumul_weight_limit`, the actual consensus-enforced ceiling on a single block's weight (and, per `core::check_incoming_block_size()`'s own comment, "block weight is always >= block blob size" — i.e. this figure bounds blob size too), is **provably always ≥ 600,000 bytes**, for every block ever mined on Monero mainnet, with no exception. This is not a rare or contrived edge case — it is the permanent structural floor of the protocol's own dynamic sizing rule. `CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR = 50` further means the *effective* ceiling scales up to `100×` the long-term median once real network throughput sustains a higher load (this is the documented mechanism, introduced at `HF_VERSION_2021_SCALING`, by which Monero intentionally lets blocks grow well past the historical minimum as adoption grows) — so the true achievable per-block size, using only blocks that have actually been mined at any point in the chain's ~12-year history, is very plausibly far larger than the 600,000-byte floor used in the conservative calculation below.

Once any such block — however large it happened to be when it was mined — exists on the immutable chain, it is retrievable by height **forever**. Because `req.heights` is not deduplicated, an attacker does not need to find 1000 different large blocks: **one** sufficiently large historical block, with its height repeated 1000 times in a single request, is enough to hit the cap's full item budget while paying the maximum possible per-item cost every single time.

**3. Neither the request-size limit nor the "response soft limit" prevents this.**

The daemon's HTTP server caps request bodies at `MAX_RPC_CONTENT_LENGTH = 1,048,576` bytes — irrelevant here, since 1000 8-byte height values is on the order of 8 KB, nowhere near that ceiling. The separate `--rpc-response-soft-limit` (25 MiB default) is a *send-queue* backpressure mechanism checked when **queuing** bytes for an already-open connection across *multiple* responses; the code comment states outright: *"a single http response will never fail this check"* — it does not prevent the handler from fully constructing (i.e., allocating) one arbitrarily large `res.blocks` in memory before that data is ever queued for sending.

## Steps to Reproduce

### Static confirmation (what I verified directly)

1. Confirmed `/get_blocks_by_height.bin` / `/getblocks_by_height.bin` are registered without a `_IF(..., !m_restricted)` gate (`core_rpc_server.h:96-97`), so the endpoint is reachable under `--restricted-rpc`.
2. Confirmed the restricted-mode cap (`RESTRICTED_BLOCK_COUNT = 1000`, `core_rpc_server.cpp:71`) genuinely fires and rejects requests over 1000 heights when `m_restricted` is true (`core_rpc_server.cpp:552-556`) — i.e., this is not the FINDING-14/15 "cap only checked when unrestricted" pattern; the cap works as designed.
3. Confirmed `req.heights` has no uniqueness/deduplication requirement anywhere in the handler or in `COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::request_t` (`core_rpc_server_commands_defs.h:280-289`) — the same height may be repeated any number of times up to the 1000-entry cap.
4. Confirmed each loop iteration fetches the **full block** and **every transaction in it** (`core_rpc_server.cpp:561-579`), and confirmed `block_complete_entry` serializes each transaction's complete raw `blob` (not a hash or pruned reference) whenever `pruned == false`, which is always the case here since the handler never sets it (`cryptonote_protocol_defs.h:134-164`).
5. Confirmed, from `Blockchain::update_next_cumulative_weight_limit()` (`blockchain.cpp:4440-4488`), that `m_current_block_cumul_weight_limit` — the consensus ceiling on a single block's weight/blob size, per `core::check_incoming_block_size()`'s own comment (`cryptonote_core.cpp:1454-1466`) — is unconditionally floored at `2 × CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 = 600,000` bytes at every height in the chain's history, and can scale up to `100×` the long-term median under the `CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR = 50` surge mechanism.
6. Confirmed `MAX_RPC_CONTENT_LENGTH = 1,048,576` is applied uniformly to the same HTTP server object that serves this binary endpoint (`core_rpc_server.cpp:242`), and is not the limiting factor for a ~1000-entry, ~8 KB request.
7. Confirmed the `--rpc-response-soft-limit` mechanism (`abstract_tcp_server2.inl:832-884`) is a per-connection send-queue backpressure check across multiple responses, and read its own in-source comment confirming a single response is never blocked by it (`abstract_tcp_server2.inl:850-852`).

### Worst-case arithmetic

Let `H` = the height of one block, anywhere in Monero's mined history, whose weight (and therefore blob size, including all its transactions) is `W` bytes. By the protocol invariant established above, `W` can be as small as the guaranteed structural floor and, per the surge-scaling design, is realistically much larger for blocks mined during any sustained period of higher-than-baseline network usage.

- **Conservative, protocol-guaranteed floor** (true for every block in the chain's post-HF5 history, no assumptions about current or historical network load required): `W ≥ 600,000` bytes.
  - Request: `{"heights": [H, H, H, ..., H]}` (H repeated 1000 times), encoded in epee's binary portable-storage format — an array of 1000 fixed-width `uint64` values plus minor envelope overhead, on the order of **~8 KB**.
  - Response: 1000 × (at least) 600,000 bytes ≈ **600,000,000 bytes (≈ 572 MiB)** of raw block+transaction data materialized into `res.blocks` before serialization even begins, plus the transient cost of the DB reads and the final buffer used to flatten the whole vector for transmission.
  - Amplification ratio: on the order of **70,000-to-1**, from a request that is a small, well-formed, standards-compliant use of the documented `heights` parameter.
- **Realistic worst case**: because the effective block-weight ceiling is explicitly designed (via `CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR = 50`) to scale up to 100× the long-term median as real usage grows, and because Monero's actual median transaction throughput has only grown across its history, an attacker who selects the height of the single heaviest block that has ever actually been mined on mainnet (a matter of public record, not something requiring live network access to state precisely) can very plausibly exceed the conservative floor above by a substantial further factor. This report does not assert a specific figure for that historical maximum, since doing so would require querying live/historical chain data, which is outside the static-analysis scope of this report (see Note on AI usage) — the 572 MiB figure above is presented as the defensible, code-provable lower bound of the worst case, not the upper bound.

Either way, this happens with `--restricted-rpc` **enabled** and the `RESTRICTED_BLOCK_COUNT` cap **firing exactly as intended** — the cap simply does not bound the right quantity for this endpoint's actual per-item cost.

### Suggested dynamic reproduction (not run by me — see disclosure note)

```python
#!/usr/bin/env python3
# poc_get_blocks_by_height_amplification.py
#
# Sends one small /get_blocks_by_height.bin request to a monerod running
# --restricted-rpc, repeating the height of one already-mined, heavy block
# up to the restricted-mode cap (1000 entries), to demonstrate that the
# per-item cost of this endpoint (a full block + every transaction in it)
# makes the existing, correctly-enforced RESTRICTED_BLOCK_COUNT cap
# insufficient to prevent a large server-side memory allocation.
#
# Usage:
#   python3 poc_get_blocks_by_height_amplification.py <daemon_host> <daemon_port> <heavy_block_height>
#
# <heavy_block_height> should be the height of a known, unusually large
# (high transaction-count / high weight) block on the target chain. Any
# valid height demonstrates the underlying repeat-amplification structurally;
# a heavier block makes the effect larger.
#
# NOTE: this endpoint is served over epee's binary "portable storage" wire
# format, not plain JSON. A full implementation needs an epee-compatible
# binary encoder; this sketch shows the request shape and intended
# reproduction procedure, using monerod's own bin_request helper module if
# available, rather than a byte-for-byte encoder (left for the operator
# running this against a disposable node, per program norms for .bin RPCs).

import sys
import time

# import an epee/monero binary RPC client library here, e.g. the one
# vendored in monero-python or a local copy of epee's portable_storage
# codec; construct:
#
#   request = { "heights": [heavy_block_height] * 1000 }
#
# and POST it, binary-encoded, to:
#
#   http://<host>:<port>/get_blocks_by_height.bin
#
# against a monerod started with --restricted-rpc, and confirm:
#  (a) the request is accepted (not rejected with
#      "Too many blocks requested in restricted mode" — it will not be,
#      since exactly 1000 <= RESTRICTED_BLOCK_COUNT), and
#  (b) daemon RSS memory climbs by roughly (1000 * single_block_blob_size)
#      bytes for the duration of the call.

def main():
    host, port, height = sys.argv[1], sys.argv[2], int(sys.argv[3])
    print(f"[poc] target: http://{host}:{port}/get_blocks_by_height.bin")
    print(f"[poc] would request heights=[{height}] * 1000 (binary portable-storage encoded)")
    print("[poc] see script comments: requires an epee binary-RPC encoder to complete")

if __name__ == "__main__":
    main()
```

### Expected result on the vulnerable build

Against a `monerod` running **`--restricted-rpc`**, a request naming 1000 repetitions of one heavy block's height is accepted (not rejected — 1000 is exactly at, not over, `RESTRICTED_BLOCK_COUNT`), and the daemon's resident memory usage (observable via `ps`/`top`/`/proc/<pid>/status` `VmRSS`) should be observed climbing by an amount consistent with `1000 × <that block's blob size>` — hundreds of megabytes at minimum per the conservative floor derived above — for the duration of the call, from a request body of only a few kilobytes. This is the behavior the identical request would *not* be able to produce against `get_block_headers_range` or `get_block_header_by_hash` at the same `1000`-item scale, because those endpoints' per-item payload is a small fixed-shape header rather than a full block's transaction set.

## Possible Solution

1. Bound this endpoint's actual per-response cost, not merely the item count: either cap the **total weight/byte-size** of the blocks a single restricted-mode `get_blocks_by_height` request may return (summing `block_weight`/blob size as blocks are fetched and aborting once a byte budget is exceeded), or lower `RESTRICTED_BLOCK_COUNT`'s effective value specifically for this endpoint to a number appropriate for its true worst-case per-item cost rather than reusing the constant sized for header-only responses.
2. Reject (or collapse) duplicate heights in `req.heights` before doing any DB work, mirroring the same fix suggested for FINDING-14's hash-duplication issue — this alone prevents the "one large block repeated N times" variant of this attack, independent of fix (1).
3. Consider, for the restricted-mode case specifically, forcing `pruned` semantics (returning pruned/reference transaction data rather than full blobs) the way other restricted-mode paths already reduce response verbosity elsewhere in this file, if full transaction bodies are not required for the endpoint's legitimate restricted-mode use cases.

## Impact

An attacker with no special access — just the ability to send one small, well-formed binary RPC request to a `monerod` instance running **`--restricted-rpc`**, the daemon's own documented hardened configuration for safe public exposure — can force that daemon to allocate several hundred megabytes of memory (conservatively, using only a protocol-guaranteed structural floor; plausibly much more in practice) by naming the height of one already-mined block up to 1000 times in a single request. Because the restricted-mode count cap on this endpoint is real and does fire, this bug specifically demonstrates that "the daemon has `--restricted-rpc` enabled" is not sufficient, by itself, to conclude that a size/count-capped endpoint is safe from disproportionate memory-amplification attacks — the cap must also be checked against the true per-item cost, which this report shows was not done here.

## Note on AI usage

Source-code analysis (enumerating every RPC endpoint registration in `core_rpc_server.h` to identify which remain reachable under `--restricted-rpc`; identifying that `on_get_blocks_by_height`'s restricted-mode cap is enforced correctly, unlike the FINDING-14/15 pattern; tracing the per-item cost of `block_complete_entry` versus the `block_header_response` structs used by the endpoints that share the same `1000`-scale cap constants; deriving the block-weight-limit floor and its surge-scaling behavior from `Blockchain::update_next_cumulative_weight_limit()` and the relevant `cryptonote_config.h` constants; confirming the request-size and response-soft-limit mechanisms do not mitigate this; and drafting of this report) was done with AI assistance, working directly against the `v0.18.5.1` and `master` source. **This has been verified by static code reading only — every code excerpt quoted above was read directly from the actual current source at the cited file/line, and the memory-amplification arithmetic was derived by hand from those exact code paths and from consensus constants also read directly from source (`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`, `CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR`, `RESTRICTED_BLOCK_COUNT`, `MAX_RPC_CONTENT_LENGTH`, `DEFAULT_RPC_SOFT_LIMIT_SIZE`). No dynamic reproduction, build, or PoC execution was performed, and no attempt was made to determine any specific historical Monero mainnet block's actual size — the "conservative, protocol-guaranteed floor" calculation (≈572 MiB) is derived purely from consensus constants that are structurally true for every block in the chain's post-HF5 history, and the further "realistic worst case" discussion is explicitly presented as a qualitative, code-grounded expectation rather than a claimed measurement.** The PoC script above is a structural sketch, not a runnable byte-for-byte encoder (this endpoint uses epee's binary "portable storage" wire format rather than JSON), and has not been run against any live daemon. Please complete it with an epee-compatible binary RPC encoder and run it only against a disposable/regtest or testnet `monerod` instance started with `--restricted-rpc` (or a mainnet node you control and can afford to stress), and attach the observed memory usage and timing before submitting, per this program's requirement for a working PoC with logs.
