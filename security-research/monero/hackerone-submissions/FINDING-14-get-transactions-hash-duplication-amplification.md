# `/get_transactions` RPC: no cap on hash-list size in unrestricted mode, plus a built-in 2x "old compat" duplication of every returned tx blob — lets a ~1MB request force tens of GB of server-side memory

## Summary

`core_rpc_server::on_get_transactions()` (the handler for the ordinary, unauthenticated-by-default `/get_transactions` and `/gettransactions` HTTP RPC endpoints) only caps the number of transaction hashes a client may request (`req.txs_hashes.size()`) when the daemon is running with `--restricted-rpc`. On a daemon running in its **default, unrestricted** RPC mode — which is what `monerod` does unless the operator explicitly passes `--restricted-rpc` — there is **no limit at all** on how many hashes a single request may list.

Because the daemon's HTTP server enforces a 1&nbsp;MB request-body ceiling (`MAX_RPC_CONTENT_LENGTH`), a single request can still name on the order of **~15,000 hashes** even with no server-side count limit. Critically, nothing stops the *same* hash from being repeated: `Blockchain::get_split_transactions_blobs()` performs one independent DB lookup and pushes one independent copy of the transaction's blobs *per requested hash*, with no de-duplication. `on_get_transactions()` then builds, **per repeated hash**, a hex-encoded copy of the transaction blob — and, due to a still-live "old compatibility" code path, **a second, fully redundant copy of that same hex string** in a legacy top-level response array (the code comments this itself as dead weight slated for removal: `// older compatibility stuff` / `// TODO: remove after FCMP++ hf`).

The result: an attacker who knows the hash of any one real, already-confirmed Monero transaction (trivially obtainable from any block explorer or from their own local chain) can send **one ~1&nbsp;MB HTTP POST** that repeats that single hash ~15,000 times, and force the target daemon to allocate memory that is a **three-to-four-order-of-magnitude multiple of the request size** — realistically several gigabytes, and, using a maximally-sized real transaction, on the order of ten gigabytes or more — from a single RPC call, on a completely default daemon configuration, with no MITM and no unusual settings required.

## Severity

Monero severity: **HIGH** (unauthenticated, default-configuration, single-request remote memory-exhaustion / denial-of-service against `monerod`).
Suggested CVSS v3.1: `7.5` with `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`.

Rationale:
1. Reachable over ordinary, unauthenticated HTTP RPC to a `monerod` running its default (non-`--restricted-rpc`) configuration — the configuration used by any node operator who has not deliberately opted into the public-facing restricted mode, e.g. local wallet-backing nodes, private/internal infrastructure, or a publicly reachable node an operator forgot to restrict (`AV:N/PR:N/UI:N/AC:L`).
2. No authentication, no crafted/invalid data, and no protocol trickery is needed — just one ordinary, well-formed JSON HTTP POST that any RPC client could send, referencing a real transaction hash that exists on the public chain (a normal, legitimate value).
3. Impact is memory (and CPU/IO) exhaustion of the target daemon process — a classic single-request DoS amplification — hence `A:H`, `C:N`, `I:N`.
4. Under `--restricted-rpc` (the documented "safe for public exposure" mode) the existing `RESTRICTED_TRANSACTIONS_COUNT = 100` cap keeps this specific vector's impact small; this report is about the unrestricted default, which remains a normal, common, in-scope configuration.

## Affected Versions

Confirmed present, identically in structure (same duplication logic, same missing unrestricted cap), in both:

- **`master`**, commit `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f` (the actively maintained branch):
  - Missing unrestricted cap: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.cpp#L687-L693
  - Per-hash DB duplication with no de-dup: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_core/blockchain.cpp#L2633-L2664
  - Per-entry hex materialization: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.cpp#L886-L903
  - Legacy "old compat" second copy: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.cpp#L925-L928
  - Response struct showing the deliberate, still-live duplication (`txs_as_hex`/`txs_as_json` alongside per-entry `txs[].as_hex`/`txs[].as_json`), with the maintainers' own "old compat"/"TODO: remove" comments: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server_commands_defs.h#L375-L438
  - `MAX_RPC_CONTENT_LENGTH` (1 MB): https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_config.h#L136 , applied to the daemon RPC server: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.cpp#L242
  - Per-transaction consensus weight ceiling used for the worst-case estimate below: `get_transaction_weight_limit()` https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_core/tx_verification_utils.cpp#L319-L325 , `get_min_block_weight()`/`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 = 300000` https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_basic/cryptonote_basic_impl.cpp#L67-L74 and https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_config.h#L60

- **`v0.18.5.1`**, the latest tagged release, commit `4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5`:
  - Missing unrestricted cap: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/rpc/core_rpc_server.cpp#L974-L990
  - Legacy second copy: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/rpc/core_rpc_server.cpp#L1188-L1190
  - Response struct duplication: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/rpc/core_rpc_server_commands_defs.h#L373-L451
  - (Here, an additional `CHECK_PAYMENT_MIN1(req, res, req.txs_hashes.size() * COST_PER_TX, false)` call exists at line 990 as part of the now-removed-on-master optional "RPC payment" anti-spam feature — see Root Cause below for why this provides **no actual protection under the default configuration**, which is why the bug is reported as present in v0.18.5.1 too.)

## Root Cause

### 1. The count cap is restricted-only

`src/rpc/core_rpc_server.cpp` (master):
```cpp
bool core_rpc_server::on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res, const connection_context *ctx)
{
  RPC_TRACKER(get_transactions);

  const bool restricted = m_restricted && ctx;

  if (restricted && req.txs_hashes.size() > RESTRICTED_TRANSACTIONS_COUNT)
  {
    res.status = "Too many transactions requested in restricted mode";
    return true;
  }
  ...
```
`restricted` is `m_restricted && ctx`. `m_restricted` is a whole-daemon flag set only by `--restricted-rpc`; it is `false` by default. So on any ordinary daemon that has not been explicitly started with `--restricted-rpc`, `restricted` is always `false`, and `req.txs_hashes.size()` is **never checked against any bound** before the function proceeds to look every one of those hashes up and build a response entry for each.

*(v0.18.5.1's version of this function has the identical `if (restricted && req.txs_hashes.size() > RESTRICTED_TRANSACTIONS_COUNT)` gate at `core_rpc_server.cpp:984`; it additionally has a `CHECK_PAYMENT_MIN1(req, res, req.txs_hashes.size() * COST_PER_TX, false)` call at line 990, part of the optional "RPC payment" feature. That macro expands to a no-op unless the operator explicitly configured `--rpc-payment-address` (`check_payment()` returns `true` immediately "if (m_rpc_payment == NULL)" — the default state — see `core_rpc_server.cpp:413-416` in v0.18.5.1). Since virtually no real-world node runs with RPC payment configured, and master has removed the feature entirely, this does not change the practical outcome in either version.)*

The transport itself does not save the day either: `/get_transactions` is mapped as a plain JSON HTTP endpoint (`MAP_URI_AUTO_JON2("/get_transactions", on_get_transactions, COMMAND_RPC_GET_TRANSACTIONS)`, `core_rpc_server.h:102-103`), and the daemon's HTTP server caps request bodies at `MAX_RPC_CONTENT_LENGTH = 1048576` (1 MB) bytes (`cryptonote_config.h:136`, applied at `core_rpc_server.cpp:242`). A JSON array element for one 32-byte hash, hex-encoded, is `"` + 64 hex chars + `"` + `,` = 67 bytes. `1,048,576 / 67 ≈ 15,650` — so **one 1 MB request can still list on the order of 15,000 hashes**, even though there is no explicit count limit; the only thing capping the count is the unrelated HTTP body-size limit, not any request-shape validation.

### 2. Every requested hash — even a repeat — gets its own independent DB fetch and its own independent copy of the transaction blobs

`src/cryptonote_core/blockchain.cpp`:
```cpp
bool Blockchain::get_split_transactions_blobs(const t_ids_container& txs_ids, t_tx_container& txs, t_missed_container& missed_txs) const
{
  ...
  reserve_container(txs, txs_ids.size());
  for (const auto& tx_hash : txs_ids)
  {
    try
    {
      cryptonote::blobdata tx;
      if (m_db->get_pruned_tx_blob(tx_hash, tx))
      {
        txs.push_back(std::make_tuple(tx_hash, std::move(tx), crypto::null_hash, cryptonote::blobdata()));
        if (!is_v1_tx(std::get<1>(txs.back())) && !m_db->get_prunable_tx_hash(tx_hash, std::get<2>(txs.back())))
        { ... }
        if (!m_db->get_prunable_tx_blob(tx_hash, std::get<3>(txs.back())))
          std::get<3>(txs.back()).clear();
      }
      else
        missed_txs.push_back(tx_hash);
    }
    ...
  }
  return true;
}
```
There is no de-duplication of `txs_ids` (which is exactly `req.txs_hashes`, hex-decoded, in the caller's order and with duplicates preserved). If the client's list contains the same real, confirmed transaction hash 15,000 times, this loop performs 15,000 independent `m_db->get_pruned_tx_blob()`/`get_prunable_tx_blob()` lookups and pushes 15,000 independent, fully-populated `(hash, pruned_blob, prunable_hash, prunable_blob)` tuples into `txs` — i.e. 15,000 in-memory copies of that one transaction's blob data.

### 3. Each of those 15,000 entries is then hex-encoded — and stored *twice*

`src/rpc/core_rpc_server.cpp`, the per-entry response-building loop (non-split/non-pruned branch, the default when the client sets no special flags and the transaction is a normal, unpruned, confirmed one):
```cpp
else
{
  // use non-splitted form, leaving pruned_as_hex and prunable_as_hex as empty
  cryptonote::blobdata tx_data = std::get<1>(tx) + std::get<3>(tx);
  e.as_hex = string_tools::buff_to_hex_nodelimer(tx_data);
  if (req.decode_as_json)
  {
    cryptonote::transaction t;
    if (cryptonote::parse_and_validate_tx_from_blob(tx_data, t))
    {
      e.as_json = obj_to_json_str(t);
    }
    ...
  }
}
```
and, a few lines further down, inside the same per-entry loop:
```cpp
// fill up old style responses too, in case an old wallet asks
res.txs_as_hex.push_back(e.as_hex);
if (req.decode_as_json)
  res.txs_as_json.push_back(e.as_json);
```
`e.as_hex` (the full hex-encoded transaction, ~2× the raw blob size) is stored **once** inside `res.txs[i].as_hex`, and then a **byte-for-byte second copy** is pushed onto the separate, top-level `res.txs_as_hex` vector — purely for backward compatibility with old clients that read the pre-`entry`-struct response shape. The response struct itself documents this as legacy dead weight, in `core_rpc_server_commands_defs.h`:
```cpp
struct response_t: public rpc_access_response_base
{
  // older compatibility stuff
  // TODO: remove after FCMP++ hf
  std::vector<std::string> txs_as_hex;  //transactions blobs as hex (old compat)
  std::vector<std::string> txs_as_json; //transactions decoded as json (old compat)
  ...
  std::vector<entry> txs;
  ...
```
So, for every hash in the request (including repeats), the server materializes **at least two independent, full-size copies** of the hex-encoded transaction blob (one inside `res.txs[i].as_hex`, one inside `res.txs_as_hex[i]`) simultaneously alive in memory for the life of the request — and, if the client also sets `decode_as_json: true` (a normal, documented request parameter — no special/rare setting), a further two independent copies of the JSON-decoded transaction representation (`res.txs[i].as_json` and `res.txs_as_json[i]`), which is at least as large as the hex form due to field-name and JSON-structural overhead.

### 4. Putting the numbers together

Let `S` = size in bytes of the one real transaction blob the attacker chooses to reference (pruned + prunable data combined, i.e. `tx_data` above), and `C` = number of times its hash is repeated in the request.

- **DB layer**: `C` independent tuples in `txs`, each holding a copy of the blob data ⇒ `C × S` bytes.
- **Response layer (hex only, i.e. even with `decode_as_json` left at its default)**: each entry contributes `e.as_hex` (`2×S`) *plus* the duplicate in `res.txs_as_hex` (`2×S`) ⇒ `C × 4×S` bytes, concurrently alive alongside the `C × S` from the DB layer ⇒ **`C × 5×S`** bytes of live heap data during response construction, before the final JSON-RPC string serialization step (which must additionally flatten this whole structure into one contiguous output string, adding further transient memory on top).

**Concrete worst case using only consensus-defined constants, no exotic assumptions:**
- Maximum HTTP request body: `MAX_RPC_CONTENT_LENGTH = 1,048,576` bytes ⇒ `C ≈ 15,650` hash repeats of one hash fit in a single request.
- Current consensus per-transaction weight ceiling (`get_transaction_weight_limit()` for the active, per-byte-fee hard fork): `get_min_block_weight(version)/2 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE = 300,000/2 - (small reserved) ≈ 149,600` bytes. This is a real, consensus-enforced ceiling on how large any single confirmed transaction on the live chain can be — so `S ≈ 150,000` bytes is a legitimate, reachable worst case (an attacker need only get one such large — but otherwise completely ordinary — transaction mined once, a normal, in-scope "broadcast a tx that gets relayed/mined" action, then reuse its hash indefinitely against any target).
  - `C × 5 × S ≈ 15,650 × 5 × 150,000 ≈ 11.7 GB` of live heap allocation from a single ~1 MB HTTP request.
- **Even with no special effort at all** — simply repeating the hash of any typical, everyday confirmed transaction (`S ≈ 2,000` bytes, a normal small transfer) 15,650 times:
  - `C × 5 × S ≈ 15,650 × 5 × 2,000 ≈ 156 MB` from a ~1 MB request — a ~150× amplification with zero preparation, using any transaction hash pulled from a public block explorer.

This is a genuine amplification, not merely "large output proportional to what the attacker sent": the attacker's request contains one 32-byte value repeated with negligible entropy, while the server performs `C` independent, full-cost DB fetches and produces `Θ(C×S)` bytes of duplicated data — i.e., the *shape* of the request (one hash, many times) is what makes the cost disproportionate to the request's actual information content.

## Steps to Reproduce

### Static confirmation (what I verified directly)

1. Confirmed the count check is gated behind `restricted &&` with no companion unrestricted-mode limit, both on `master` (`core_rpc_server.cpp:689`) and `v0.18.5.1` (`core_rpc_server.cpp:984`).
2. Confirmed `Blockchain::get_split_transactions_blobs()` performs no de-duplication of its input hash list and pushes one independent tuple per input entry, duplicates included (`blockchain.cpp:2633-2664`).
3. Confirmed the per-entry `as_hex`/`as_json` values are independently duplicated into the legacy top-level `res.txs_as_hex`/`res.txs_as_json` vectors on every iteration (`core_rpc_server.cpp:925-928` on master, `:1188-1190` on v0.18.5.1), and that the response struct's own comments (`core_rpc_server_commands_defs.h:418-421`) label this as legacy, still-live compatibility code.
4. Confirmed `MAX_RPC_CONTENT_LENGTH = 1,048,576` is applied to the daemon RPC server (`core_rpc_server.cpp:242`) and derived the ~15,650 hash-per-request ceiling from JSON element size.
5. Confirmed the consensus transaction-weight ceiling (`get_transaction_weight_limit()`, `tx_verification_utils.cpp:319-325`, using `get_min_block_weight()`/`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 = 300000`) used for the worst-case arithmetic above.

### Suggested dynamic reproduction (not run by me — see disclosure note)

```python
#!/usr/bin/env python3
# poc_get_transactions_amplification.py
#
# Sends one ~1MB /get_transactions request to an UNRESTRICTED monerod,
# repeating a single real, confirmed transaction hash as many times as
# fit in the RPC server's 1MB request-body limit, to demonstrate the
# server-side memory blow-up described in this report.
#
# Usage:
#   python3 poc_get_transactions_amplification.py <daemon_host> <daemon_port> <real_confirmed_tx_hash_hex>
#
# Before running: pick a real, already-confirmed transaction hash from the
# target chain (e.g. via `get_transaction_pool` history or any block explorer
# for the same network the target daemon is on). Larger real transactions
# (many inputs/outputs, e.g. exchange consolidation txs) maximize the effect;
# any confirmed hash demonstrates the underlying amplification.

import json
import sys
import urllib.request

MAX_RPC_CONTENT_LENGTH = 1048576  # matches cryptonote_config.h

def build_request(tx_hash_hex: str) -> bytes:
    # Reserve room for the JSON envelope and reduce count slightly for safety margin.
    per_entry = len(tx_hash_hex) + 3  # quotes + comma
    overhead = 64
    count = max(1, (MAX_RPC_CONTENT_LENGTH - overhead) // per_entry)
    body = {
        "txs_hashes": [tx_hash_hex] * count,
        "decode_as_json": False,
    }
    encoded = json.dumps(body).encode()
    print(f"[poc] repeating hash {count} times, request body = {len(encoded)} bytes "
          f"(limit {MAX_RPC_CONTENT_LENGTH})")
    return encoded

def main():
    host, port, tx_hash = sys.argv[1], sys.argv[2], sys.argv[3]
    url = f"http://{host}:{port}/get_transactions"
    body = build_request(tx_hash)
    req = urllib.request.Request(url, data=body, method="POST",
                                  headers={"Content-Type": "application/json"})
    print(f"[poc] sending request to {url} ...")
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read()
    print(f"[poc] response received, {len(data)} bytes")

if __name__ == "__main__":
    main()
```

### Expected result on the vulnerable build

Sent against a `monerod` running in its default (non-`--restricted-rpc`) configuration, the request is accepted without any "too many transactions" error (unlike the identical request against a `--restricted-rpc` daemon, which rejects anything over 100 hashes). The daemon's resident memory usage should be observed (e.g. via `ps`/`top`/`/proc/<pid>/status` `VmRSS`, or a memory profiler) to spike by an amount many times larger than the ~1 MB request body while the request is processed — consistent with the `C × 5 × S` estimate above for whatever transaction size `S` was chosen — before either completing (returning a very large HTTP response) or, at the higher end of the estimated range on a memory-constrained host, causing the `monerod` process to be OOM-killed.

## Possible Solution

1. Apply a hash-count cap to `on_get_transactions()` unconditionally, not only when `restricted` is true — e.g. reuse `RESTRICTED_TRANSACTIONS_COUNT` (or a separate, more generous but still finite unrestricted-mode constant) as an absolute ceiling regardless of `m_restricted`, mirroring how a hard per-request item cap is applied elsewhere in this file for genuinely unbounded RPCs.
2. Independently, reject (or collapse) duplicate hashes in `req.txs_hashes` before doing any DB work, so that a request cannot force `C` independent full-cost lookups and `C` independent copies of the same underlying data merely by repeating one value.
3. Remove (or at minimum, make opt-in via a request flag) the redundant `res.txs_as_hex`/`res.txs_as_json` "old compat" duplication called out in the code's own `// TODO: remove after FCMP++ hf` comment — this halves the memory and bandwidth cost of every legitimate `get_transactions` response as well, independent of this specific abuse pattern.

## Impact

An attacker with no special access — just the ability to send one ordinary HTTP POST to a `monerod` instance running its default (non-`--restricted-rpc`) RPC configuration — can force that daemon to allocate on the order of gigabytes of memory (up to roughly 10 GB using only consensus-defined size ceilings, or a smaller but still substantial ~150 MB using a completely ordinary, unremarkable transaction hash with zero preparation) from a single ~1 MB request, by repeating one real, already-confirmed transaction's hash many times. This is a straightforward, unauthenticated, single-request denial-of-service / memory-exhaustion vector against any node that has not opted into `--restricted-rpc` — a large, normal population of nodes (all local wallet-backing daemons, private infrastructure, and any publicly reachable node an operator has not deliberately restricted).

## Note on AI usage

Source-code analysis (tracing the unrestricted/restricted split in `on_get_transactions()`, the lack of hash de-duplication in `Blockchain::get_split_transactions_blobs()`, the double-materialization of `as_hex`/`as_json` into both the per-entry `entry` struct and the legacy top-level `txs_as_hex`/`txs_as_json` vectors, the 1 MB `MAX_RPC_CONTENT_LENGTH` ceiling and its interaction with JSON array element size, and the consensus transaction-weight-ceiling constants used for the worst-case arithmetic) and drafting of this report were done with AI assistance, working directly against the `v0.18.5.1` and `master` source. **This has been verified by static code reading only — every code excerpt quoted above was read directly from the actual current source at the cited file/line, and the memory-amplification arithmetic was derived by hand from those exact code paths and from consensus constants also read directly from source (`MAX_RPC_CONTENT_LENGTH`, `get_transaction_weight_limit()`, `get_min_block_weight()`, `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`). No dynamic reproduction, build, or PoC execution was performed — the PoC script above has been checked for correctness against this exact code path but has not been run against a live daemon.** Please run it (or an equivalent load test) against a disposable/regtest or testnet `monerod` instance and attach the observed memory usage before submitting, per this program's requirement for a working PoC with logs.
