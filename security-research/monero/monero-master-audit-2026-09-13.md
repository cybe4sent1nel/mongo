# Monero (monero-project/monero) — Exhaustive Fresh-Bug Audit, `master` @ `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f` (2026-09-10)

**Scope:** the request was to deeply and rigorously audit the latest Monero branch for fresh, unpatched vulnerabilities, using the disclosed HackerOne reports supplied as reference patterns, and to check the project's own vulnerability-response doc for framing. No area was to be left unaudited.

**Method:** fresh clone of `master`, unshallowed for history. Six parallel subagents each given a tight, evidence-based mandate over a distinct subsystem (wallet RPC access-control, wallet2↔daemon trust boundary, daemon RPC/ZMQ restricted-mode parity, RingCT/consensus verification, epee/P2P memory safety, multisig cryptography), explicitly told to cite exact file:line, compare against correctly-implemented siblings, state confidence, and say "found nothing" rather than pad a report. I independently re-verified every finding below against the actual source before including it, and did a chunk of the deepest work personally (the `submit_transfer` finding below is mine, found by following a very recent, not-yet-fully-applied hardening commit to its actual boundary).

**Severity throughout uses Monero's own framework** (from `monero-project/meta`'s `VULNERABILITY_RESPONSE_PROCESS.md`): **HIGH** = network-wide impact, potential to break the whole network, results in loss of XMR, or catastrophic scale; **MEDIUM** = impacts individual nodes/routers/wallets, or needs careful exploitation; **LOW** = not easily exploitable or low impact.

---

## Bottom line

No consensus-breaking, fund-theft, or network-wide bug was found. That's a genuinely clean result for the highest-stakes code (RingCT signature/commitment verification, the multisig CLSAG nonce protocol, and ZMQ/daemon RPC restricted-mode parity all held up under dedicated, independent scrutiny). What I did find is a cluster of **individual-wallet-scoped, MEDIUM-severity issues**, plus one genuine **pre-auth daemon RPC input-validation gap**:

| # | Finding | File(s) | Class | Severity (Monero's framework) | Confidence |
|---|---|---|---|---|---|
| 1 | `relay_tx` wallet-rpc still blindly trusts an attacker-supplied `pending_tx` blob — the disclosed fix only added the restricted-mode gate, not input validation | `wallet_rpc_server.cpp`, `wallet2.cpp` | Access-control/input-validation | MEDIUM by mechanism, but Monero's own team has already precedent-set this exact bug class as LOW (see below) | High |
| 2 | `submit_transfer`'s newer "extra/redundant" ownership check is circular and effectively a no-op, because the unsigned `import_key_images()` call that runs immediately before it already overwrote the very ground-truth it then checks against | `wallet2.cpp` (`parse_tx_from_str`, `import_key_images`) | Input-validation / logic bug in new hardening code | Same class/precondition as #1 | High (mine, traced end-to-end) |
| 3 | `monerod`'s public `.bin` RPC endpoints (`/get_outs.bin`, `/getblocks.bin`, etc.) parse attacker-controlled binary bodies with **no** object/field/string count limits, unlike the client-side and P2P/levin paths in the same codebase which both explicitly cap them | `contrib/epee/include/net/http_server_handlers_map2.h`, `core_rpc_server.h` | Pre-auth allocation-amplification DoS | MEDIUM | High |
| 4 | `wallet2::get_tx_entries` (`scan_tx` RPC) never checks the daemon actually returned the transaction that was requested | `wallet2.cpp` | Missing daemon-response binding check | MEDIUM | High |
| 5 | `wallet2::process_pool_info_extent` trusts a daemon-supplied `tx_hash` label for pool transactions without recomputing it from the blob | `wallet2.cpp` | Missing daemon-response binding check | MEDIUM | High |

Areas that got a dedicated, adversarial pass and came back **clean** (worth stating plainly, not just silently omitting): RingCT/CLSAG/Bulletproof(+) verification across every RCT type and the consensus dispatch layer (`tx_verification_utils.cpp`); the multisig key-exchange and CLSAG-nonce protocol (no nonce reuse, no kex-validation gap); the ZMQ restricted-RPC fix (fully wired, blocklist correctly sorted, no naming mismatches against HTTP); the SSL-fingerprint hex-decode fix and its call sites; levin P2P binary parsing bounds; and a very recent (Sept 3, 2026) transaction-deserialization hardening commit that caps `vin`/`vout`/`key_offsets` counts — I traced this myself and it's applied consistently across every RCT type's own vector-count fields too.

---

## Finding 1 — `on_relay_tx` still trusts an attacker-supplied `pending_tx` blob

**Files:** `src/wallet/wallet_rpc_server.cpp:1952-2003` (`on_relay_tx`), `src/wallet/wallet2.cpp:7641-7722` (`commit_tx`)

This is a **known, disclosed, partially-fixed** report (`relay_tx wallet-rpc skips --restricted-rpc guard...`, closed Low). The fix that shipped (commit `9731bbfbf`, "wallet_rpc_server: restrict relay_tx") added *only* the `if (m_restricted) { DENIED }` gate. It did not touch the deeper issue the same report described: `commit_tx` still only bounds-checks `ptx.selected_transfers` indices (`idx >= m_transfers.size()`) — it has no check that the transaction actually spends the key images belonging to those indices. An attacker with plain (non-restricted) wallet-rpc credentials can:

1. Build and sign their own, unrelated, self-funded, fully valid transaction `tx0`.
2. Hand-construct a `pending_tx` struct with `tx = tx0` but `selected_transfers = {i}` for a victim output index `i`, and an arbitrary `tx_key`.
3. Serialize it in the wallet's own wire format and call `relay_tx` with the hex.
4. `commit_tx` relays `tx0` (it's valid, so the daemon accepts it), then calls `set_spent(i, 0)` on the **victim's real output**, freezing it locally, and plants the attacker's chosen `tx_key` into `m_tx_keys[hash(tx0)]`.

What makes this a *fresh* observation rather than a re-report: eight months after the disclosed fix, GitLab-adjacent... sorry, Monero's own team added a genuinely thorough validator for exactly this shape of problem — `tools::wallet::sanity_check_pending_tx` (`src/wallet/pending_tx_validation.cpp`, ~770 lines, commit `1a8ca87e8`, Aug 9 2026) — and wired it into `submit_transfer`'s and `submit_multisig`'s blob-loading paths. `on_relay_tx` was never migrated to use it. The validator exists, is proven correct (it's what makes `submit_transfer`/`submit_multisig` safe against this exact attack — see below), and simply isn't called from the one place that most needs it.

**Severity call:** Monero's own team already ruled on this *exact* precondition class in the original report thread and set the precedent explicitly: relay_tx-shaped bugs that require an attacker to already hold non-restricted wallet-rpc credentials are **LOW**, "unless someone is able to steal funds" — and they confirmed a non-restricted caller can already retrieve the wallet's seed/secret keys via `query_key` (see Finding 2's precondition discussion), making this precondition roughly equivalent to full compromise already. I'm reporting the mechanism honestly rather than inflating the severity past what the vendor's own stated policy would assign it: this is a genuine, still-open completeness gap, but by their framework it's LOW, same as the original.

---

## Finding 2 — `submit_transfer`'s "extra validation" is circular: `import_key_images()` corrupts the ground truth it's about to be checked against

This is the deepest and most interesting thing I found, and it needed tracing three functions deep to be sure of it, so I've also produced a standalone write-up: `FINDING-monero-submit-transfer-circular-key-image-validation.md` (sent alongside this report). Summary:

`wallet2::parse_tx_from_str` (used by `on_submit_transfer`) does two `sanity_check_pending_tx` passes around one `import_key_images()` call:

1. **First pass** (`wallet2.cpp:8133-8144`) validates the blob's *internal* self-consistency: does `ptx.selected_transfers[j]`'s claimed key image — read from `signed_txs.key_images`, a field **inside the same attacker-controlled blob** — match the transaction's real on-chain key image? An attacker who controls both the transaction and the `key_images` array trivially satisfies this by making both agree with each other; it proves nothing about whether the wallet's own m_transfers really owns what's claimed.
2. **`this->import_key_images(signed_txs.key_images)`** (`wallet2.cpp:8166`) — this resolves to the *unsigned*, no-proof-of-ownership overload (`wallet2.cpp:13658`), which **unconditionally overwrites** `m_transfers[i].m_key_image = key_images[i]` for every index the blob supplies (not limited to `ptx.selected_transfers`), even logging a warning and proceeding when it *already* had a different, previously-known-good key image on file for that index.
3. **Second pass** (`wallet2.cpp:8176`), `expect_imported_key_images=true`, which per the wrapper (`wallet2.cpp:7266`) builds its resolver from `m_transfers[i].m_key_image` — the very field step 2 *just finished overwriting with the attacker's own values*. This "extra/redundant validation making sure key images line up" (the code's own comment) is checking a value against a copy of itself; it cannot fail for a self-consistent attacker blob no matter what indices are targeted.

Net effect: `submit_transfer`'s validation looks, at a skim, exactly as strong as it is for the safe `sign_transfer`/cold-signing paths (which correctly resolve against `m_transfers` *before* any attacker-controlled overwrite happens) — but for this one call path, both checks are tautological. The practical impact mirrors Finding 1 (freeze arbitrary victim outputs / plant false key-image + tx-key state), reachable via `submit_transfer` instead of `relay_tx`, under the identical "already has non-restricted wallet-rpc access" precondition — so I'd rate it at the same severity floor as Finding 1 by Monero's own precedent (LOW), while flagging it as a genuinely fresh logic bug in code added *after* the relay_tx report closed, that a shallow read of "there's a sanity checker for this now" would miss. See the standalone finding doc for full line-by-line proof and the exact call chain.

---

## Finding 3 — `monerod`'s public `.bin` RPC endpoints have no binary-deserialization limits

**Files:** `contrib/epee/include/net/http_server_handlers_map2.h:108` (`MAP_URI_AUTO_BIN2` macro); registered routes in `src/rpc/core_rpc_server.h` (`/get_blocks.bin`, `/getblocks.bin`, `/get_blocks_by_height.bin`, `/get_hashes.bin`, `/gethashes.bin`, `/get_o_indexes.bin`, `/get_outs.bin`, `/get_output_distribution.bin`).

The macro parses the raw POST body via `epee::serialization::load_t_from_binary(req, body)` — the **2-argument overload**, which passes `limits=NULL` down to `portable_storage::load_from_binary`, leaving `max_objects`/`max_fields`/`max_strings` all at `SIZE_MAX`. Two other call sites of the *identical* underlying binary parser in the same codebase explicitly pass a bound:

- Client-side (parsing a daemon's response): `contrib/epee/include/storages/http_abstract_invoke.h:98` — `default_http_bin_limits = {196608, 196608, 196608}`.
- P2P/levin (parsing a peer's message): `contrib/epee/include/storages/levin_abstract_invoke2.h:47` — `default_levin_limits = {8192, 16384, 16384}`.

Only the server-side HTTP `.bin` endpoint — which is exactly the surface a public/restricted node exposes to arbitrary internet clients, with no login by default, and no restricted-mode gate on `MAP_URI_AUTO_BIN2` itself (the parse happens before any handler-level check) — skips this. Because `reserve()` for an array field is sized by the wire-format's *minimum bytes per element* (e.g. 1 byte for an empty nested object/array entry) rather than the in-memory `sizeof()` of the C++ type actually allocated (tens of bytes for a `section`/`std::string`), a crafted request body under the daemon's 1 MB `MAX_RPC_CONTENT_LENGTH` cap can drive a single allocation on the order of several tens of megabytes from well under a megabyte of attacker bytes.

**Severity: MEDIUM.** Genuinely pre-auth, network-reachable, and squarely the kind of thing Monero's own VRP flags as under-covered ("a systematic DoS hunt has not been completed on any code... DoS's which do not crash a node remotely will receive a lower bounty reward" — implying they *do* want these reported). It's capped by the 1 MB body limit to a per-request amplification in the tens-of-MB range, not an instant single-shot crash, so it would need connection concurrency (not independently verified here) to become a serious resource-exhaustion DoS — I'm stating that caveat plainly rather than claiming more than was shown. Fix is a one-line change with an in-tree precedent to copy (pass a `limits_t` into the `MAP_URI_AUTO_BIN2` call, mirroring `default_http_bin_limits`).

---

## Finding 4 — `scan_tx` never checks the daemon returned the transaction that was actually requested

**File:** `src/wallet/wallet2.cpp:1694-1737` (`get_tx_entries`), reached via the `scan_tx` RPC / simplewallet `scan_tx <txid>` command.

`get_tx_entries` sends a batch of `txids` to `/gettransactions`, checks the response *count* matches (`res.txs.size() != req.txs_hashes.size()`), and for each entry re-derives `tx_hash` via `get_pruned_tx` — but never checks that this recomputed hash is actually a member of the requested set. A malicious or MITM'd daemon can swap in a different (but real, valid) transaction's blob at the same response slot; the wallet will process it under its own real hash without complaint, and the caller of `scan_tx` has no signal that the wrong transaction was processed. The very same file has the correct pattern three call sites away, in `read_pool_txs` (`wallet2.cpp:3106`): `if (txid_set.count(tx_hash) > 0) ... else MERROR("Got txid ... which we did not ask for")`.

**Severity: MEDIUM** — individual wallet, requires an actively malicious/MITM daemon, no direct fund loss (output ownership is still independently verified via view-key derivation against the real blob), but it breaks the integrity guarantee that "scan this specific txid" actually scanned that txid — relevant to merchant/exchange tooling that calls `scan_tx` to manually confirm a specific expected payment.

---

## Finding 5 — Incremental pool-tx processing trusts a daemon-supplied hash label without recomputing it

**File:** `src/wallet/wallet2.cpp:3151-3179` (`process_pool_info_extent`) → `process_pool_state` (`wallet2.cpp:3926`).

The `/getblocks.bin` incremental-pool-info extension returns `pool_tx_info { tx_hash; tx_blob; double_spend_seen }` entries. `process_pool_info_extent` validates the *blob* (`parse_and_validate_tx_base_from_blob`) but pairs it with the daemon's **self-reported** `tx_hash` field verbatim, never recomputing `cryptonote::get_transaction_hash(tx)` to confirm the label matches the bytes. This tuple flows straight into `process_new_transaction`, which also trusts its `txid` parameter without re-deriving it. The overflow path for the very same feature (when there are more added pool txs than the restricted-RPC limit, `wallet2.cpp:3171`) correctly routes through `read_pool_txs`, which *does* recompute and check the hash — so this is an inconsistency within one function, not a systemic design choice.

**Severity: MEDIUM** — same malicious/MITM-daemon precondition as Finding 4, self-corrects once the transaction confirms in a block (block-scanning path hashes correctly), no forged value/fund loss, but a genuine hash-binding gap on every wallet refresh cycle against an untrusted daemon — could mislabel which txid a payment-processing integration believes it saw.

---

## What was checked and came back clean (stated for completeness, not padding)

- **RingCT/consensus verification** (`rctSigs.cpp`, `rctOps.cpp`, `cryptonote_tx_utils.cpp`, `cryptonote_format_utils.cpp`, `blockchain.cpp`, `cryptonote_core.cpp`, and the actual per-type dispatcher `tx_verification_utils.cpp`): balance/commitment checks, ring-signature verification, and range-proof verification are applied consistently across every `RCTType` (Full/Simple/Bulletproof/Bulletproof2/CLSAG/BulletproofPlus), with fail-closed `default:` branches on unknown types. The already-disclosed `check_reserve_proof` commitment-check bug is fixed via a shared `decodeRct` helper used everywhere amount-decoding happens.
- **Multisig cryptography** (`multisig_account.cpp`, `multisig_kex_msg.cpp`, `multisig_clsag_context.cpp`, `multisig_tx_builder_ringct.cpp`): nonce generation/consumption/wipe lifecycle traced end-to-end — every nonce is single-use and zeroed in place immediately on use; the MuSig2-style CLSAG combination binds each signature to the specific transaction message; kex messages are signature- and subgroup-validated per round.
- **ZMQ / daemon-RPC restricted-mode parity**: the previously-disclosed ZMQ bypass fix is complete — every HTTP-restricted admin method with a live ZMQ equivalent is correctly blocked, the blocklist's sort/comparator bug from an earlier draft patch isn't present, and there's no other RPC transport or P2P-equivalent bypass.
- **SSL fingerprint hex-decode fix**: `set_daemon`'s RPC path now matches the CLI path; all fingerprint-consuming code paths validate decoded size.
- **Levin P2P binary parsing**: length-prefix vs. remaining-buffer bounds are correctly enforced; no `.front()`/`.back()`-on-possibly-empty UB pattern found anywhere in the P2P/RPC/daemon layers after a systematic sweep (every hit traced back to a preceding guard).
- **A very recent (Sept 3, 2026) transaction-deserialization hardening commit** (`f8e2a8709`, "cryptonote_basic: serialization checks") that caps `vin`/`vout`/total `key_offsets` counts during parsing (closing a prior allocation/CPU-complexity DoS surface) — I traced this myself and confirmed the cap is applied consistently to `rctSig`'s own vector fields (`ecdhInfo`, `outPk`, bulletproofs, CLSAGs), which are all sized relative to the now-capped `vin`/`vout` counts rather than independently attacker-controlled length prefixes.

---

## Honest limitations

- All analysis is static (source reading + targeted grep/diff), not dynamic — no PoC was built and run against a live `monerod`/`monero-wallet-rpc`. Every exploit scenario above is a traced code path, not an observed crash/exploit.
- I did not review the Bulletproofs/Bulletproof+ inner-product-argument cryptography from first principles, nor hardware-wallet (Ledger/Trezor) device-side multisig code, nor the FCMP+ full-chain-membership-proof subsystem (newer, still under active upstream development, out of the mandate's focus files).
- Finding 3's real-world DoS magnitude (whether concurrent-connection limits elsewhere in the HTTP stack already blunt it) wasn't independently verified.

All six subagent reports and my own trace notes are available if you want the raw detail behind any specific line above.
