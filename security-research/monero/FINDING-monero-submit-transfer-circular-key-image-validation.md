# Finding: `submit_transfer`'s post-import key-image validation is circular — it checks wallet state against the value it was just overwritten with, by the same attacker-controlled blob

**Status:** Unpatched as of `master` @ `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f` (2026-09-10).
**Found by:** my own direct trace, prompted by reading the git history for `src/wallet/` and noticing `pending_tx_validation.cpp` (commit `1a8ca87e8`, Aug 9 2026) was added *after*, and clearly in response to, the already-disclosed `relay_tx` blob-trust report — then checking whether it was actually wired in everywhere it needed to be.
**Confidence:** High on the mechanism (traced three functions deep, each step quoted verbatim below). Not independently built/run against a live `monero-wallet-rpc`.
**All line numbers/links pinned to commit `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f`.**

## Summary

`monero-wallet-rpc`'s `submit_transfer` RPC accepts a hex-encoded "signed tx" blob and is meant to be safe against a blob that lies about which of the wallet's own outputs it spends — unlike the already-disclosed `relay_tx` bug, which was fixed only at the access-control layer (added `if (m_restricted)`) and never got the ownership check the report asked for. `submit_transfer`'s loading path (`wallet2::parse_tx_from_str`) *does* call the newer `sanity_check_pending_tx` validator, twice, which on the surface looks like the fix `relay_tx` never got.

It isn't, for `submit_transfer`'s own attacker-facing input: the **first** validation pass checks the blob's key images against *another field of the same attacker-controlled blob* (proves nothing), and by the time the **second** pass runs — the one that's actually supposed to check against the wallet's own real state (`m_transfers[i].m_key_image`) — that real state has *already been overwritten* by an unauthenticated `import_key_images()` call sitting between the two checks, using values taken from that same blob. The second check ends up comparing a value to a copy of itself.

## The three-step trace, each step quoted verbatim from source

**Step 1 — the "pre-import" validation is blob-internal, not against real wallet state.**

`src/wallet/wallet2.cpp` (`wallet2::parse_tx_from_str`), lines 8131-8146:
```cpp
try
{
  // validate before mutating state or displaying to user
  // - Verify with the assumption signed txs are redacted.
  for (const auto &ptx : signed_txs.ptx)
  {
    // Manually check `signed_txs.key_images` so local state is not mutated before we validate.
    // We inject the key image checker because `ptx` internal sorting ambiguity makes it cumbersome to
    // directly validate key images here.
    // NOTE: These txs may be READ-ONLY, which means spent/frozen inputs are allowed.
    const auto &kis = signed_txs.key_images;
    this->sanity_check_pending_tx(ptx,
      true,
      false,
      { [&kis](const size_t i) {
        CHECK_AND_ASSERT_THROW_MES(i < kis.size(), "failed loading signed tx: ptx selected transfer "
          "is outside the bounds of imported key images");
        return kis.at(i);
      } },
      true);
  }
}
```
The resolver closure returns `kis.at(i)` — an entry from `signed_txs.key_images`, which is itself part of the exact same untrusted `hex` blob the RPC caller supplied to `submit_transfer`. The check inside `sanity_check_pending_tx` (`pending_tx_validation.cpp:404-421`) confirms the transaction's *actual* on-chain key images match what `kis` claims for the referenced `selected_transfers` indices. An attacker who controls both `ptx.tx` (their own valid, self-funded transaction) and `signed_txs.key_images` (an array in the same blob) can trivially make these agree — put the *real* key image of their own transaction at whatever index they've named in `selected_transfers`. This step, honestly, is the code's own comment: it's checking self-consistency "so local state is not mutated before we validate" — it is explicitly *not yet* a check against real wallet state.

**Step 2 — the wallet's real state gets overwritten, unconditionally, with no proof of ownership.**

Fourteen lines later, `wallet2.cpp:8166`:
```cpp
// import key images
bool r = this->import_key_images(signed_txs.key_images);
if (!r) return false;
```
This resolves to the **unsigned** overload — `wallet2::import_key_images(std::vector<crypto::key_image> key_images, size_t offset=0, boost::optional<std::unordered_set<size_t>> selected_transfers=boost::none)` (`wallet2.cpp:13658-13682`, declared with those defaults at `wallet2.h:1347`):
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
    if (selected_transfers && selected_transfers.get().find(transfer_idx) == selected_transfers.get().end())
      continue;

    transfer_details &td = m_transfers[transfer_idx];
    if (td.m_key_image_known && !td.m_key_image_partial && td.m_key_image != key_images[ki_idx])
      LOG_PRINT_L0("WARNING: imported key image differs from previously known key image at index " << ki_idx << ": trusting imported one");
    td.m_key_image = key_images[ki_idx];
    m_key_images[td.m_key_image] = transfer_idx;
    td.m_key_image_known = true;
    ...
  }
  return true;
}
```
Called with a single argument (`this->import_key_images(signed_txs.key_images)`), `offset=0` and `selected_transfers=boost::none` both take their defaults — meaning it walks **every index from 0 up to `key_images.size()-1`**, not just the indices named in any `ptx.selected_transfers`, and for each one it does `td.m_key_image = key_images[ki_idx]` **regardless of whether the wallet already had a different, previously-verified key image on file** (the code path for that case only logs a `WARNING` and "trusts the imported one" anyway). There is no signature or proof-of-ownership check anywhere in this overload — contrast with `wallet2::import_key_images(const std::vector<std::pair<crypto::key_image, crypto::signature>>&, ...)` (`wallet2.cpp:13383`, used by the `import_key_images` RPC handler itself), which *does* verify a per-key-image signature before trusting it. The overload actually invoked here is the "I already trust this list" variant — used correctly elsewhere for legitimate cold-signing round trips where the list genuinely originates from the wallet's own paired offline device, but here it's fed straight from RPC-caller-supplied bytes.

**Step 3 — the "extra/redundant validation" now checks the overwritten value against itself.**

Ten lines after the import, `wallet2.cpp:8173-8177`:
```cpp
try
{
  // extra/redundant validation making sure key images line up
  for (const auto &ptx : signed_txs.ptx)
    this->sanity_check_pending_tx(ptx, true, true, std::nullopt, true);
}
```
Here `expect_imported_key_images=true` and the resolver is `std::nullopt`, which routes through the `wallet2::sanity_check_pending_tx` wrapper (`wallet2.cpp:7266-7295`):
```cpp
void wallet2::sanity_check_pending_tx(const wallet2::pending_tx &ptx,
  const bool redacted, const bool expect_imported_key_images,
  std::optional<std::function<const crypto::key_image(const size_t)>> transfer_ki_resolver,
  const bool allow_read_only) const
{
  if (expect_imported_key_images)
  {
    const std::function<const crypto::key_image(const size_t)> temp =
      [this](const size_t i)
      {
        const auto &transfer = m_transfers.at(i);
        CHECK_AND_ASSERT_THROW_MES(transfer.m_key_image_known, ...);
        return transfer.m_key_image;
      };
    transfer_ki_resolver = temp;
  }
  wallet::sanity_check_pending_tx(ptx, this->nettype(), m_account.get_keys(), m_subaddresses,
    m_transfers, redacted, transfer_ki_resolver, allow_read_only);
}
```
The resolver now reads `m_transfers.at(i).m_key_image` — **the exact field Step 2 just finished writing, from the exact same attacker-controlled array, moments earlier, in the same function call**. This "extra/redundant" pass (the code's own words) is comparing `m_transfers[i].m_key_image` (== `signed_txs.key_images[i]`, just written) against the transaction's real key images (which, per Step 1's already-established self-consistency, also equal `signed_txs.key_images[i]` at the relevant indices). It is, for this specific call path, a tautology — it validates that the write in Step 2 succeeded, not that the wallet legitimately owned the claimed outputs before the blob arrived.

## Why this matters despite `sanity_check_pending_tx` genuinely being a good, working validator

This same function, called the same way, **is** the correct fix for the cold-signing round trip (`wallet2.cpp:7991`, `sign_multisig_tx` context) and for `load_tx`'s post-hoc double-check when `signed_txs.key_images` was populated honestly by a trusted cold device — in those flows, `m_transfers[i].m_key_image` reflects genuine prior wallet state at the time of comparison, because nothing attacker-controlled was allowed to overwrite it first. `submit_transfer`'s flow is the one place where an *unauthenticated* `import_key_images()` call sits **between** establishing the untrusted claim and checking it against "ground truth" — turning a real check into a self-fulfilling one.

## Exploit scenario

Precondition: attacker holds non-restricted (`m_restricted == false`) `monero-wallet-rpc` credentials for the victim wallet — the same precondition Monero's own team already accepted and ruled LOW severity for the sibling `relay_tx` report, on the reasoning that this level of access already permits retrieving the wallet's secret keys via `query_key` (`on_query_key`, `wallet_rpc_server.cpp`, also gated only by `!m_restricted`) and is therefore close to full compromise. I'm not claiming a stronger precondition than that established precedent.

1. Attacker calls `query_key` (`key_type: "view_key"`) to obtain the wallet's secret view key — needed because `submit_transfer`'s accepted blob format (`SIGNED_TX_PREFIX` + version byte `\x05`) is a value encrypted with `encrypt_with_view_secret_key`, i.e. symmetric encryption keyed by the wallet's own secret view scalar (`wallet2.cpp:14926` `encrypt()`/`decrypt()` family) — so a version-5 blob must be producible with that same key to pass `decrypt_with_view_secret_key` in `parse_tx_from_str`.
2. Attacker builds their own valid, self-funded transaction `tx0` (real key images `KI_A`, spending only their own outputs).
3. Attacker enumerates the victim's transfer indices (`incoming_transfers`/`get_transfers`, both read-only and available at this access level) and picks a victim index `i` they want to corrupt.
4. Attacker constructs a `signed_tx_set` with `ptx.tx = tx0`, `ptx.selected_transfers = {i}`, and `signed_txs.key_images[i] = KI_A` (i.e., they put their *own* real key image at the *victim's* index in the blob's key-images array), serializes it, encrypts with the view key from step 1, and calls `submit_transfer`.
5. Step 1's check passes (blob is self-consistent: `tx0`'s real key image at position `i` matches `kis[i]`, both attacker-chosen). `import_key_images` overwrites `m_transfers[i].m_key_image = KI_A` (the victim's real, previously-tracked key image for that output is discarded, only a `WARNING` logged). Step 3's check passes trivially (compares `KI_A` to `KI_A`). `commit_tx` then relays `tx0` and calls `set_spent(i, 0)` on the victim's real, unrelated output `i`.
6. Effect: victim output `i` is now (a) marked spent in the wallet's local cache though nothing happened to it on-chain (frozen until a `rescan_blockchain`/`rescan_spent`), and (b) has its `m_key_image` permanently corrupted to the attacker's `KI_A` in `m_key_images`/`m_transfers`, until a rescan re-derives it.

Impact is state corruption / local DoS (freeze a chosen output; poison key-image bookkeeping used by `export_key_images`/multisig flows), not fund theft — the same shape and severity class as the already-disclosed `relay_tx` finding, which Monero's own team classified LOW given the identical precondition.

## What I could not verify

I did not build and run `monero-wallet-rpc` to observe this live — the trace above is a full, direct source read of the exact call chain with every relevant line quoted, not a runtime PoC. I also did not check whether `submit_multisig`'s parallel path (`parse_multisig_tx_from_str`, `wallet2.cpp:8268`) has an analogous ordering issue — a quick read suggests it calls `sanity_check_pending_tx(ptx, false, false, std::nullopt, true)` (no `expect_imported_key_images`, resolver `nullopt`) without an intervening `import_key_images` call, which would make it not share this exact pattern, but I did not trace it as thoroughly as the `submit_transfer` path above and am not making a claim about it either way.

## Suggested fix

For the `submit_transfer` path specifically: do the ownership check *before* calling `import_key_images`, using a resolver built from `m_transfers` as it stood **prior** to this blob's arrival (exactly what `sign_multisig_tx`'s call at `wallet2.cpp:7991` already does correctly) — not from the blob's own `key_images` array, and not from `m_transfers` *after* that same blob has already written into it. If `import_key_images(signed_txs.key_images)`'s unrestricted (all-indices, no-selected_transfers-limit) overwrite semantics are needed for legitimate cold-signing flows elsewhere, consider scoping the call at this specific site to `selected_transfers` only, so an attacker can't use a `submit_transfer` call to overwrite key-image tracking for wallet outputs the transaction doesn't even reference.

## How to check this yourself

Read, in order, exactly the three quoted code blocks above at:
- https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/wallet/wallet2.cpp#L8131-L8146
- https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/wallet/wallet2.cpp#L13658-L13682
- https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/wallet/wallet2.cpp#L8173-L8177
- https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/wallet/wallet2.cpp#L7266-L7295

and confirm for yourself that the resolver in the first block reads from `signed_tx_set::key_images` (attacker blob), the function in the second block writes into `m_transfers[i].m_key_image` from that same array with no signature check, and the resolver built at the fourth block (used by the third) reads back from that same, now-overwritten, `m_transfers[i].m_key_image`.
