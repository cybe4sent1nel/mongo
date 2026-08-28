# Brave Browser (brave-core) — Ethereum wallet provider audit, round 1

**Status: no exploitable bug found yet — this is a first pass, not a completed audit.**
Recorded now so the ground already covered doesn't get re-walked in a follow-up session.

## Scope and methodology

At the user's request: audit Brave's **own** source (`brave/brave-core`), explicitly
excluding stock Chromium (out of scope for Brave's bug bounty). Checked out at `92589089`
(2026-08-27). `chromium_src/` (Brave's override/patch files for Chromium behavior) and
`patches/` are in scope as Brave-authored code even though they target Chromium paths;
the separate, unmodified Chromium checkout is not part of this repo at all, so there was
nothing to accidentally wander into.

Picked `components/brave_wallet` as the highest-value first target: it's the component
where a bug has the clearest path to "critical" (loss of user funds), and it has the
textbook browser-extension attack surface — a JS API (`window.ethereum`) injected into
every web page, bridging untrusted website JS to privileged native code via Mojo IPC. This
is exactly the bug class that has hit real wallet extensions before (origin-spoofing to
steal approved-account permissions, missing per-origin permission checks before signing).

## What was traced and ruled safe

1. **Renderer-side JS bridge** (`components/brave_wallet/renderer/js_ethereum_provider.cc`,
   865 lines, read in full). This installs `window.ethereum`/`window.braveEthereum` and
   forwards `request`/`send`/`sendAsync`/`enable` calls to the browser process over Mojo.
   It does essentially no validation itself — which is correct and expected, since the
   renderer is the untrusted side of this boundary in Chromium's threat model; the real
   question is whether the browser-process side enforces everything it needs to.

2. **Origin derivation** — traced where `EthereumProviderImpl`'s `origin_` (used for every
   permission check in the class) actually comes from:
   `browser/brave_wallet/brave_wallet_tab_helper.cc:95` —
   `url::Origin origin = frame_host->GetLastCommittedOrigin();`. This is the browser
   process reading its own trusted `RenderFrameHost` state, **not** a value the renderer
   supplies over the Mojo pipe. Ruled out the classic "compromised/malicious renderer lies
   about its own origin to inherit another origin's wallet permissions" bug class — there's
   no IPC field for the renderer to lie in; the browser doesn't trust the renderer for this
   at all.

3. **Permission gate before signing/sending a transaction** — traced
   `EthereumProviderImpl::AddAndApproveTransaction` → `FindAuthenticatedAccountByAddress`
   (`ethereum_provider_impl.cc:1443-1466`): rejects unless (a) the address resolves to a
   real known account, AND (b) that account is present in `GetAllowedAccounts(false)` for
   `origin_`, checked via `CheckAccountAllowed` (`:798-808`, a straightforward
   case-insensitive address-list membership check — no logic bug found in it). Confirmed
   this gate sits in front of `AddUnapprovedEvmDappTransaction`, i.e. a website cannot get a
   transaction signed for an address it hasn't been explicitly granted via
   `eth_requestAccounts`/the connect-site permission flow, regardless of what it passes as
   `from`.

4. **Sub-request origin parsing for the permission-approval UI**
   (`brave_wallet_tab_helper.cc`'s `GetBubbleURL`/`ParseRequestingOriginFromSubRequest`)
   — traced `request->requesting_origin()` back to Chromium's own
   `permissions::PermissionRequest`/`PermissionRequestManager` infrastructure, which is
   itself browser-side-sourced, not renderer-supplied. Not a spoofing vector.

## Not yet covered (honest inventory for a follow-up round)

This was one focused pass through one request path (`eth_sendTransaction`/account
authorization) in one provider (Ethereum). Explicitly **not yet audited**:

- The Solana and Cardano JS providers (`js_solana_provider.cc` — 1160 lines, `js_cardano_provider.cc`)
  and their browser-side counterparts — same bug class to check, different code, not yet read.
- `eth_sign`/`personal_sign`/`eth_signTypedData` and SIWE (`Sign-In with Ethereum`) message
  handling — briefly seen (`origin_ != siwe_message->origin` check at line 456) but not
  traced end to end the way the transaction path was.
- The actual keyring/seed-derivation and signing crypto itself
  (`browser/internal/hd_key*.cc`, `secp256k1_signature.cc`, the ZCash/Cardano/Bitcoin/
  Polkadot HD-derivation code and Rust components `cardano_tx_decoder.rs`,
  `polkadot_extrinsic.rs`, `sr25519.rs`) — a memory-safety or cryptographic implementation
  bug here (not a permission-check bug) is a completely different, also high-value, avenue
  not touched this round.
- `cosmetic_filters`/`brave_shields` (parses untrusted ad-block filter list syntax —
  classic memory-safety surface for a filter-list-parsing engine).
- `ipfs`/`brave_webtorrent` (parse untrusted decentralized-network content).
- `chromium_src/` overrides specifically for security-relevant Chromium subsystems
  (sandbox, site isolation, permission broker) — not yet swept at all.

## Assessment so far

The one path fully traced this round (Ethereum dApp-permission → transaction-signing gate)
is correctly implemented: origin is browser-derived and unforgeable by the renderer, and
the authorization check is a real gate in front of signing, not a client-side-only check.
No finding from this round. Given the size of `brave_wallet` alone (685 files) and the
number of untouched sibling components listed above, this is a first pass, not a verdict on
Brave as a whole — flagging that explicitly rather than implying more coverage than was
actually done.
