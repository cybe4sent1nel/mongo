# cb-mpc — Negative-Result Audit Notes

**Target:** `coinbase/cb-mpc` (https://github.com/coinbase/cb-mpc)
**Commit audited:** `2f2c4f1005729bd575b6f17bce8a47478df7ce78` (2026-08-31)
**Scope per BUG_BOUNTY.md:** protocols reachable through the public C++ headers under
`include/cbmpc/api/` (signing, DKG, TDH2). `include-internal/`, `demo-*`, and
`include/cbmpc/c_api/*` are out of scope as PoC entry points.

**Result: no Critical/High finding.** This is a negative-result report, delivered per
the standing rule that every completed audit pass gets written up and handed over, not
just findings. Nothing here should be read as "the library is bug-free" — only that a
manual source review of the areas below, within the time invested, did not surface an
exploitable issue meeting the bounty's Critical/High bar (key compromise or RCE via the
public API, reachable with no or only realistic extra preconditions).

## Areas reviewed (api layer + underlying protocol/crypto layer)

1. **TDH2** (`src/cbmpc/api/tdh2.cpp`, `src/cbmpc/crypto/tdh2.cpp`)
   - `dkg_additive` / `dkg_ac`, `encrypt`, `verify`, `partial_decrypt`,
     `combine_additive`, `combine_ac`.
   - Public-key `Gamma` binding to `(Q, sid)` is checked both at deserialization
     (`validate_public_key`) and again inside `ciphertext_t::verify` (defense in depth).
   - Subgroup/infinity checks (`curve.check`) on every point taken from an opaque blob
     or the wire (`Q`, `Gamma`, `R1`, `R2`, `Xi`, `Qi`).
   - `combine_additive` rejects a `public_shares` set that doesn't sum to `pub_key.Q`,
     and rejects duplicate/out-of-range `rid`s in the partial-decryption set.
   - `combine_ac` correctly gates on `ac.enough_for_quorum` before reconstruction and
     re-validates that the reconstructed exponent from the *selected* public shares
     equals the real public key.

2. **ECDSA-2PC** (`src/cbmpc/api/ecdsa2pc.cpp`, `src/cbmpc/protocol/ecdsa_2p.cpp`)
   - `dkg`, `refresh`, `sign` (the only signing entry point in the public header —
     `sign_with_global_abort` is intentionally *not* exposed in `include/cbmpc/api/ecdsa_2p.h`,
     consistent with SECURE_USAGE.md's caveat about that variant's bit-leak-on-cheat
     property).
   - Key-blob deserialization (`blob_to_key`) enforces: valid curve, Paillier
     modulus size and validity (`verify_cipher`), `x_share` bounded to `Z_N`, and for
     P1 blobs that `c_key` actually decrypts to `x_share` — rejecting a
     mismatched/forged blob before it reaches signing.
   - `detach_private_scalar` / `attach_private_scalar`: the detached blob is made
     invalid-by-construction (`x_share == N`, out of range) so it can't accidentally be
     used for signing; `attach_private_scalar` re-derives and checks
     `(x mod q)*G == public_share_compressed` before accepting a reattached scalar.
   - The final produced signature is **self-verified** against the public key
     (`ecc_verification_key.verify(...)`) before being returned, so a cheating
     counterparty's manipulated Paillier ciphertext produces an error rather than a
     bad or leaking signature — the correct fail-closed behavior.
   - The Paillier-based ZK proof used to bind the ciphertext to the signature
     (`zk_ecdsa_sign_2pc_integer_commit_t`) enforces every published range on
     verify (`check_open_range` / `check_right_open_range`) that `prove()` produces.

3. **Schnorr-2P / EdDSA / BIP340** (`src/cbmpc/protocol/schnorr_2p.cpp`)
   - `s = s1 + s2` combination is correct given additive key shares.
   - BIP340 even-`y` nonce/challenge negation (`k1,k2 = q-k1,q-k2` and `e = q-e` when
     `Q.y` is odd) is the standard, correct fix-up; `rx` is invariant under the
     negation so it remains valid for the challenge hash.
   - Both variants self-verify the produced signature before returning it.

4. **EC-DKG** (`src/cbmpc/protocol/ec_dkg.cpp`) — 2-party and n-party (incl.
   access-structure DKG/refresh).
   - Uses commit-then-reveal-then-DL-proof of `Q_i = x_i·G` before any party's share
     is accepted into the sum — the standard defense against rogue-key attacks in
     naive multi-key aggregation.
   - `refresh` / `refresh_ac` re-derive and cross-check the reconstructed `Q` against
     the pre-refresh key at every step.

5. **ECDSA-MPC (OT-based multiparty signing)** (`src/cbmpc/protocol/ecdsa_mp.cpp`,
   `ot.cpp`)
   - `ot_role_map` is fully validated (dimensions, anti-symmetry, no self-role) before
     use as an index, closing a would-be OOB-via-attacker-shaped-map path.
   - The OT-extension correlation check (`step2_S2R_helper`) accumulates failures into
     `any_fail` instead of early-returning, with an explicit comment noting this is to
     avoid leaking the position of the first mismatch via timing — deliberate
     side-channel awareness.
   - The final signature is self-verified against the public key before being handed
     to `sig_receiver`, same pattern as the 2P protocol.

6. **Core serialization** (`include-internal/cbmpc/internal/core/convert.h`,
   `src/cbmpc/core/convert.cpp`, `buf.cpp`)
   - Length-prefixed (`convert_len`) fields are capped at `MAX_CONVERT_LEN` (64 MiB);
     container element counts capped at `MAX_CONTAINER_ELEMENTS` (2^20).
   - `at_least()` / `forward()` do explicit overflow-safe bounds checks before every
     read; `deser()` rejects trailing bytes. No OOB read/write path found for
     attacker-controlled blobs (`key_blob`, `ciphertext`, `partial_decryption`, etc.)
     reaching this layer from the public API.

7. **Paillier ZK proofs** (`src/cbmpc/zk/zk_paillier.cpp`) — `valid_paillier_t`,
   `paillier_zero_t`, `two_paillier_equal_t`, `pdl_t` (Paillier-discrete-log linkage),
   `paillier_range_exp_slack_t`. Range checks, coprimality checks, and small-factor
   checks are present on every verify path and match the bounds used on the
   corresponding prove path.

8. **PVE (verifiable backup encryption)** (`src/cbmpc/protocol/pve.cpp`)
   - `decrypt()` calls `verify()` by default (`skip_verify=false`), so a malformed
     cut-and-choose ciphertext is rejected before any decryption is attempted.
   - `restore_from_decrypted` zeroes and errors out (rather than returning a partially
     reconstructed value) whenever `x*G != Q`.

## What wasn't fully verified

Time was not spent on a from-scratch cryptographic security proof of the OT-extension
correlation check or the multiparty-ECDSA ElGamal-commitment/MtA construction in
`ecdsa_mp.cpp` (lines ~180-490) beyond confirming the integration-level defenses above
(input validation, self-verification of output, side-channel-aware branch-free checks).
That construction appears to be original/CB-specific and a rigorous soundness check
would need the accompanying spec (`docs/spec/`) rather than code reading alone. Also
not reviewed in depth: `int_commitment.cpp`'s hardcoded Pedersen parameters generation
path, `hd_keyset_*` derivation code, and the base RSA/Paillier primitive files
(`base_rsa.cpp`, `base_paillier.cpp`) beyond their call sites above.

## Conclusion

No report was filed. The codebase shows consistent, deliberate defense-in-depth:
subgroup/infinity checks on every externally-supplied point, range/coprimality checks
matched between prove/verify, fail-closed blob validation at every opaque-blob
boundary, and — notably — every signing protocol self-verifies its own output against
the public key before releasing it, so a cheating counterparty produces an error
instead of a bad or leaking signature. This matches a previously-audited, professionally
engineered library, and is consistent with no fresh Critical/High bug being found in the
areas listed above.
