# Title

`secp256k1_ellswift_xdh()` silently accepts out-of-range (`>= curve order n`) private keys instead of rejecting them as documented — the input-overflow flag from `secp256k1_scalar_set_b32()` is discarded (assigned over, not OR'd), so the function returns success and computes a shared secret using the implicitly-reduced scalar instead of returning the documented failure code

## Summary

`coinbase/secp256k1` is a fork of `bitcoin-core/secp256k1` (per its own README: "The purpose of this repository is [to] make any changes needed to make it easy to integrate and use in `coinbase/cb-mpc`"). I diffed the fork against its stated single intentional change (`f07e46d`, an explicit `void*`→`unsigned char*` cast for C++ compatibility — behaviorally inert) and confirmed the fork otherwise carries upstream `bitcoin-core/secp256k1` logic verbatim, pinned at a commit predating upstream's `v0.6.0` release cut. I then checked ~420 upstream commits made since that pin point for security-relevant fixes the fork hasn't picked up. One is a genuine, confirmed bug: `bitcoin-core/secp256k1` commit `307b49f` ("ellswift: fix overflow flag handling in secp256k1_ellswift_xdh", merged upstream Feb 2026) fixes exactly this issue — and that fix is **absent** from the coinbase fork's pinned code, which still contains the buggy version.

The bug, in `src/modules/ellswift/main_impl.h`:

```c
/* Load private key (using one if invalid). */
secp256k1_scalar_set_b32(&s, seckey32, &overflow);
overflow = secp256k1_scalar_is_zero(&s);          /* BUG: overwrites, doesn't combine */
secp256k1_scalar_cmov(&s, &secp256k1_scalar_one, overflow);
...
return !!ret & !overflow;
```

`secp256k1_scalar_set_b32()` sets `overflow = 1` when the raw 32-byte `seckey32` is `>= n` (the curve order) and gets implicitly reduced mod `n` to produce `s`. The very next line **discards** that flag entirely, replacing it with a completely different check (`s == 0`). The sibling `secp256k1_ecdh()` function in the same codebase (`src/modules/ecdh/main_impl.h:51`) does this correctly:

```c
overflow |= secp256k1_scalar_is_zero(&s);   /* correct: combine both invalid-input conditions */
```

The header doc comment for `secp256k1_ellswift_xdh` (`include/secp256k1_ellswift.h`) is explicit about the contract:

```
 *  Returns: 1: shared secret was successfully computed
 *           0: secret was invalid or hashfp returned 0
```

Because of the bug, any `seckey32` that is `>= n` but does **not** reduce to exactly `0` mod `n` (i.e. essentially every out-of-range 32-byte value an attacker or buggy caller could supply, since only exact multiples of `n` reduce to zero) is treated as valid: the function returns `1` and silently computes/returns a "shared secret" using `seckey32 mod n`, instead of returning `0` as its own documentation promises.

## Impact

`secp256k1_ellswift_xdh()` is a public, documented API (`SECP256K1_API`, `SECP256K1_WARN_UNUSED_RESULT`) intended to let a caller safely pass a 32-byte value as a private scalar and rely on the library's own return-value contract to detect and reject malformed/out-of-range input, rather than validating scalar range itself. Any application built on this fork — which by the fork's own stated purpose means `coinbase/cb-mpc` and anything consuming it — that calls this function and checks the return code as its sole validation of "is this a well-formed private scalar" will silently accept and use an out-of-range input instead of erroring out. In an MPC/threshold-signing context specifically, private-key material is frequently the output of secret-sharing arithmetic (additions/subtractions of shares) rather than a single fresh RNG draw, and such intermediate values are exactly the kind of data that can legitimately land `>= n` before modular reduction — making this exactly the class of API where callers are most likely to rely on the library's own overflow check rather than re-implementing scalar-range validation themselves. I did not have the `cb-mpc` source in this environment to confirm whether it specifically calls `secp256k1_ellswift_xdh` (vs. only `secp256k1_ecdh`, which is correctly implemented) — that is the concrete next step to establish whether this rises from "the library's documented contract is violated" to "a specific Coinbase system silently used an invalid key it should have rejected." Even without that confirmation, the bug itself is a real, verified specification violation in a security-documented cryptographic API shipped to Coinbase's own consumers, unpatched relative to the upstream fix that exists for it.

## Weakness

CWE-20 (Improper Input Validation) / CWE-1284-adjacent (a validation flag is discarded via assignment instead of accumulated via OR), in a function explicitly documented to perform this exact validation and communicate it through its return value.

## Component / Version

- Repository: `coinbase/secp256k1`
- File: `src/modules/ellswift/main_impl.h`, function `secp256k1_ellswift_xdh()`, line 574 (`overflow = secp256k1_scalar_is_zero(&s);`)
- Confirmed present on the repository's current default branch (`master`, commit `1cad9f9`, the fork's HEAD at time of audit). The fork's only intentional deviation from upstream (`f07e46d`) is a single unrelated C++-compatibility cast in `src/util.h`; this bug is inherited, unmodified, from the upstream commit the fork is pinned to.
- Fixed upstream in `bitcoin-core/secp256k1` by commit `307b49f1b996024d458a9b69e9df8d15b628d34a` ("ellswift: fix overflow flag handling in secp256k1_ellswift_xdh"), not yet merged into this fork as of this audit.

## Proof of Concept

Built the fork's actual code (`cmake -DCMAKE_BUILD_TYPE=Release .. && cmake --build .`, default module set which includes `ENABLE_MODULE_ELLSWIFT=1`) and linked a small C program directly against the resulting `libsecp256k1.so` — not source analysis alone.

```c
/* seckey_overflow = curve_order_n + 7 (reduces mod n to exactly 7, nonzero) */
int ret_valid    = secp256k1_ellswift_xdh(ctx, out_valid,    ell_a64, ell_b64, seckey_valid7,    0, hashfp, NULL);
int ret_overflow = secp256k1_ellswift_xdh(ctx, out_overflow, ell_a64, ell_b64, seckey_overflow,  0, hashfp, NULL);
```

Output:
```
seckey = 7                    -> ret=1
seckey = curve_order_n + 7     -> ret=1  (documented contract: MUST be 0, 'secret was invalid')
outputs equal (both computed with effective scalar=7)? YES

*** BUG CONFIRMED: secp256k1_ellswift_xdh() returned 1 (success) for an
*** out-of-range private key (curve_order_n + 7) instead of the documented 0.
*** It silently computed the shared secret using (seckey32 mod n) = 7
*** instead of rejecting the invalid input as its own doc comment promises.
```

Control test against the sibling `secp256k1_ecdh()` in the same build, same input class, proving the correct-vs-buggy contrast is real and isolated to `ellswift_xdh`:
```c
int ret = secp256k1_ecdh(ctx, out, &pub, seckey_overflow, NULL, NULL);
```
Output:
```
secp256k1_ecdh with seckey = curve_order_n + 7 -> ret=0 (correctly rejects overflow: YES)
```

Both binaries were compiled and run against the real, freshly-built `libsecp256k1.so` produced from this repository's own source tree, confirming the bug is present in the actual compiled artifact this fork produces, not just in a static reading of the code.

## Suggested fix

Apply the same one-line fix already merged upstream (`bitcoin-core/secp256k1@307b49f`):

```c
secp256k1_scalar_set_b32(&s, seckey32, &overflow);
overflow |= secp256k1_scalar_is_zero(&s);
```

## Notes on scope

Found by diffing this fork against upstream `bitcoin-core/secp256k1` to identify what Coinbase actually changed (essentially nothing — one inert cast) and then checking commits upstream has merged since the fork's pin point for security-relevant fixes not yet incorporated. Several other post-fork upstream commits were also checked and ruled out as inapplicable (e.g. a MuSig2 nonce-clearing regression fix, `961ec25`, turned out to fix a bug introduced by a refactor the coinbase fork never received in the first place — its `secp256k1_musig_nonce_gen_internal` still uses the older, unaffected per-iteration structure, verified by reading the actual checked-out code rather than assuming the upstream diff applied). This `ellswift_xdh` finding is the one that was reproduced end-to-end against the fork's own compiled output.
