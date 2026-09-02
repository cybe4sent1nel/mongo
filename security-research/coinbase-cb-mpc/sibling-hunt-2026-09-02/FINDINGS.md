# cb-mpc — regression-sibling hunt against the 2026 security fixes

**Target:** `coinbase/cb-mpc` @ `2f2c4f1005729bd575b6f17bce8a47478df7ce78` (master, 2026-08-31)
**Question asked:** for each past High/Critical security fix, is there an *unpatched sibling* — the same
bug class in a code path the fix missed — that is reachable through the supported public API
(`include/cbmpc/api/`) and would qualify as High or Critical (key compromise or RCE)?

**Answer: no High or Critical sibling found.** Two genuine unpatched defects were found and are
written up below, but both land at Low severity on Coinbase's own cb-mpc scale (which pays only for
key compromise or RCE), so neither is submitted as a bounty report. Everything is stated at the
severity I could actually demonstrate — Finding 1 in particular was *downgraded* after building the
library and testing it, because the exploit primitive I predicted from source reading did not
materialize in practice.

Build used for all testing: OpenSSL 3.6.4 built from the repo's own script, `-DCMAKE_BUILD_TYPE=Debug`,
ASan + `-fno-omit-frame-pointer`, `BUILD_TESTS=OFF`.

---

## 1. Methodology

Every commit in the repository's history (68 commits) was classified; 16 are security fixes. For each
fix I extracted the *bug class*, then swept the whole tree for other instances of that class and
checked reachability from `include/cbmpc/api/`.

| # | Fix | Bug class | Sibling sweep result |
|---|-----|-----------|----------------------|
| #136 | `pdl_t::verify` response range bound | ZK bound off-by-a-factor | Bound was *widened* (completeness fix, not soundness). Checked the analogous bounds in `zk_ecdsa_sign_2pc_integer_commit_t::verify` against its prover sampling ranges — consistent. |
| #135 | Validate peer input before use (mpc_job / ECDSA-MP / TDH2 / OT) | use-before-validate | Swept every peer-supplied value in `ecdsa_mp.cpp` rounds 3–8: each is verified before it is summed or hashed into the transcript. **Except** the `.at()` calls — see Finding 2. |
| #132 | Reject non-canonical Ed25519 point encodings | non-canonical encoding accepted | Other curves decode through OpenSSL `EC_POINT_oct2point`, which enforces `x < p`; scalars are range-checked at every consumer. Clean. |
| #131 / #126 | Clear signature/plaintext outputs before use; never return unverified output | partially-written output on failure | Applied consistently across `ecdsa_2p`, `ecdsa_mp`, `eddsa_2p/mp`, `schnorr_2p/mp` api wrappers and `aes_gcm_t::decrypt`. Clean. |
| #125 | Validate R1/R2 are on the signing curve in ECDSA-2P | ZK verify called with a **peer-supplied curve-defining argument** | This is the highest-value class: `uc_dl_t::verify` / `uc_batch_dl_t::verify` / `dh_t::verify` / the ElGamal-com proofs all take `curve` from their *first argument*. I enumerated every call site: `ecdsa_2p` (fixed), `schnorr_2p`, `schnorr_mp`, `ec_dkg` (2p, mp, ac), `ecdsa_mp`, `hd_keyset_*`. In every remaining case the curve-defining argument is either locally computed (`E`, `P`, a validated sum) or explicitly `curve.check(...)`-ed against the session curve first. Clean. |
| #124 | Correct sign of Paillier-decrypted `s` in ECDSA-2P | Paillier plaintext representative used without sign correction | Swept the other places a Paillier representative crosses into `Z_q`: `refresh()` (documented unreduced-integer invariant, bounded by `N.is_in_range` in `blob_to_key`), `blob_to_key` (`plain != N.mod(x_share)` cross-check), `hd_keyset_ecdsa_2p` (P1's share and `c_key` are carried unchanged; P2 absorbs the delta — invariant preserved). Clean. |
| #117 / #99 | Bound modulus buffers, `buf_t` aliasing | unbounded bignum / aliasing | `bn_t::MAX_SERIALIZED_BIGNUM_BYTES` enforced at deserialization; `bn_t::to_bin(dst,size)` is `cb_assert`-guarded and `cb_assert` is **not** NDEBUG-gated, so oversize is fail-closed. Clean. |
| #114 / #109 | Additive share reconstruction; PVE decrypt row search | logic | Reviewed; current code re-derives sizes from the data it validates. |
| #107 | `MODULO` macro safe under early return | RAII correctness | Now a scope guard. Clean. |
| #57 | **Out-of-bounds read in PVE** (`row.r.take(16)` / `.skip(16)` with no length check) | `mem_t::take/skip/range` used on attacker-controlled data with no size check | Full sweep of every `.take(` / `.skip(` / `.range(` in `src/` + `include*/` (33 sites). All are now either preceded by an exact size check or operate on a locally computed fixed-size hash/DRBG output. **The class itself is clean — but the *adjacent* pattern of indexing a container by a count that was never checked against it is not: see Finding 1.** |
| #54 | Buffer overflow in converter (`bits_t::convert`) | deserializer reads without `at_least` | Swept every `converter.current()` use (30 sites): each read path is guarded by `at_least(...)` first. `convert_len` caps at 64 MiB, `convert_vector` caps at 2^20 elements and pre-checks remaining bytes. Clean. |
| #17 / #16 | Zeroize plaintext on AES-GCM failure; RSA-OAEP MGF1 | crypto misconfiguration | Present in current code. |

Additional areas checked while hunting, all clean: access-structure parsing (node count **and** depth
bounded, plus an iterative variant), `verify_share_against_ancestors_pub_data` (validates OR/AND/THRESHOLD
consistency from the local leaf to the root using `find()` with graceful missing-key errors), OT-extension
matrix indexing (`h_matrix_256rows_t` row/col arithmetic and the `e[index]` → `s[beta]` byte-bounded index
trick), `job_util.h` public-job validation (`self` bounds, name uniqueness, 2..64 parties), and the
confirmed absence of `sign_with_global_abort` from `include/` (it exists only in `include-internal/`,
so the documented bit-leak variant is genuinely not part of the public API surface).

---

## 2. Finding 1 — `ec_pve_batch_t`: `Q[i]` indexed by a count that is never checked against `Q.size()`

**Severity: Low** (out-of-range `std::vector::operator[]` / UB; on the tested build it degrades to a clean
error return — no crash, no disclosure). Not submitted.

### Root cause

`ec_pve_batch_t` carries two independent notions of "how many scalars are in this batch":

- `n` — a constructor argument, taken from the **outer** ciphertext blob's `batch_count` field
  (`src/cbmpc/api/pve_batch_single_recipient.cpp:19-25, 112, 159-162`);
- `Q.size()` — the length of the point vector inside the **inner** serialized body.

`ec_pve_batch_t::convert()` (`include-internal/cbmpc/internal/protocol/pve_batch.h`) *tries* to tie them
together, but the guard runs before the read and is therefore a no-op on deserialization:

```cpp
void convert(coinbase::converter_t& converter) {
  if (int(Q.size()) != n) { converter.set_error(); return; }   // passes: ctor did Q.resize(n)
  converter.convert(Q, L, b);                                   // <- clears Q and resizes it to the
  ...                                                           //    attacker's wire-declared count
}
```

The only place `Q.size() == n` is actually enforced is `ec_pve_batch_t::verify()`
(`src/cbmpc/protocol/pve_batch.cpp:78`) — and the public decrypt entry point deliberately skips it:

```cpp
// src/cbmpc/api/pve_batch_single_recipient.cpp:173
rv = pve_ct.decrypt(bridge, ..., /*skip_verify=*/true);
```

which is the documented contract of that API ("This function intentionally does not verify `ciphertext`
before decryption", `include/cbmpc/api/pve_batch_single_recipient.h:44-46`). `decrypt()` then reaches:

```cpp
// src/cbmpc/protocol/pve_batch.cpp:181-184
for (int i = 0; i < n; i++) {
  MODULO(q) x[i] = x0[i] + x1[i];
  if (Q[i] != x[i] * G) return coinbase::error(E_CRYPTO);   // i can exceed Q.size()
}
```

### Reachability, confirmed

`poc/gen_blob.cpp` builds a ciphertext with outer `batch_count = 64` and an inner body carrying **one**
Q point, and `poc/victim_decrypt.cpp` (public API headers only) calls
`coinbase::api::pve::decrypt_batch(...)`. Reaching the loop requires the attacker to make index 0
verify, which they can: the base PKE is a *public*-key scheme (`base_pke_i::encrypt` is itself public
API), so the attacker encrypts the exact 16-byte DRBG seed that makes `x[0]` equal the discrete log of
the single Q point they supplied. `poc/evidence_gdb.txt` is the debugger transcript:

```
loop index i        = 0
declared n          = 64   (from attacker-supplied outer blob batch_count)
actual  Q.size()    = 1    (from attacker-supplied inner body)
...
loop index i        = 1  >= Q.size() = 1  -> out-of-range std::vector::operator[]
```

### Why this is only Low — the part I got wrong on first reading

Reading the source, this looked like a heap out-of-bounds read on a `std::vector<ecc_point_t>`, i.e. a
wild `EC_POINT*` fed straight into `operator!=` — an RCE-class primitive. Building it and testing it
showed that is **not** what happens: the constructor does `Q.resize(n)` *before* deserialization shrinks
the vector, and `clear()`/`resize()` never shrink capacity, so every index in `[Q.size(), n)` still lands
inside the vector's own allocation. The slots hold destroyed-but-zeroed `ecc_point_t` values
(`curve.ptr == 0x0`, `ptr == 0x0`), the comparison fails, and the call returns `E_CRYPTO`. ASan does not
fire. It is real undefined behaviour (reading past `size()`, touching destroyed objects) and worth
fixing, but on this build it is not a memory-disclosure or corruption primitive.

### Fix

Move the guard after the read, or drop `n` and derive the batch count from `Q.size()` the way
`ec_pve_ac_t` already does (`aggregate_to_restore_row` uses `int batch_size = int(Q.size())`, which is
why the access-structure variant is not affected by this bug).

---

## 3. Finding 2 — uncaught `std::out_of_range` from peer-controlled maps in access-structure DKG/refresh

**Severity: Low/Medium (availability).** Explicitly outside cb-mpc's paid tiers, which cover only key
compromise and RCE. Not submitted; reported here as a hardening item.

`key_share_mp_t::dkg_or_refresh_ac` reads a peer's broadcast map with `std::map::at`, which throws:

```cpp
// src/cbmpc/protocol/ec_dkg.cpp
397:    ecc_point_t Qj = ac_pub_all._j.at(ac.root->name);
413:      Q += ac_pub_all._j.at(ac.root->name);
426:      Qis[job.get_name(l)] += ac_pub_all._j.at(job.get_name(l));
```

`ac_pub_all` is `job.uniform_msg<ac_internal_pub_shares_t>()` — a `std::map<std::string, ecc_point_t>`
broadcast by each quorum member and deserialized with attacker-chosen keys
(`converter_t::convert_with_instance`). Nothing before these lines requires the map to contain any
particular key: the commitment and the batch-DL proof are generated by that same peer over that same
map's values, so a malicious member is free to omit an entry. Line 397 is guarded only in the refresh
branch (`if (is_refresh) ac_pub_all._j[ac.root->name] = curve.infinity();`), so plain `dkg_ac` throws;
line 426 dereferences *every* party name, which `verify_share_against_ancestors_pub_data` does not
guarantee are present (it only walks the ancestors of the local party's leaf).

Reachable from the public `dkg_ac` / `refresh_ac` entry points of `ecdsa_mp`, `eddsa_mp`, `schnorr_mp`
and `tdh2`. The library's contract everywhere else is `error_t` return codes, and the same call paths
are exposed through the C API and Go bindings, where an escaping C++ exception becomes
`std::terminate()`. One malicious quorum member can abort every honest party's DKG.

**Fix:** replace `.at()` with `find()` + `E_BADARG`, as `verify_share_against_ancestors_pub_data`
already does two frames down.

---

## 4. Bottom line

The sibling hunt did not turn up a High or Critical. The 2026 hardening pass on this repository was
thorough: the classes that produced the past High-severity fixes (missing curve checks before ZK
verification, unbounded `take`/`skip` on wire data, unguarded converter reads) are now closed
everywhere I could reach, and every signing protocol additionally self-verifies its own output before
releasing it. What survives are two container-indexing/lookup defects on attacker-controlled input
that fail closed in practice.
