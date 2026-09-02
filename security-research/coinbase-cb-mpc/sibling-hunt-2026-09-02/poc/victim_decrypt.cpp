// ---------------------------------------------------------------------------
// cb-mpc PVE batch (single-recipient) — victim side.
//
// PUBLIC API HEADERS ONLY. The entry point under test is
//   coinbase::api::pve::decrypt_batch(...)
// from include/cbmpc/api/pve_batch_single_recipient.h.
//
// Input is the hex blob emitted by gen_blob (an attacker-supplied ciphertext).
// The victim supplies only its own dk/ek and the label, exactly as a real
// application would when restoring a PVE backup.
// ---------------------------------------------------------------------------
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <cbmpc/api/curve.h>
#include <cbmpc/api/pve_batch_single_recipient.h>
#include <cbmpc/core/buf.h>

static coinbase::buf_t from_hex(const std::string& s) {
  coinbase::buf_t out(static_cast<int>(s.size() / 2));
  for (size_t i = 0; i < s.size() / 2; i++) {
    out.data()[i] = static_cast<uint8_t>(strtoul(s.substr(i * 2, 2).c_str(), nullptr, 16));
  }
  return out;
}

int main(int argc, char** argv) {
  const char* path = (argc > 1) ? argv[1] : "blob.txt";
  std::ifstream f(path);
  if (!f) {
    printf("cannot open %s\n", path);
    return 1;
  }

  std::string ek_hex, dk_hex, ct_hex, label_str, line;
  while (std::getline(f, line)) {
    std::istringstream is(line);
    std::string key;
    is >> key;
    if (key == "EK") is >> ek_hex;
    else if (key == "DK") is >> dk_hex;
    else if (key == "CT") is >> ct_hex;
    else if (key == "LABEL") is >> label_str;
  }

  coinbase::buf_t ek = from_hex(ek_hex);
  coinbase::buf_t dk = from_hex(dk_hex);
  coinbase::buf_t ct = from_hex(ct_hex);
  coinbase::mem_t label = coinbase::mem_t::from_string(label_str);

  printf("[victim] ek=%d bytes dk=%d bytes ciphertext=%d bytes label=\"%s\"\n", ek.size(), dk.size(), ct.size(),
         label_str.c_str());

  int batch_count = -1;
  coinbase::error_t rv = coinbase::api::pve::get_batch_count(ct, batch_count);
  printf("[victim] get_batch_count -> rv=%d batch_count=%d\n", (int)rv, batch_count);

  std::vector<coinbase::buf_t> out_xs;
  printf("[victim] calling coinbase::api::pve::decrypt_batch(...)\n");
  fflush(stdout);

  rv = coinbase::api::pve::decrypt_batch(coinbase::api::curve_id::p256, dk, ek, ct, label, out_xs);

  printf("[victim] decrypt_batch returned rv=%d, out_xs.size()=%zu\n", (int)rv, out_xs.size());
  return 0;
}
