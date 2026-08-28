# libmongocrypt — FLE2 payload parsing + kms-message audit

**Status: no exploitable bug found — several real-looking leads traced to a confirmed
mitigated/non-exploitable conclusion. Negative result recorded honestly.**

Picked as this round's target from the HackerOne scope list: `libmongocrypt` is named
explicitly (separate from language driver bindings) as an in-scope, bounty-eligible asset.
It's a C library implementing client-side field-level/Queryable Encryption (FLE2/QE) —
memory-unsafe language + cryptographic logic, so bugs here have an unusually high ceiling
(a parsing bug can be a Critical if it lets a hostile server crash or corrupt a decrypting
client — exactly the threat model QE claims to resist). Checked out `mongodb/libmongocrypt`
at `289ca83a` (2026-08-27, "MONGOCRYPT-977 validate db and collection").

## Lead 1 (the deep one): missing `length >= 16` check in `mc_FLE2IndexedEncryptedValue_decrypt`

`src/mc-fle2-payload-iev.c:372-389`, reached from the real client-side document-decrypt path
(`mongocrypt-ctx-decrypt.c:71` → `mc_FLE2IndexedEncryptedValue_add_S_Key` →
`mc_FLE2IndexedEncryptedValue_decrypt`, invoked whenever a driver decrypts a
Queryable-Encryption equality-indexed field from a document returned by the server):

```c
uint64_t length; /* length is sizeof(K_KeyId) + ClientEncryptedValue_length. */
CHECK_AND_RETURN(mc_reader_read_u64(&reader, &length, status));
CHECK_AND_RETURN(mc_reader_read_uuid_buffer(&reader, &iev->K_KeyId, status));
uint64_t expected_length = mc_reader_get_consumed_length(&reader) + length - 16;
if (length > iev->Inner.len || expected_length > iev->Inner.len) { ... return false; }
CHECK_AND_RETURN(mc_reader_read_buffer(&reader, &iev->ClientEncryptedValue, length - 16, status));
```

`length` is read directly off decrypted plaintext with **no check that it's >= 16** before
two separate `length - 16` subtractions. If `length < 16`, both subtractions underflow
`uint64_t` and wrap to a value near `UINT64_MAX`. Traced the consequence precisely rather
than assuming exploitability:

- The "protective" check on the line above (`expected_length > iev->Inner.len`) is
  computed with the *same* underflowing arithmetic, so for `length < 16` it evaluates to
  `length + 8` (mod 2^64) — a small number that is *smaller* than the real buffer length,
  so **the check itself passes** on the malformed input it's supposed to catch. Confirmed
  by direct modular arithmetic, not by inspection alone.
- The subsequent `mc_reader_read_buffer(..., length - 16, ...)` receives the full
  `~2^64`-sized value (not re-wrapped a second time) and this **is** caught: it flows into
  `_mongocrypt_buffer_copy_from_data_and_size` (`mongocrypt-buffer.c:493`), whose first
  action is `size_to_uint32(len, &buf->len)` (`mongocrypt-util.c:50`) — an explicit
  `in > UINT32_MAX` rejection. Since the underflowed value is always `>> UINT32_MAX` for
  any `length` in `[0,15]`, this call always returns `false` cleanly before `bson_malloc`
  is ever reached. No allocation-size attack, no OOB read, no crash — a clean decrypt
  failure. Verified this is the actual final gate, not an assumption: read
  `mongocrypt-util.c`'s `size_to_uint32` directly.

Conclusion: the missing `length >= 16` check is a genuine code-quality gap (the two
"validation" lines are silently dead against the exact case they're named for), but it is
fully absorbed by an unrelated defensive cast four calls downstream. Not independently
reportable — would read as "theoretical, no working exploit," and rightly so.

### Related: `_mcFLE2Algorithm` is deliberately unauthenticated (documented, not a bug)

While tracing reachability of Lead 1, confirmed `InnerEncrypted` (the blob containing the
vulnerable `length` field) is encrypted with `DECLARE_ALGORITHM(FLE2, CTR, NONE)` —
AES-256-CTR with **no MAC**, explicitly commented in `mongocrypt-crypto.c:1156` as
*"FLE2 used with ESC/ECOC tokens: AES-256-CTR no HMAC"*. This means a party who can only
tamper with stored ciphertext bytes (e.g. a hostile/compromised `mongod`, exactly QE's
stated threat model) can flip bits in `InnerEncrypted` and get a *deterministic*
corresponding bit-flip in the decrypted `length` field — **without needing the data key at
all** (CTR malleability). This raised the stakes on Lead 1 considerably (key-free,
server-only attacker, not an insider-with-DEK scenario) — but since Lead 1 itself turns out
to be safely absorbed downstream, the malleability doesn't currently lead anywhere. Filed
here because it's a real, if intentional, design property worth knowing about if any other
`Inner`-plaintext field ever gets a similarly-unchecked arithmetic path added later.

## Lead 2: `edge_count`-driven allocation in `mc_FLE2IndexedEncryptedValueV2_parse`

`src/mc-fle2-payload-iev-v2.c:574-619`. For FLE2 "text" search type, `edge_count` is read
directly as an attacker-controlled `uint32_t` (up to 4.29 billion), then used in
`bson_malloc0(iev->edge_count * sizeof(mc_FLE2TagAndEncryptedMetadataBlock_t))`. Looked
for an unbounded-allocation DoS. Traced the actual bound: before that `bson_malloc0`, the
code requires `SEV_and_metadata_len >= kMinServerEncryptedValueLen + edge_count * 96`
where `SEV_and_metadata_len` is the *real* remaining bytes in the received buffer — capped
by the ~16 MiB BSON document limit. So `edge_count` in practice tops out around ~174,000,
not 4.29 billion; the allocation size is proportional to the actual document size an
attacker can smuggle in, not attacker-arbitrary. Not exploitable beyond "a big legitimate-
looking document," which is not a distinct vulnerability.

## Lead 3: `kms-message` (KMS/KMIP response parsing) — sibling-bug hunt off stored crash corpus

`oss-fuzz/` ships three crash reproducers from past fuzzing (`crash-kmip-parser-overflow.bin`,
`crash-kms-chunked-overflow.bin`, `crash-kms-chunked-overflow-bof.bin`) — proof this code has
been fuzzed and had real bugs before. Read the current HTTP response parser
(`kms_response_parser.c`) and KMIP TTLV reader/parser (`kms_kmip_reader_writer.c`,
`kms_kmip_response_parser.c`) end-to-end looking for an unfixed sibling of the same shape.

- `kms_response_parser_feed`/`_parse_line`: chunk size and Content-Length are both bounds-
  checked against `KMS_PARSER_MAX_RESPONSE_LEN` (16 MiB) at parse time, and the streaming
  feed function re-checks total accumulated length on every call. Reads as the post-fix
  state matching the stored `chunked-overflow` reproducers.
- `kms_kmip_response_parser_feed`: reads the 4-byte length field at a fixed, always-in-
  bounds offset (`FIRST_LENGTH_OFFSET=4`, gated by `KMS_KMIP_RESPONSE_PARSER_FIRST_LENGTH=8`
  bytes-fed requirement) and caps `first_len` against the same 16 MiB ceiling. Consistent
  with the stored `kmip-parser-overflow` reproducer being fixed.
- `kmip_reader_in_place` (`kms_kmip_reader_writer.c:257-273`) has a real code smell: it
  bounds-checks using its `pos` parameter but builds the returned sub-reader's pointer from
  `reader->pos` (a different field) — `out_reader->ptr = reader->ptr + reader->pos;` should
  by rights read `+ pos`. Checked both call sites
  (`kmip_reader_find_and_read_enum`, `kmip_reader_find_and_read_bytes`): both call this
  function immediately after `kmip_reader_find` returns, at which point `reader->pos` and
  the `pos` output parameter are always identical (find() sets `*pos = reader->pos` right
  before returning, with nothing in between to diverge them). Currently benign, but fragile:
  a future caller that reuses a reader across a save/restore of `pos` would silently break.
  Not independently exploitable today — no call site exists where the two values differ.
- Noted, not chased further: `compute_padded_length`/`CHECK_REMAINING_BUFFER_AND_RET`
  arithmetic in `kms_kmip_reader_writer.c` is done in `size_t`. On a 32-bit build,
  `pos + compute_padded_length(read_length)` could wrap where it wouldn't on 64-bit. Did
  not pursue: MongoDB's supported driver/libmongocrypt platforms are overwhelmingly 64-bit,
  and this would need a 32-bit target to matter, which lowers realistic severity enough that
  it wasn't worth the build-environment detour this round.

## Assessment

Same pattern as the mongo-c-driver pass earlier this program: this is code that reads as
if written by people who have already been fuzzed against and are actively defending this
exact bug class (integer wraparound before a length-bounded read/alloc) — every promising
underflow/overflow candidate traced to a real, verified mitigating check one or two calls
downstream, not an assumption of safety. No fresh reportable bug from this round.
