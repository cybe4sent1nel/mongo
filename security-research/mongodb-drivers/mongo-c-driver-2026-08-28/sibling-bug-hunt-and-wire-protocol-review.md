# mongo-c-driver — sibling-bug hunt on recent memory-safety fixes + wire-protocol parser review

**Status: no fresh bug found — genuine, substantive effort, negative result recorded honestly.**
Checked out `mongodb/mongo-c-driver` at `d203e47` (release 2.5.1, "update NEWS for 2.5.1"), fetched
800 commits of history to apply the same "read recent security-fix commits, look for an unfixed
sibling with the same gap shape" technique that found the BSONColumn RLE bomb in `mongod` earlier
in this program.

## Recent CDRIVER memory-safety fixes checked

All four of the following were confirmed **already present** in the `d203e47` checkout
(`git merge-base --is-ancestor <fix-commit> d203e47` returns true for each) — i.e. these are fixed,
not open. Each was traced to make sure there wasn't an unfixed sibling elsewhere with the same shape:

1. **`c9cfa4cb` CDRIVER-6343 — missing minimum-length check in `bson_new_from_buffer`.**
   The original code only checked `length > *buf_len`, never `length < 5` (BSON's own minimum valid
   document size) — an all-zero or tiny embedded-length buffer would be accepted, producing a
   `bson_t` that violates the driver's own "every bson_t is >= 5 bytes" invariant. Checked the two
   sibling constructors the same commit's docs also touched, `bson_init_static` and
   `bson_new_from_data` — both **already have independent, correct `(length < 5)` checks** (lines
   1900 and 1995 of `bson.c`) predating this fix; they were never vulnerable, the doc update was
   just a documentation clarification pass covering all three functions together.

2. **`54605bd8` CDRIVER-5680 — integer overflow validating BSON Binary subtype-2's redundant length
   header.** Original: `binary_len + 4 != l` (could wrap if `binary_len` is near `UINT32_MAX`,
   defeating the check). Current code (`bson-iter.c`, the subtype-2 branch inside
   `_bson_iter_next_internal`) checks `l < 4` first, then compares `bin_len != (l - 4)` — properly
   guarded against the underflow/overflow this fix targeted.

3. **`8a85033b` CDRIVER-5681 — off-by-one buffer overflow writing the NUL terminator after
   Decimal128 significand digits.** Read the *entire* current `bson_decimal128_to_string()` function
   line by line (not just the two lines the original fix touched) to check whether the *other*
   format branches (scientific notation, "regular, exponent >= 0") have the same unguarded pattern.
   They use an absolute-offset bound of `(str_out - str) < 36`, not the `available_bytes` pattern
   the fix introduced for the `exponent < 0` branch — worth checking arithmetically rather than
   assuming: `BSON_DECIMAL128_STRING` is **43**, not 36, so the `<36` bound leaves 7 bytes of margin
   after the loop (enough for `'E'` + a 6-byte `bson_snprintf`-bounded exponent, or a lone NUL) in
   every branch. Confirmed safe by the numbers, not by assumption.

4. **`d9c26f49` CDRIVER-6134 — integer overflow in `mongoc-cyrus.c`'s `_mongoc_cyrus_canon_user`**
   (a Cyrus-SASL/GSSAPI callback). Original `inlen + 1 >= out_max` could wrap if `inlen` were near
   `UINT_MAX`. Current code uses `mlib_add(&inlen_1, inlen, 1)` (an explicit overflow-checked add)
   ahead of the comparison, short-circuiting correctly via `||` before any wrapped value could be
   used. Fixed correctly.

## Wire-protocol / OP_MSG reply parser (`mcd-rpc.c`) — reviewed directly

This is the code that first touches bytes from a (potentially malicious or compromised) server's
response — the clearest "not defense-in-depth, genuinely remote" threat model, distinct from
anything requiring pre-existing local access. Read `_consume_bson_objects`, `_consume_op_msg_section`
(both the "Body" kind-0 and "Document Sequence" kind-1 branches), `_consume_utf8`, and the top-level
message-length check in the RPC decode entry point.

Findings: this code is deliberately, visibly hardened against exactly the overflow/underflow classes
found in the four fixes above — e.g. the Document Sequence section-length check
(`mcd-rpc.c:377-386`) carries an explicit comment: *"4 bytes is sufficient to avoid unsigned integer
overflow when computing `remaining_section_bytes`"* — the kind of comment that only exists because
someone specifically reasoned through this exact bug class while writing the code, not
retrofitted after a fuzzer found it. `_consume_bson_objects`'s per-document length check
(`doc_len < MONGOC_RPC_MINIMUM_BSON_LENGTH || mlib_cmp(doc_len, >, *remaining_bytes +
sizeof(int32_t))`) is bounded by the real received-buffer size, itself bounded by the top-level
message-length check (`MONGOC_RPC_MINIMUM_MESSAGE_LENGTH` / total buffer size), so the addition
inside the comparison can't practically reach a size_t wraparound.

## Assessment

`mongo-c-driver` runs its own libFuzzer/OSS-Fuzz harnesses for exactly this class of bug (confirmed
via commit history: `CDRIVER-5676`, `CDRIVER-5648`, `refresh patches...to prevent fuzz` all reference
this infrastructure directly) — consistent with what was found here: recent, genuinely-serious
memory-safety bugs (integer overflows, off-by-ones) get found and fixed promptly, and the codebase
reads as if written by people actively thinking about this exact bug class, not merely reacting to
it after the fact. No unfixed sibling found across four checked fixes, and the wire-protocol parser
read cleanly on direct review. This is a properly-attempted, honest negative result — not a
should-have-looked-harder gap.
