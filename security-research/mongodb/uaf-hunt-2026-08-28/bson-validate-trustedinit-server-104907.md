# bson_validate.cpp — "improper BSONElement creation" (SERVER-104907): already found/fixed by MongoDB, present in this checkout, sibling hunt

**Status: real memory-safety bug, confirmed by reading MongoDB's own fix diff — but NOT a
fresh finding. This is the exact same situation as the BSONColumn depth-reset report you
pasted earlier: MongoDB found and fixed it themselves (very recently — Aug 24-27, 2026,
literally days before this checkout), so an external report would very likely close
Informative. Flagging clearly rather than presenting it as new.**

## What it is

Found via the same technique that worked for the depth-reset bug: searched recent commit
history for `bson_validate` fixes. Found a three-commit cycle, all within 72 hours of this
repo's HEAD:

1. `03eb2d97` (Aug 24) — `SERVER-104907 Fix improper BSONElement creation in bson_validate.cpp`
2. `e1713b70` (Aug 25) — auto-revert-bot reverts it (commit authored by `auto-revert-app[bot]`
   — almost certainly an unrelated CI-queue failure, not evidence the fix itself was wrong;
   the diff that lands two days later is byte-for-byte identical in `bson_validate.cpp`)
3. `c24890b8` (Aug 27) — the same fix re-lands cleanly

**Checked this repo's actual `src/mongo/bson/bson_validate.cpp` and `bsonelement.h` — neither
fix is present.** `checkNonConformantElem` still takes `uint8_t type` (all three validator
classes), and `PreciseFrameInfo` still has the old `BSONElement elem` member rather than the
fixed `nestedElemStart`. This checkout's copy of this one file predates Aug 24, even though
other parts of the tree are newer.

## The actual bug

`PreciseFrameInfo` (pre-fix) stores a `BSONElement elem` per nesting frame, constructed via
`BSONElement(_currElem, nameLen, BSONElement::TrustedInitTag{})` in `_pushFrame`
(`bson_validate.cpp:496` in this checkout). `TrustedInitTag` is BSONElement's "skip my own
internal validation, I trust you" constructor — its whole contract is that the caller has
already confirmed the invariant `(byte at d == EOO) <=> (fieldNameSize == 0)` before calling
it.

The bug: `_pushCodeWithScope` (used to track CodeWScope's embedded scope sub-object for
depth-limit purposes) pushes an extra "dummy" frame whose `_currElem` is deliberately set to
**the NUL terminator of the CodeWScope's code string** — not a real element start at all
(the comment: *"Use the terminating NUL as a dummy scope element"*). When that dummy frame's
`.elem` later gets read — specifically in the validator's error-message-building path,
walking `_frames` to construct field-path context like `"a.b.c"` for a validation-failure
message — code calls `.fieldName()`/`.type()` on a `BSONElement` that was never a real
element to begin with. The fix's own regression test makes the trigger concrete:

```cpp
TEST(BSONValidateFast, UnterminatedStringErrorInCodeWScope) {
    // BSONCodeWScope("code", scope-object-containing-an-unterminated-string)
    // asserts the error message names the field correctly instead of misreading
    // adjacent/garbage bytes as a field name.
}
```

So: **a `$where`-style CodeWScope value whose *scope sub-object* contains a malformed field
(e.g. an unterminated string) causes the validator's own error-reporting path to read a
`BSONElement`'s field name starting from a NUL-terminator pointer that isn't a real element
— i.e., a validator that's supposed to safely reject malformed input can itself walk off
into adjacent memory while constructing the *error message describing the malformation*.**
This is a real memory-safety defect (a bounded-but-real out-of-bounds read, the same general
flavor as the CVEs the pasted H1 report cited as precedent), and it's already fixed upstream
— not something to submit as fresh, but real enough that I'd recommend treating this repo's
`bson_validate.cpp`/`bsonelement.h` as needing an update if this checkout is ever used past
research purposes.

## Sibling hunt: same pattern (`TrustedInitTag` from a pointer whose "real element" invariant isn't actually established yet) elsewhere

The bug's shape is narrow and specific: it's not "any `TrustedInitTag` use is risky" — most
uses are fine because they run on a `BSONObj` that something *else* already fully validated
(e.g. wire-protocol ingestion). The risk is specifically **code that is itself in the
business of validating/reconstructing not-yet-trusted bytes, and internally uses
`TrustedInitTag` on one of its own bookkeeping/intermediate pointers without having
independently confirmed that pointer is a real element start.**

Enumerated every `TrustedInitTag` call site in the tree (~20) and checked the ones that
plausibly fit that narrower shape:

- **`bsonobj.cpp:588,597` (`BSONObj::getField`)** — operates on a `BSONObj` the caller
  already holds, which by the codebase's pervasive standing invariant has already passed
  `validateBSON()` at ingestion. Safe under that invariant; not a sibling of this bug (the
  precondition is established by something else, correctly).
- **`bsoncolumn.cpp:97` (`BSONElementStorage::Element::element()`)** — this is a *writer*:
  the buffer and `_nameSize` were set by the decompressor itself when it allocated and wrote
  the element's bytes moments earlier, not read from someone else's untrusted blob. Safe;
  different shape (constructing after writing, not trusting after reading).
- **`bsoncolumn_interleaved.cpp:205` (`DecodingState::loadControl`, real decompression hot
  path)** — this one genuinely fits the risky shape: `BSONElement literalElem(buffer, 1,
  TrustedInitTag{})` directly off a raw pointer into the column's encoded byte stream, no
  visible local check. Traced whether something upstream already guarantees this: yes, for
  the validation-triggered decompression path specifically — `_validateSpecial`'s dispatch
  to `_doValidateColumn`/`ColumnValidator::doValidateBSONColumn` runs **unconditionally**,
  for every validation mode, strictly *before* `checkNonConformantElem`'s mode-specific
  extra check that triggers real decompression (`BSONColumn(...).size()`) — and that
  structural pass explicitly validates each literal control byte's element as a real,
  bounded BSON element (`validateAndMeasureElem()`) before decompression ever sees the same
  bytes. So on the validation path, this is safe — the precondition genuinely is established
  first, not assumed.
  **Left open, not fully chased down:** whether *production, non-validation* decompression
  (a normal client read against an already-stored time-series/columnar collection) always
  goes through that same structural pre-check, or — following the very common
  validate-on-write/trust-on-read pattern I flagged for `InterleavedSchema::_discover` in
  the earlier round — skips it, trusting the data was valid when written. If any insertion
  path can get malformed BSONColumn bytes onto disk without full structural validation
  (compromised/buggy replica peer, a bug in a completely different code path, direct
  storage-engine-level tampering), reading it back would hit this exact `TrustedInitTag`
  call with no second check. Did not trace every insertion path in the time available for
  this round — this is the single most valuable next step if this thread gets picked up
  again.

## Assessment

One confirmed, real memory-safety bug — already found and fixed by MongoDB, not fresh, but
worth having on record since it's present in this checkout and gives a second concrete,
narrow pattern (beyond the depth-reset one) to check future BSON-adjacent code against. The
sibling hunt found two clean misses with real reasoning behind each, and one open thread
(read-path decompression's reliance on write-path validation) flagged honestly rather than
either oversold as a live bug or silently dropped.
