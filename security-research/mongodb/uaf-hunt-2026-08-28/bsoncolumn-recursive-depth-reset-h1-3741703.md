# BSONColumn recursive-depth-reset stack exhaustion (H1 #3741703 / #3675648) — status check + sibling hunt

**Status: the exact reported bug is FIXED in this checkout. Two structurally-similar
candidate siblings were traced and both are very likely safe in practice, for two
different, specific reasons documented below — not just assumed.**

User pasted HackerOne report #3741703 (closed Duplicate of #3675648, itself closed
Informative — i.e. real bug, no bounty because MongoDB already knew and was already
patching it before either external report arrived). Asked: is this bug class still present,
and are there siblings.

## The reported bug, and why it's fixed here

The report's claim: `_doValidateColumn()`'s interleaved-start handler
(`bson_validate.cpp`) calls `validateBSON()` on a Column's embedded reference object; that
call allocates a brand-new `ValidateBuffer` whose depth counter starts at 0, so
`BSONDepth::getMaxAllowableDepth()` (200) never accumulates across Column-nesting
boundaries — nest 20,000 Columns and you exhaust the real C++ stack via genuine recursive
descent, before the 200-limit is ever consulted.

Checked the current structure (this repo has been substantially refactored since the report
was filed — the recursive-descent-into-a-fresh-validator shape the report describes is now
inside a `ColumnValidator` template, not a bare call to top-level `validateBSON()` — but the
same fundamental shape). The fix is at `bson_validate.cpp:516-519`, in `_validateSpecial`'s
BinData dispatch, guarding entry into `_doValidateColumn` in the first place:

```cpp
if (subtype == BinDataType::Column && _validationVersion >= V2_Column) {
    uassert(InvalidBSONColumn,
            "BSONColumn cannot contain nested BSONColumn data",
            !_insideColumn);
    /* do not pass down cursor; we want to reset the nesting depth */
    ...
```

`_insideColumn` is a flag threaded through `ValidateBuffer`'s constructor, set `true` on the
instance built to validate an interleaved-mode reference object
(`ColumnValidator::doValidateBSONColumn`, lines ~755-765: `ValidateBuffer<precise,
DefaultValidator>(ptr, end - ptr, ..., /*insideColumn=*/true)`). MongoDB didn't fix this by
propagating a depth counter (the report's suggested fix) — they closed the whole bug class
by **outright prohibiting Column-inside-Column nesting**, full stop. A reference object that
itself contains a `BinData(Column)` field is rejected immediately as invalid, so the
recursive chain the report describes can never go past one level. Confirmed this is the
*default* behavior: `currentValidationVersion = V2_Column` (`bson_validate.h:28`) is the
default argument on every public `validateBSON()` overload, so this guard is active on the
ordinary, unqualified call path — not something a caller has to opt into.

**Conclusion: this exact bug, as described in the report, does not reproduce against this
checkout.**

## Sibling hunt: same general shape elsewhere (BinData-blob-triggers-a-second-recursive-pass)

Went looking for other code that shares the actual bug *mechanism* — a validator/decoder
that safely bounds ordinary BSON object/array nesting via an iterative, iteratively-managed
stack (this file's `_frames`/`_objFrames` vectors, confirmed elsewhere to correctly cap
ordinary nesting and even `CodeWScope` nesting at 200 without real C++ recursion per level —
`CodeWScope` uses `_pushFrame`/`_pushCodeWithScope` into the *same* frame vector, not a fresh
instance, so it was never a sibling of this bug to begin with), but which special-cases some
embedded-blob type by spinning up a **second, independent instance of itself** to interpret
the embedded content, with no way for the outer bound to constrain the inner one.

Two real candidates found, both traced to ground rather than left as "probably fine":

### 1. `ExtendedValidator::checkNonConformantElem`'s BinData(Column) handling — different code path, same file

`bson_validate.cpp:106-113`:

```cpp
case BinDataType::Column: {
    // Check for exceptions when decompressing.
    // Calling size() decompresses the entire column.
    BSONColumn(BSONElement(ptr)).size();
    break;
}
```

This runs for `kExtended`/`kFull` validation mode, on every BinData(Column) field, and is a
**completely separate code path** from the `_insideColumn`-guarded structural check above —
it directly invokes the *real* `BSONColumn` decompressor
(`src/mongo/bson/column/bsoncolumn.cpp`), not the structural validator. If the real
decompressor recursively decompressed nested Column-within-reference-object data the same
way the structural validator used to, this would be an independent, unfixed way to reach
the same stack exhaustion, immune to the `_insideColumn` guard (which lives in a different
class entirely).

Traced `BSONColumn::size()` (`bsoncolumn.cpp:756-758`): `return
std::distance(begin(), end());` — walks the column via its element iterator, which
reconstructs each top-level element's *value* faithfully but does not need to recursively
re-decompress a `BinData(Column)`-typed *field value* found inside a reconstructed
sub-document — that field's bytes are opaque payload as far as counting/reconstructing the
outer column's elements is concerned. **This is a materially different job from what the
structural validator does** (full recursive structural re-validation of the reference object
necessarily walks into every nested BinData field because that's what "validate everything"
means) — decompression only needs byte-accurate reconstruction, not recursive interpretation
of every nested blob's own semantics. Did not find a recursive re-entry into
`BSONColumn::size()`/decompression triggered by nested Column data. Likely safe, traced by
reading the actual iterator logic rather than assumed.

### 2. `InterleavedSchema::_discover()` — a genuine unbounded C++ recursive function, but not independently reachable at dangerous depth

`src/mongo/bson/column/interleaved_schema.cpp:18-42` — builds a flattened schema
("enter sub-object / scalar / exit sub-object" op list) from a Column's reference object, to
drive interleaved decompression:

```cpp
void InterleavedSchema::_discover(const BSONObj& obj, ..., index_t& scalarIdx) {
    _entries.push_back({Op::kEnterSubObj, ...});
    for (auto&& elem : obj) {
        if (isSubObj) {
            _discover(elem.Obj(), ...);   // <-- genuine recursive call, no depth check anywhere
        } else {
            _entries.push_back({Op::kScalar, ...});
        }
    }
    _entries.push_back({Op::kExitSubObj, ...});
}
```

This *is* real, unbounded C++ recursion — one stack frame per level of sub-object nesting in
the reference object, with **no depth check in the function at all**. On its face this looks
like exactly the sibling being hunted for. Two things keep it from being independently
exploitable as things stand, though, both worth stating precisely rather than hand-waving:

- The reference object this walks is a BSONObj that has already passed ordinary BSON
  structural validation (the same iterative, 200-level-capped `_frames` mechanism confirmed
  safe elsewhere in this file) before `InterleavedSchema` is ever built from it on any path
  that goes through `bson_validate.cpp` — so its nesting is bounded to ~200 levels by the
  time `_discover` sees it, not attacker-arbitrary.
- Each `_discover` stack frame is small (a `BSONObj`, a `string_view`, a `BSONType`, a bool,
  and a reference) — 200 levels of a frame this size is on the order of tens of KB, nowhere
  close to exhausting a normal thread's stack (unlike the original bug, where the *heavier*
  `validateBSON()`/`ValidateBuffer` frames were multiplied by 20,000 iterations, not 200).

So: real recursion, genuinely no internal depth guard, but not independently dangerous
*given* its only confirmed call path constrains input depth to 200 first. Flagging as a
defense-in-depth gap worth having MongoDB harden (a future code path that constructs
`InterleavedSchema` from a reference object that *hasn't* gone through the standard 200-cap
validation first — e.g. trusted-on-read storage-engine decompression of already-stored data
— would reinherit the exact bug shape) rather than a demonstrated live vulnerability today.

## Assessment

The specific, reported bug is fixed, and fixed robustly (outright prohibition, not a
depth-counter that could itself be gotten wrong again). The sibling hunt found one clean
miss (decompression doesn't share the structural validator's "recurse into everything"
behavior) and one real defense-in-depth gap (`InterleavedSchema::_discover` has no depth
check of its own) that isn't currently reachable at a dangerous depth given its one known
caller's precondition, but would become live again if that precondition ever stopped
holding. Recorded so this exact ground doesn't get re-walked, and so the `_discover` gap is
on record if a future refactor changes how `InterleavedSchema` gets constructed.
