# mongod — sibling-bug hunt off CVE-2026-4148, candidate UAF in mozjs BSON↔JS bridge

**Status: strong, carefully-reasoned STATIC finding. NOT dynamically confirmed — no live
crash reproduced. Full honesty on confidence level below; this is a lead worth a triage
report, not a proven exploit.**

## How this was found

Per direction: went back to the real `mongodb/mongo` source (this repo, `upstream` remote),
started from the exact CVE-2026-4148 fix and applied the same "recent-fix sibling hunt"
technique that found the BSONColumn RLE bomb earlier in this program — but this time swept
*all* recent (2026) UAF fix commits, not just the one CVE, and went one level deeper: not
just "did they fix the sibling stage," but "is the *general mechanism* the fix leaned on
itself reliable everywhere else it's used."

### Step 1 — confirmed the CVE fix and exhausted its direct siblings (negative)

Found the exact fix via `git log`/GitHub commit search:
`11a15a850cc52e25b04e34fa9a615b6cf6b4ba2a` ("SERVER-120592 fix ExprCtx use-after-free for
$lookup/$graphLookup clone"). Root cause: every `Expression` node holds an *unowned* pointer
to its query's `ExpressionContext`; `$lookup`/`$graphLookup`'s clone-constructors used to
shallow-copy their `Expression`-bearing members (`_letVariables`, `startWith`) instead of
rebuilding them against the new `ExpressionContext`, so a clone (created when a sharded
aggregation splits a pipeline across shards) could end up evaluating expressions against an
already-destroyed `ExpressionContext`.

Confirmed this checkout (current HEAD content, `fd0d5b3c4` per shallow-clone log) already
has the fix, **and** that the API was hardened since: `Expression::clone()` is now a
mandatory pure-virtual taking `ExpressionContext&` (no more argument-less `clone()`), which
forces every subclass to explicitly re-home children with the new context. Enumerated
*every* `DocumentSource` that hand-rolls its own `clone()` instead of using the safe default
(serialize-then-reparse): `$lookup`, `$graphLookup` (both fixed), `$unionWith`,
`$_internalChangeStreamOplogMatch`, `$listSessions`, `$sequentialCache`,
`$_internalDocumentResultsAndMetadata`, `$collStats`. Traced each one's actual member-copy
logic by hand (not just presence of a `clone()` override) — all seven remaining stages are
safe: either they delegate to the base class's serialize+reparse pattern
(`$unionWith`'s sub-pipeline, `$listSessions`/`$_internalChangeStreamOplogMatch`'s
MatchExpression via `DocumentSourceMatch`'s own copy-with-newExpCtx constructor, which
*also* serializes+reparses), or their extra state is plain data / shared ownership with no
live ExpCtx-bound pointer (`$sequentialCache`'s `shared_ptr` cache,
`$_internalDocumentResultsAndMetadata`'s IDL-generated `ShardedPlanSpec`, which is
BSON-only data by the `.idl` definition). **No unfixed sibling in the aggregation
clone-machinery itself.**

### Step 2 — broadened to other recent 2026 UAF fixes, found a more promising shape

Searched `mongodb/mongo` commit history for `"use-after-free"` across all of 2026 (10
hits). One stood out as a *different*, more generally-applicable bug shape:
`2fc5c20f53a7cffd4a7f4d16564013271a498c44`
("SERVER-128790 Call makeOwned() in bsonObjToArray to avoid use-after-free", merged
2026-06-16), a one-line fix in `src/mongo/scripting/mozjs/common/types/bson.cpp`:

```cpp
auto obj = ValueWriter(cx, args.get(0)).toBSON();
obj.makeOwned();   // <- the fix
ValueReader(cx, args.rval()).fromBSONArray(obj, nullptr, false);
```

Read the full file to understand *why* this one call site needed it and whether the reason
generalizes. `BSONInfo`'s other free functions in the same file
(`bsonWoCompare`/`bsonUnorderedFieldsCompare`/`bsonBinaryEqual`/`bsonToBase64`) call the same
`getBSONFromArg()` helper *without* `makeOwned()` and are fine, because they only read the
bytes synchronously within the same call (`woCompare`/`binaryEqual`/`objdata()`) — nothing
persists a reference. `bsonGetImmutable`, by contrast, *does* call `makeOwned()`, with an
explicit comment: *"A 'BSONHolder'-managed object can store unowned BSON that references a
sub-document of some parent object... This new object does not copy that reference, so it
cannot safely store unowned BSON."* — i.e. the fix pattern is: **any time a BSONObj is going
to be wrapped into a new JS-visible object that outlives the current call, it must be
`makeOwned()`'d first; a purely-synchronous read doesn't need it.**

### Step 3 — traced `ValueWriter::toBSON()`/`ObjectWrapper::toBSON()` itself for the same gap

`ValueWriter::toBSON()` (`valuewriter.cpp:189-195`) is a one-line forward to
`ObjectWrapper(_context, obj).toBSON()`. Read `ObjectWrapper::toBSON()`
(`objectwrapper.cpp:578-...`) in full. It has two paths:

```cpp
BSONObj ObjectWrapper::toBSON() {
    auto* runtime = getCommonRuntime(_context);
    if (getProto<BSONInfo>(runtime).instanceOf(_object) ||
        getProto<DBRefInfo>(runtime).instanceOf(_object)) {
        BSONObj* originalBSON = nullptr;
        bool altered;
        std::tie(originalBSON, altered) = BSONInfo::originalBSON(_context, _object);
        if (originalBSON && !altered)
            return *originalBSON;          // <-- fast path
    }
    // ... slow path: builds a fresh BSONObjBuilder and returns b.obj() (owned)
}
```

The **fast path** returns `*originalBSON` — a plain `BSONObj` copy (cheap handle copy, not a
byte copy) of whatever `holder->_obj` is, **without calling `makeOwned()`**. Whether that's
safe depends entirely on `BSONHolder::_isOwned`
(`bson.cpp:88`: `obj.isOwned() || (parent && parent->isOwned())`) at the moment this
JS-wrapper object was originally created. `originalBSON()` does call
`getValidHolder()`/`uassertValid()` first, which throws if the holder is unowned **and**
the JS-scope's generation counter has advanced since the holder was created — but that
generation mechanism (`MozJSImplScope::advanceGeneration()`, bumped from `reset()`, called
when a pooled JS scope is checked out/returned across *different operations*,
`src/mongo/scripting/engine.cpp:463/475/530`) protects against a completely different hazard
(a stale document-view surviving into a *different, later operation* sharing a pooled JS
scope). It does **nothing** to protect a value that is genuinely backed by a
short-lived, unowned C++ buffer (e.g. a stack-local `BSONObjBuilder`, or a caller-provided
view) whose owner scope ends *within the same operation*, before whatever now holds this
`toBSON()` result is done with it — that hazard has no generation check guarding it at all,
by construction, since the generation counter never moves during that window.

This is structurally the same shape as the just-fixed `bsonObjToArray` bug: a BSONObj that
can be unowned flows out of the shared `toBSON()`/`ObjectWrapper::toBSON()` machinery
without a forced `makeOwned()`, and it is the *caller's* job to know to add one — exactly
the thing a human fixing `bsonObjToArray` one call site at a time is liable to miss
elsewhere, since `ValueWriter(cx, val).toBSON()` is called at ~15+ sites across
`common/`, `shell/`, and `wasm/` (`mongo.cpp`, `resumetoken.cpp`, `nativefunction.cpp`,
`object.cpp`, `dbref.cpp`, and more), and only one of them (`bsonObjToArray`) has been
audited and patched for this specific gap so far.

### Step 4 — where the "unowned, parent-less" precondition is concretely real

The clearest confirmed case of a BSONHolder actually being created unowned with **no owned
parent** (so `_isOwned` is false, so the fast path's missing `makeOwned()` actually matters)
is `src/mongo/scripting/mozjs/wasm/engine/engine.cpp`'s `invokeFunction`/predicate paths:

```cpp
// Advance generation so any unowned BSONHolder retained from a prior invokeFunction call
// is detected as stale if accessed during this predicate.
++_generation;
...
ValueReader(_cx, &smrecv).fromBSON(document, nullptr, false);   // parent = nullptr
```

This is the WASM/extension-stage host bridge (`featureFlagExtensionsAPI`, `default: true`
in `query_feature_flags.idl` — the flag itself is on, but reaching this code still requires
an extension actually be loaded, which today is an operator/admin action, not something an
ordinary "read role" user can trigger unassisted — this materially lowers real-world
reachability versus the original CVE, which needed only an ordinary aggregation). The
comment shows the WASM engine's own authors were specifically worried about exactly this
unowned-holder-outliving-its-call hazard and built a generation counter to catch cross-call
reuse — but as traced in Step 3, that counter does not cover the narrower, same-call
"the C++-side backing buffer went away before the JS-side value did" hazard that
`bsonObjToArray`'s fix actually targeted.

## What is NOT yet confirmed

- **No live crash.** This entire chain is reasoned from static code reading, cross-checked
  against the one sibling fix that exists as ground truth for the bug class. I have not
  built mongod (no `bazel`/`bazelisk` toolchain present in this environment, and a from-source
  build of this size is realistically hours, not something this session can complete) and
  have not exercised the actual `invokeFunction`/extension-loading path end to end.
- **Concrete trigger not yet nailed down.** I have not identified the exact minimal script/
  extension/aggregation that forces (a) a BSONHolder to be created unowned with no owned
  parent, (b) its `toBSON()` fast-path taken, (c) the backing buffer freed, and (d) the
  resulting stale `BSONObj` actually dereferenced (not just copied) before anything else
  notices. Steps (a)-(b) are demonstrated as *reachable in principle*; (c)-(d) needs either
  a real build or a much closer reading of exactly which C++ call sites hand a
  stack-temporary-backed, parent-less BSONObj into `fromBSON`.
- **Reachability for the one confirmed "unowned, parent-less" instance (WASM extension
  engine) requires an extension already loaded** — an operator action. Whether the *same*
  gap in `ObjectWrapper::toBSON()`'s fast path is reachable from the far more ubiquitous,
  always-on `$where`/`$function`/`$accumulator` JS execution path (which would match
  CVE-2026-4148's "ordinary authenticated read-role user" severity) is the single most
  important open question, and the next concrete step: find where (if anywhere) a
  parent-less, unowned BSONHolder gets constructed on that path specifically.

## Assessment

This is the most substantive lead this session has produced on the "find a fresh UAF" front
— a real, demonstrated gap in a shared, widely-used function that the codebase's own recent
history shows engineers repeatedly getting wrong at individual call sites (bsonObjToArray,
bsonGetImmutable) rather than fixing at the source. But it stops at "very plausible,
well-evidenced, unconfirmed" rather than "proven" — reported as such rather than dressed up,
consistent with how every other finding this session has been calibrated. Recommended next
step if pursuing further: either commit to an actual from-source build (hours, likely
spanning multiple sessions) to get a real binary for dynamic confirmation, or narrow Step 4
further by finding the specific non-WASM call site (if one exists) that constructs an
unowned, parent-less BSONHolder from the classic `$where`/`$function` path.
