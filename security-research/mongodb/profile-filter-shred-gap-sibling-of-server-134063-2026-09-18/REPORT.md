# `operationProfiling.filter` / `db.setProfilingLevel(level, {filter: ...})` shares the SERVER-134063 / CVE-2026-89099 shared-constant double-free, and the shipped fix does not cover it

**Status: static-analysis-verified sibling of a confirmed, patched CVE. Not independently exercised against a running mongod (no build was performed — this report is based on full source tracing of the exact call chain, cross-checked function-by-function). Recommend the assigned engineer reproduce with a debug/ASAN build before triage, using the "Suggested repro" section below.**

## Summary

MongoDB's own fix for **SERVER-134063 / CVE-2026-89099** ("Shred collection validator constants during parsing") closes a double-free / use-after-free that occurs when a single, once-parsed aggregation expression tree containing an `ExpressionConstant` is evaluated concurrently by many threads without cloning. The fix is a single-condition gate: `ExpressionConstant::parse()` only materializes ("shreds") the constant's `Value` when `expCtx->getIsParsingCollectionValidator()` is true.

There is a second site in the same codebase, structurally identical to the collection-validator case the fix targets, that the gate does not cover: **the operation-profiling filter** (`db.setProfilingLevel(level, {filter: <expr>})`, and the equivalent `operationProfiling.filter` startup/config parameter). It is parsed once, stored as a `shared_ptr<const ProfileFilter>`, and its `matches()` method — which evaluates the same shared expression tree — is called from every operation on every connection thread, unmodified, for the lifetime of the filter. A filter that embeds a large object-valued `$literal` constant via `$expr` hits the identical `DocumentStorage::alloc()` race under concurrent evaluation, with the same consequence: double free / heap corruption from a write of attacker-influenced (well, filter-author-influenced) bytes.

This is not a re-discovery of SERVER-134063 itself — it's a different trigger surface the shipped fix doesn't reach, verified by reading the actual 8.3.11 source tree (the fix's target branch) function-by-function.

## Asset / Product

- MongoDB Server, `mongodb/mongo` — checked out at tag `r8.3.11` (the branch the SERVER-134063 fix shipped to)
- `src/mongo/db/profile_filter_impl.cpp` — `ProfileFilterImpl`
- `src/mongo/db/pipeline/expression.cpp` — `ExpressionConstant::parse()` (the fix's only gate)
- `src/mongo/db/exec/matcher/matcher.cpp` — `exec::matcher::evaluateExpression()` (the shared, concurrent evaluation path)
- `src/mongo/db/curop.cpp` — `CurOp::_shouldProfileAtLevel1AndLogSlowQuery()` (the concurrent call site, hit on essentially every operation)
- `src/mongo/db/commands/profile_common.cpp` — authorization check for `setProfilingLevel`/`profile` command
- `src/mongo/db/commands/set_profiling_filter_globally_cmd.cpp` — authorization check for the cluster-wide variant

## Severity

Suggested severity: **High**, same underlying memory-safety class as the parent CVE (double free / heap corruption from a race, no fund/auth bypass, but a documented path to process crash and — per MongoDB's own writeup of SERVER-134063 — potential memory corruption beyond a clean crash). Scored one notch below the parent bug's own severity because the trigger requires a real, if modest, privilege (see below) rather than "any authenticated user with ordinary write access."

Suggested CVSS v3.1 (by analogy to the parent bug's shape — race condition leading to memory corruption, privileged-but-not-admin trigger): `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:H` (~6.3, High band) — `AC:H` because it requires winning a race under concurrent load (same as the original), `PR:H` reflecting the `enableProfiler` privilege requirement detailed below.

## Minimum privilege required to trigger this bug

This is the part that differs materially from the parent CVE, so it's broken out explicitly.

**Runtime vector — `db.setProfilingLevel(level, {filter: <expr>})` (or the raw `profile` command):**

Traced the authorization check directly (`src/mongo/db/commands/profile_common.cpp:75-109`):

```cpp
if (!authzSession->isAuthorizedForActionsOnResource(ResourcePattern::forDatabaseName(dbName),
                                                    ActionType::enableProfiler)) {
    return Status(ErrorCodes::Unauthorized, "unauthorized");
}

// 'slowms' and 'sampleRate' write to process-global parameters that affect all databases.
if (request.getSlowms() || request.getSampleRate()) {
    if (!authzSession->isAuthorizedForActionsOnResource(
            ResourcePattern::forAnyNormalResource(dbName.tenantId()),
            ActionType::enableProfiler)) {
        return Status(ErrorCodes::Unauthorized, "unauthorized");
    }
}
```

Setting **only** `filter` (no `slowms`/`sampleRate` in the same command) requires just the first check: `ActionType::enableProfiler` scoped to `ResourcePattern::forDatabaseName(dbName)` — a **single-database** resource, not cluster-wide.

`enableProfiler` is granted by the built-in **`dbAdmin`** role (`src/mongo/db/auth/builtin_roles.yml`, `dbAdminRoleActions` list, confirmed present alongside `collMod`, `createCollection`, etc. — i.e., the exact same tier of role that lets a user create the collection validators SERVER-134063 itself was reachable through). `dbOwner` (readWrite + dbAdmin + userAdmin on one database) also grants it, as does any custom role a cluster admin builds that includes `enableProfiler`.

**Minimum privilege: `dbAdmin` (or `dbOwner`) on a single database — not `clusterAdmin`, not `root`, not a cluster-wide privilege.** This is a common role handed to application-level database owners in multi-tenant or per-service database setups; it is *not* the DBA/superuser tier. It is one step above the parent CVE's "ordinary write access" bar (which only needed `readWrite`/`createCollection`), but still well short of cluster-admin.

**Startup/config vector — `operationProfiling.filter`:** setting this via `--setParameter` or the config file at mongod startup requires control over server startup configuration — an infrastructure/ops-level trust boundary, not a database-user privilege at all. Mentioned for completeness; the `dbAdmin`-via-`setProfilingLevel` vector above is the meaningful "authenticated low(er)-privileged user" trigger.

**Cluster-wide variant — `setProfilingFilterGlobally`:** `src/mongo/db/commands/set_profiling_filter_globally_cmd.cpp:66` requires `enableProfiler` on `ResourcePattern::forAnyNormalResource(...)` — cluster-wide, a higher bar than the per-database vector above. Not the minimum path; noted for completeness only.

## Technical Details

### 1. The fix's only gate

```cpp
// src/mongo/db/pipeline/expression.cpp:904-915
intrusive_ptr<Expression> ExpressionConstant::parse(ExpressionContext* const expCtx,
                                                    BSONElement exprElement,
                                                    const VariablesParseState& vps) {
    assertNoRestrictedBinDataSubtype(exprElement);
    Value exprValue = Value(exprElement);
    // Shred values when parsing collection-validator constants to avoid lazily
    // populating the BSON cache on write paths.
    if (MONGO_unlikely(expCtx->getIsParsingCollectionValidator())) {
        exprValue = exprValue.shred();
    }
    return new ExpressionConstant(expCtx, std::move(exprValue));
}
```

This is the *only* place in the tree that defensively materializes a constant for this bug class — confirmed by grepping every `.shred()` call site in `src/mongo/db/`:

```
document.h:292          Document::shred() itself (the primitive the fix reuses)
document.cpp:454,459     MutableDocument rebuild internals (unrelated call sites)
value.cpp:1309,1313      Value::shred() itself (the primitive)
internal_shred_documents_stage.cpp:58   the (unrelated) $_internalShredDocuments agg stage
expression.cpp:912        <-- the fix, and the ONLY constant-materialization gate in the tree
```

The gate is a single boolean: `getIsParsingCollectionValidator()`. (Note: this backport uses the plain, pre-existing `Value::shred()` rather than the newer `Value::shredForConcurrentReads()` that MongoDB's Jira description for the fix says mainline eventually grew, with the extra `DocumentStorage::_frozenForSharing` + `tassert` safety net. Consistent with the ticket's own backport-justification text — "we can go even narrower... trading a bit of defense-in-depth for an even smaller change" — 8.3.11 shipped the narrower version. Either function closes the *validator* case; neither closes the profile-filter case below, because the gate that calls them is unchanged.)

### 2. The uncovered sibling: `ProfileFilterImpl`

```cpp
// src/mongo/db/profile_filter_impl.cpp:61-86
ProfileFilterImpl::ProfileFilterImpl(BSONObj expr,
                                     boost::intrusive_ptr<ExpressionContext> parserExpCtx)
    : _matcher(expr.getOwned(), parserExpCtx) {
    ...
    parserExpCtx->setIsProfileFilter(true);   // <-- NOT setIsParsingCollectionValidator(true)

    // The operation context is necessary for parsing, but should not be used for the rest of the
    // lifetime of the filter, since the filter exists for longer than a single operation.
    parserExpCtx->setOperationContext(nullptr);
}
```

`ProfileFilterImpl`'s `ExpressionContext` sets a *different* flag, `isProfileFilter`, which `ExpressionConstant::parse()` never checks. Any `ExpressionConstant` embedded in the filter (e.g. via `$literal`) is therefore parsed with its lazily-materializing, BSON-backed `Value` intact — exactly the pre-fix state SERVER-134063 describes for collection validators.

### 3. `$expr` (and therefore embedded constants) is allowed in profile filters by default

```cpp
// src/mongo/db/matcher/matcher.h:65-69
Matcher(const BSONObj& pattern,
        const boost::intrusive_ptr<ExpressionContext>& expCtx,
        const ExtensionsCallback& extensionsCallback = ExtensionsCallbackNoop(),
        MatchExpressionParser::AllowedFeatureSet allowedFeatures =
            MatchExpressionParser::kDefaultSpecialFeatures);
```

`ProfileFilterImpl` constructs its `_matcher` with only two arguments (`_matcher(expr.getOwned(), parserExpCtx)`), so `allowedFeatures` takes the default:

```cpp
// src/mongo/db/query/compiler/parsers/matcher/expression_parser.h:118-122
enum AllowedFeatures {
    kText = 1, kGeoNear = 1 << 1, kJavascript = 1 << 2, kExpr = 1 << 3, ...
};
static constexpr AllowedFeatureSet kBanAllSpecialFeatures = 0;
static constexpr AllowedFeatureSet kDefaultSpecialFeatures =
    AllowedFeatures::kExpr | AllowedFeatures::kJSONSchema | AllowedFeatures::kEncryptKeywords;
```

`kExpr` is in the default set. (Contrast with index partial filters, which the parent fix's own "survey of safe sites" correctly notes ban `$expr` entirely via `kBanAllSpecialFeatures` — that site really is safe; profile filters are not banned the same way.) So `db.setProfilingLevel(1, {filter: {$expr: {$eq: ["$ns", {$literal: <big object>}]}}})` parses without restriction.

### 4. It is shared, and evaluated concurrently, unmodified, on (effectively) every operation

```cpp
// src/mongo/db/profile_settings.h:47
std::shared_ptr<const ProfileFilter> filter;  // nullable
```

One shared instance, handed out (by value-copy of the enclosing `ProfileSettings` struct, which still shares the underlying pointer) to every database's profiling-settings lookup.

```cpp
// src/mongo/db/curop.cpp:790
const bool passesFilter = filter->matches(opCtx(), _debug, *this);
```

Called from `CurOp::_shouldProfileAtLevel1AndLogSlowQuery()`, which runs at the end of essentially every operation on every connection thread (`service_entry_point_shard_role.cpp` calls into `completeAndLogOperation`, which reaches this) — not a rare administrative path, the ordinary slow-op/profiling decision hit continuously under normal server load.

For an `$expr` node, this lands in:

```cpp
// src/mongo/db/exec/matcher/matcher.cpp:47-54
Value evaluateExpression(const ExprMatchExpression* expr, const MatchableDocument* doc) {
    Document document(doc->toBSON());

    // 'Variables' is not thread safe, and ExprMatchExpression may be used in a validator which
    // processes documents from multiple threads simultaneously. Hence we make a copy of the
    // 'Variables' object per-caller.
    Variables variables = expr->getExpressionContext()->variables;
    return expr->getExpression()->evaluate(document, &variables);
}
```

This comment is the tell: the code is explicitly aware that a single parsed expression tree gets evaluated by many threads concurrently for the validator case, and mitigates the `Variables` half of that hazard with a per-call copy — but `expr->getExpression()` itself (the parsed tree, holding the unshredded `ExpressionConstant` for a profile filter) is the same shared object on every call. This is the identical shape SERVER-134063 fixed for validators, reached here through a path the fix's gate doesn't recognize.

### 5. The race itself

Unchanged from the parent bug's own analysis (not re-derived here, since MongoDB's own writeup already covers it precisely): `DocumentStorage::findField()` lazily populates its field cache via `const_cast` even when called through a `const` accessor; `DocumentStorage::alloc()`'s growth path frees the previous cache buffer. Two threads concurrently evaluating the same shared, large-enough object-valued constant (`ExpressionConstant::evaluate()` returns a shallow, refcount-only copy of the shared `Value`, so both threads read/write the same `DocumentStorage`) race inside `alloc()` — double free, and a subsequent use-after-free write of filter-author-influenced bytes into freed heap memory.

## Suggested repro (not yet executed — flagged honestly)

1. Build mongod with ASAN or a debug allocator that reliably surfaces double-free (release builds may only lose the race occasionally, per the parent CVE's own test-coverage notes about needing 25 rounds / a sanitizer variant to reliably trip).
2. As a user holding `dbAdmin` on some database, run:
   ```js
   db.setProfilingLevel(1, {
     filter: {
       $expr: {
         $eq: [
           "$ns",
           { $literal: <BSONObj with several thousand fields, mirroring the parent CVE's ~4096/20000-field PoC scale> }
         ]
       }
     }
   })
   ```
3. Drive many concurrent operations against that database from multiple client connections (any ordinary command that goes through `CurOp::_shouldProfileAtLevel1AndLogSlowQuery`, e.g. concurrent `find`/`insert` from N threads), so the shared filter's constant is evaluated concurrently across threads, forcing repeated `DocumentStorage::alloc()` cache growth on the shared `Value`.
4. Expect: double-free detection under ASAN, or (on a release build, per the parent bug's own "occasional" loss characterization) intermittent crash/heap corruption under sustained concurrent load.

## Suggested Fix

Extend the same gate `ExpressionConstant::parse()` checks to cover profile filters — either:

- `if (expCtx->getIsParsingCollectionValidator() || expCtx->getIsProfileFilter()) { exprValue = exprValue.shred(); }`, or
- (matching the direction mainline's `shredForConcurrentReads()` was already heading, per the parent Jira ticket's later revisions) rename the concept to something like `isParsedOnceEvaluatedConcurrently` and set it from both `parseValidator()` and `ProfileFilterImpl`'s constructor, so future third call sites with the same shape don't require rediscovering this gap one at a time.

Also worth double-checking `Variables::setQueryConstantValue()` (the parent fix's second materialization site, for `$$USER_ROLES`/`$$JS_SCOPE`) for whether it's reachable from a profile-filter `ExpressionContext` in the same unshredded way — not chased down in this pass.

## Notes on scope of this audit

This finding came from asking, for the parent fix's own stated safety assumption ("the collection validator remains the only site where an expression tree is parsed once and evaluated concurrently" — survey covering index partial filters, views, change streams, `CopyableMatchExpression`), whether that survey was actually complete. `ExpressionContext` turns out to carry a second, adjacent-but-distinct "long-lived, multi-threaded, once-parsed" flag (`isProfileFilter`) sitting right next to `isParsingCollectionValidator` in the same struct (`expression_context.h:1176-1179`) — used elsewhere in the file for an unrelated (`VersionContext`/feature-flag) concern, and apparently not cross-referenced against the constant-shredding fix. Did not exhaustively check every other `ExpressionContext` flag/call site for a third instance of this pattern in the time available for this round.
