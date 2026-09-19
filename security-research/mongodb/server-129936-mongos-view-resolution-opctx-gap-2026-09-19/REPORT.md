# Title

SERVER-129936 / CVE-2026-18704's fix does not cover mongos's view-query resolution path — `PipelineResolver::buildResolvedMongosViewRequest` re-lite-parses the client's pipeline with `opCtx` unset in two separate branches, reopening the exact `$_internalSearchIdLookup.viewPipeline` smuggling bug for any aggregate run against a view through mongos

## Summary

SERVER-129936/CVE-2026-18704 (fixed and present on `r8.3.11`, confirmed below) closed the `$_internalSearchIdLookup.viewPipeline` internal-field-smuggling bug at exactly one call site: `ClusterPipelineCommandBase::Invocation`'s constructor in `src/mongo/s/commands/query_cmd/cluster_pipeline_cmd.h`, which now threads a real `opCtx` into the `LiteParserOptions` used for the top-level authorization-time lite-parse of an incoming `aggregate` command on mongos.

That is not the only place mongos lite-parses a client's raw pipeline BSON for a namespace that turns out to be a view. `src/mongo/db/views/pipeline_resolver.cpp`'s `PipelineResolver::buildResolvedMongosViewRequest` — invoked specifically when the target namespace resolves to a view, to build the pipeline mongos sends on to the shards — performs its **own, independent** re-parse of the client's request in two separate branches, and neither one threads `opCtx`, even though `opCtx` is the function's own first parameter and is passed through to a sibling call one line away. Since `LiteParsedInternalSearchIdLookUp::parse()`'s rejection of `viewPipeline` is gated on `opts.opCtx` being non-null, both of these re-parses accept the field from an external client with no check at all — exactly the behavior SERVER-129936 exists to prevent, just reached via mongos's view-resolution path instead of its command-authorization path.

## The fixed call site (for reference — confirmed correct)

`src/mongo/s/commands/query_cmd/cluster_pipeline_cmd.h`, `Invocation` constructor:
```cpp
_liteParsedPipeline(_aggregationRequest,
                    false /* isRunningAgainstView_ForHybridSearch */,
                    {.ifrContext = _ifrContext,
                     .opCtx = opCtx,                       // <-- added by SERVER-129936
                     .extensionMetrics = &_extensionMetrics}),
```

## The two unfixed call sites

`src/mongo/db/views/pipeline_resolver.cpp`, `PipelineResolver::buildResolvedMongosViewRequest` (lines 218-263), which takes `opCtx` as its first parameter:

**Branch 1 — mongot/timeseries pipelines (line 233-250):**
```cpp
PipelineResolver::MongosViewRequestResult PipelineResolver::buildResolvedMongosViewRequest(
    OperationContext* opCtx,                              // <-- available here
    const AggregateCommandRequest& request,               // <-- the client's own request
    const ResolvedView& resolvedView,
    ...) {
    ...
    if (search_helper_bson_obj::isMongotPipeline(ifrContext, request.getPipeline()) ||
        resolvedView.timeseries()) {
        ...
        if (!resolvedView.timeseries()) {
            LiteParserOptions options{.ifrContext = ifrContext};      // <-- opCtx NOT set
            auto lpp = LiteParsedPipeline(request, true, options);    // <-- fresh re-parse of client BSON
            lpp.makeOwned();
            LiteParsedDesugarer::desugar(&lpp);
            auto resolvedNamespaces = helpers.resolveInvolvedNamespaces(lpp.getInvolvedNamespaces());
            validateStagesOnView(&lpp, resolvedView, requestedNss, resolvedNamespaces, options);
        }
        ...
```

`$_internalSearchIdLookup` is a mongot-family stage (used by `$search`/`$vectorSearch` on views), so a pipeline containing it is classified as `isMongotPipeline` — meaning **this is the branch such a pipeline actually takes**, not the other one.

**Branch 2 — regular views (line 254, delegating to `buildResolvedPipelineForRegularView` at line 96-117):**
```cpp
    } else {
        std::tie(resolvedPipeline, userLPP) = buildResolvedPipelineForRegularView(
            opCtx, request, resolvedView, requestedNss, verbosity, ifrContext, helpers);
                // opCtx is passed to the callee...
    }
```
```cpp
buildResolvedPipelineForRegularView(OperationContext* opCtx,        // <-- received here
                                    const AggregateCommandRequest& request,
                                    ...) {
    auto lpp = LiteParsedPipeline(request, true, LiteParserOptions{.ifrContext = ifrContext});
                // ...but never reaches the LiteParserOptions two lines later.
    lpp.makeOwned();
    LiteParsedDesugarer::desugar(&lpp);
    ...
    PipelineResolver::applyViewToLiteParsed(&lpp, resolvedView, requestedNss, resolvedNamespaces,
                                            LiteParserOptions{.ifrContext = ifrContext});   // <-- same gap, second time
```

In both branches, `LiteParsedPipeline(request, ...)` performs a **fresh, from-scratch lite-parse of the raw BSON in the client's own submitted `request.getPipeline()`** — this is not reusing an already-validated `LiteParsedDocumentSource` object from an earlier parse. Each stage, including any `$_internalSearchIdLookup`, gets `LiteParsedInternalSearchIdLookUp::parse()` invoked on it again, with a `LiteParserOptions` whose `.opCtx` is null. Since the guard added by SERVER-129936 is `if (idlSpec.getViewPipeline() && opts.opCtx)`, a null `opts.opCtx` means the guard body — the actual `assertAllowedInternalIfRequired` rejection — never runs, and `viewPipeline` is accepted from the external client exactly as it would have been before the fix.

## Why this is exploitable, not just an accepted-but-inert field

`LiteParsedInternalSearchIdLookUp` has no `requiredPrivileges()` override — it inherits the default from `LiteParsedDocumentSourceDefault`, which does not recurse into `viewPipeline`. The fix's own added comment states this plainly:

```cpp
// 'viewPipeline' is an internal field injected by the router. Reject it from external
// clients, since it runs an arbitrary sub-pipeline without an authorization re-check.
```

So a `viewPipeline` that survives Guard 1 (the `opts.opCtx` check) is never separately privilege-checked, and — per `buildResolvedPipelineForRegularView`'s own docstring, its purpose is to "ensure view info is properly bound and **included in the BSON sent from mongos to the shards**" — its contents get serialized into the pipeline mongos dispatches for actual execution. `SERVER-129936`'s own regression test proves the field is fully functional when accepted: it uses `viewPipeline: [{$merge: {into: {db: "targetdb", coll: "pwned"}}}]}` as the proof-of-concept payload for exactly this reason.

## Attack scenario

An authenticated user holding only `find` on a view (or on the underlying collection a view is defined over) issues, through `mongos`, against that view:

```js
db.someView.aggregate([
  { $_internalSearchIdLookup: {
      viewPipeline: [ { $merge: { into: { db: "otherdb", coll: "pwned" } } } ]
  }}
])
```

Because the namespace resolves to a view, this request is routed through `PipelineResolver::buildResolvedMongosViewRequest`, which re-lite-parses it with an opCtx-less `LiteParserOptions` in whichever of the two branches applies (the mongot-pipeline branch, since `$_internalSearchIdLookup` is classified as such) — accepting `viewPipeline` unchecked and forwarding the resulting resolved pipeline to the shards for execution, giving a read-only user a write into a collection they were never authorized to touch — the same impact CVE-2026-18704 is rated for.

## Weakness

CWE-863 (Incorrect Authorization) — identical classification to the original ticket; same root defect shape (an internal-only pipeline field's guard silently disabled by a missing `opCtx`), reached through a call site the original fix did not cover.

## Component / Version

- Repository: `mongodb/mongo`
- Confirmed on `r8.3.11` (where SERVER-129936's own fix, commit `1d4ba92fb9dcc6662ce3f281cd0421fa424d1ad0`, is present and correct at `cluster_pipeline_cmd.h`)
- Unfixed call sites: `src/mongo/db/views/pipeline_resolver.cpp`
  - `PipelineResolver::buildResolvedMongosViewRequest`, mongot/timeseries branch, line 243 (`LiteParserOptions options{.ifrContext = ifrContext};`)
  - `buildResolvedPipelineForRegularView`, lines 105 and 117 (both `LiteParserOptions{.ifrContext = ifrContext}`), called from the `else` branch of the same function at line 254
  - All three sites have `opCtx` available in the enclosing function's own parameter list (it is threaded to `buildResolvedPipelineForRegularView` as an explicit argument one line above the first gap) but never add `.opCtx = opCtx` to the `LiteParserOptions` they construct

## Suggested fix

Add `.opCtx = opCtx` to all three `LiteParserOptions` constructions in `pipeline_resolver.cpp` listed above, mirroring exactly what SERVER-129936 already did for `cluster_pipeline_cmd.h`. Given this is the second call site found with this exact "opCtx available in scope but not threaded into `LiteParserOptions`" defect (the first being the `$graphLookup`/`$_internalFromPipeline` bug in `view_catalog_helpers.cpp`/`authorization_checks.cpp` on master, reported separately), it's likely worth an audit of every `LiteParserOptions{...}` construction in the codebase rather than patching call sites one at a time as each is discovered — I counted at least 8 other sites on `r8.3.11` alone that omit `.opCtx` (`cluster_aggregate.cpp` x3, `document_source_rank_fusion.cpp`, `document_source_score_fusion.cpp`, `pipeline_factory.cpp` x2, `run_aggregate.cpp` x2); I did not have time to individually assess reachability for all of them the way I did for this one, so some may be benign (opCtx genuinely unavailable, or the resulting parse never reaches an internal-only-field check) and are not claimed as vulnerable here — only the three cited above were traced end-to-end.

## Notes on scope

Found while verifying SERVER-129936/CVE-2026-18704's fix on `r8.3.11` and, per the pattern established by the recent `$graphLookup`/`$_internalFromPipeline` case, checking whether the same "opCtx-gated internal-field guard, opCtx left null at some other construction site" defect recurs elsewhere. It does, in a call path (mongos view-query resolution) structurally analogous to but distinct from the one this ticket's own fix addressed.
