> **Recovery note (2026-08-28):** reconstructed verbatim after the working container was recycled
> before a successful push. Content unchanged from the original.

# MongoDB 8.3.8 — closing out the `db.createView()` null-`opCtx`/stub-process-interface bypass class

**Date:** 2026-08-24
**Status:** Static-only (this pass). No live `mongod` was available in this session — see note at
the end. No new exploitable bug found; this narrows the confirmed-Critical
`$_internalSearchIdLookup.viewPipeline` finding (`../README.md`) from "one instance of a pattern"
to "the only instance of this pattern in the 8.3.8 tree", with the actual enforcement code read
end-to-end to show why.

## The exact mechanism, traced to source

`db.createView()`'s validation (`view_catalog_helpers.cpp:79` `validatePipeline()`) does two
separate things, each with a different "is this really an internal caller" blind spot:

1. **Lite-parse construction** — `const LiteParsedPipeline liteParsedPipeline(viewDef.viewOn(),
   viewDef.pipeline());` — no `LiteParserOptions` argument, so every stage's own `LiteParsed::parse()`
   runs with `options.opCtx == nullptr` (`lite_parsed_document_source.h:83` default). Any stage that
   does its own inline `assertAllowedInternalIfRequired(opts.opCtx, ...)` call *guarded on
   `opts.opCtx` being non-null* silently skips the check here (this is the confirmed
   `$_internalSearchIdLookup.viewPipeline` bug — `lite_parsed_internal_search_id_lookup.h:75-81`).

2. **Full parse for structural validation** — `Pipeline::parseFromLiteParsed(liteParsedPipeline,
   std::move(expCtx), ...)` (`view_catalog_helpers.cpp:113`), where `expCtx` is built with a real,
   non-null `opCtx` (`.fromRequest(opCtx, aggregateRequest)`) but a **stub** process interface
   (`"We can use a stub MongoProcessInterface because we are only parsing the Pipeline for
   validation here"`). `StubMongoProcessInterface::isExpectedToExecuteQueries()` returns `false`
   (`stub_mongo_process_interface.h:84-86`) — the *only* type that does
   (`mongo_process_interface.h:210-220`: "This function only returns false when the process
   interface is of type 'StubMongoProcessInterface'"). Any check gated on
   `isExpectedToExecuteQueries()` is therefore also skipped during `createView`, separately from
   the null-`opCtx` gap above.

3. Separately, `LiteParsedPipeline::validate(opCtx, performApiVersionChecks)` — called at
   `view_catalog_helpers.cpp:86` with the **real** `opCtx` and `performApiVersionChecks =
   !viewDef.timeseries()` (true for ordinary views) — **is** the correct, working enforcement path
   for any stage registered with `AllowedWithClientType::kInternal` at the top level
   (`lite_parsed_pipeline.cpp:154-183`, `assertLanguageFeatureIsAllowed` →
   `assertAllowedInternalIfRequired`, `allowed_contexts.cpp:38-49,90-99`). This is why the
   already-confirmed `$_internalUnpackBucket`/`$_internalApplyOplogUpdate` bugs (both closed
   Informative — see the correction notices on those two `README.md`s) were about being registered
   with the *unrestricted* `AllowedWithClientType::kAny` default in the first place, not about this
   `opCtx`/stub-interface gap — a properly-`kInternal`-registered stage **is** rejected by
   `db.createView()`, because this specific check path uses the real `opCtx`.

So the bypass class only bites a stage/field that does its **own**, separate, manually-coded
internal-only check inside its custom `LiteParsed::parse()` (gap 1) or `createFromBson()` (gap 2),
rather than relying purely on the central `AllowedWithClientType` registration + `validate()` path.

## Enumerated every such manual check site in the 8.3.8 tree (`assertAllowedInternalIfRequired` call sites)

| Site | Reads `opCtx` from | Runs at real query-execution time too? | Exploitable via `createView`? |
|---|---|---|---|
| `lite_parsed_internal_search_id_lookup.h:78` (`viewPipeline`) | `opts.opCtx` (lite-parse, gap 1) | **No** — the check exists only inside `LiteParsed::parse()`; ordinary query execution never re-invokes that class for an already-stored view pipeline | **Yes — confirmed, see `../README.md`** |
| `document_source_sort.cpp` internal fields (`$_internalLimit`/`$_internalOutputSortKeyMetadata`) | `SortLiteParsed::parse()`, same shape as above | No (same reasoning) | Reachable, but **no privilege gain** (Low — see `../sort-internal-fields-no-guard-confirmed.md`) |
| `accumulator_internal_construct_stats.cpp:84` | `expCtx->getOperationContext()`, inside the **accumulator's own constructor** — this is exec-tree construction, not lite-parse; only reachable at all when a real, executing `expCtx` exists | Yes, by construction (there's no non-executing path that reaches this constructor) | No |
| `document_source_hybrid_scoring_util.cpp:404` (`kIsHybridSearchFlagFieldName`) | `expCtx->getOperationContext()` inside `createFromBson`-time validation | Yes — `createFromBson` runs again on every real execution against the view, and `isExpectedToExecuteQueries()` is `true` there (real process interface) | No |
| `document_source_vector_search.cpp:212` (`view` field) | same, gated additionally by `shouldValidateInternalSearchFields()` (gap 2 shape) | Yes — verified `isExpectedToExecuteQueries()` defaults `true` for every process interface except the stub (`mongo_process_interface.h:217-220`), and no override exists in `common_mongod_process_interface.{h,cpp}`, so a real query against the resolved view uses the real interface | No |
| `search_helper.cpp:706` (`validateInternalSearchFieldsNotSetByUser`, `getInternalOnlyFieldNames()`) | same as above — called from `document_source_search.cpp:115` and `document_source_search_meta.cpp:160`, both inside their `createFromBson` | Yes, same reasoning | No |

**Net result:** of the 6 non-`$sort` sites (the 7th, `allowed_contexts.cpp:98`, is the shared
primitive itself, not a call site), only `$_internalSearchIdLookup.viewPipeline` sits at gap 1
(lite-parse-only, never re-checked) rather than gap 2 (stub-interface-only, correctly re-checked at
real execution). The distinguishing factor: every other site's check lives inside `createFromBson`
or an equivalent exec-construction path that **always** re-runs with a real, executing context the
moment the view is actually queried — only `$_internalSearchIdLookup`'s field check is isolated
inside the `LiteParsedDocumentSource` subclass, a code path that, for an already-persisted view, is
never revisited.

## Why this wasn't dynamically re-verified this pass

That session's container had outbound HTTPS to `fastdl.mongodb.org` blocked at the egress-policy
level (`connect_rejected`, gateway 403 on `CONNECT`, confirmed via the agent proxy's own
`/__agentproxy/status` — a policy denial, not a transient failure, and per that proxy's own
operating rules this is reported rather than retried or routed around). No previously-downloaded
`mongod` binary or data directory persisted into that container. The conclusions above are
therefore static-source-code analysis only — the same standard already applied and then verified
live for the confirmed findings in this directory; this particular sweep just hadn't had that live
pass yet. Flagging honestly rather than asserting a dynamic confirmation that didn't happen.

## Bottom line

No new exploitable bug. This closes out "is the `$_internalSearchIdLookup.viewPipeline` bug a
one-off or the first of several" with a specific, traced answer: **it is the only stage/field in
the 8.3.8 tree using this exact vulnerable shape** (manual internal-only check keyed off lite-parse
time's always-null `opCtx`, never repeated at execution time). The existing Critical write-up
stands as this session's one live-confirmed finding in this bug class; the BSONColumn RLE
decompression bomb (`../bsoncolumn-rle-decompression-bomb/`) stands as the other.
