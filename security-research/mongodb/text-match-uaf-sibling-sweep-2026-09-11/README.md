# Sibling-bug sweep for CVE-2026-82056 / SERVER-130306 (TextMatchExpression UAF) — negative result

**Target:** `mongodb/mongo` tag `r8.3.9` (commit `1dc3d60c3237b53589325474c668e849ecec3bae`), cloned
fresh to examine the fix and search for the same anti-pattern class elsewhere.

## The disclosed bug, as fixed in this tag

`src/mongo/db/matcher/expression_text.cpp`'s `validateFTSIndex()` helper does its own short-lived
collection acquisition (`acquireCollectionOrViewMaybeLockFree`), looks up the collection's text
index, and — in the fixed code — returns:
```cpp
return {fam->getSpec().getTextIndexVersion(), fam->getSpec().defaultLanguage().str()};
```
`FTSSpec::defaultLanguage()` (`fts_spec.h:87`) returns `const FTSLanguage&` — a reference into
memory owned by the index's `FTSSpec`/`FTSAccessMethod`, which is itself only guaranteed alive for
as long as `validateFTSIndex`'s own local `collection` acquisition is alive. Per the Jira history
(SERVER-130306), the pre-fix code returned that reference (or an unowned view derived from it)
directly instead of calling `.str()` to copy it — so by the time the caller (`TextMatchExpression`'s
constructor) used the returned language value, `validateFTSIndex`'s local acquisition had already
gone out of scope. If a concurrent index-lifecycle operation (drop/rebuild of the text index) ran
in that window, the `FTSSpec` memory could be freed while the caller still held a reference into
it — a heap-use-after-free read, reachable by an authenticated `readWrite`-privileged user via
ordinary `$text` query + concurrent index management (matches the CVE's own reachability
description). The fixed code's own added comment confirms the exact mechanism: `// Snapshot
closed. 'version' and 'defaultLanguage' are owned copies.`

## Sweep for the same shape elsewhere

The anti-pattern's specific shape: **a helper function performs its own (nested, shorter-lived)
collection/index-catalog acquisition, extracts a non-owning reference or view into
catalog-owned metadata, and returns it without copying — while the caller uses the result after
that specific acquisition (not necessarily any acquisition the caller itself might separately
hold) has already been destroyed.**

Checked, in order of relevance:

- **Every other `acquireCollectionOrViewMaybeLockFree`/`acquireCollectionMaybeLockFree` call site
  combined with `IndexCatalogEntry`/`accessMethod()`/`findIndexByType` usage** across
  `src/mongo/db` (non-test files): `dbhelpers.cpp`, `common_mongod_process_interface.cpp`,
  `s/analyze_shard_key_cmd_util.cpp`, `shard_catalog/drop_indexes.cpp`,
  `index_builds/index_builds_coordinator.cpp`, `ttl/ttl_monitor.cpp`. In every one, either (a) the
  extracted data is used and converted to an owned value (BSON copy via `.toBSON()`, an enum, a
  `bool`) entirely within the same function that did the acquisition, or (b) the raw pointer
  (`IndexCatalogEntry*`) is derived from a `CollectionPtr`/acquisition the *caller* already
  supplied and is expected to keep alive for the duration of use (the normal, correct pattern
  everywhere else in this codebase) rather than from a *new, nested* acquisition scoped only to
  the helper itself.

- **`CommonMongodProcessInterface::fieldsHaveSupportingUniqueIndex`**
  (`pipeline/process_interface/common_mongod_process_interface.cpp:1003-1051`) — iterates
  `IndexCatalogEntry*` via a raw pointer from the index iterator, but the enclosing `collection`
  acquisition stays alive for the whole function body and the return type is a value enum
  (`SupportingUniqueIndex`). Safe.

- **`ttl_monitor.cpp`'s `getValidTTLIndex`** — returns a raw `const IndexCatalogEntry*`, which
  looked suspicious at first glance, but it takes `const CollectionPtr& collection` *from the
  caller* (no internal acquisition of its own) and every caller uses the returned pointer while
  still holding that same collection reference. Different, safe shape — not the buggy one.

- **`pipeline_d.cpp`'s `extractGeoNearFieldFromIndexesByType`/`extractGeoNearFieldFromIndexes`
  (`$geoNear` index selection)** — the closest structural match found. Both return
  `StringData`/`boost::optional<StringData>` built from `idxToUse->keyPattern()`'s field name — a
  **non-owning view into the `IndexDescriptor`'s own BSON key-pattern**, exactly the same
  "raw view into index-catalog-owned memory" shape as the disclosed bug's `FTSLanguage&`. Traced
  the one caller (`PipelineD::buildInnerQueryExecutorGeoNear`, `pipeline_d.cpp:1887`): the
  `StringData` is converted to an owned `std::string` in the very same statement it's returned
  into (`auto nearFieldName = std::string{... extractGeoNearFieldFromIndexes(...)};`), and unlike
  `validateFTSIndex`, this function doesn't do its own nested acquisition — `collection` is a
  reference to the *same* acquisition the caller (`buildInnerQueryExecutorGeoNear`) already holds
  for the whole pipeline-build call, which doesn't yield or release in between. Checked and ruled
  out: safe.

## Net result

**No new instance of this UAF class found in `r8.3.9`.** This was a targeted, code-reading sweep
(not a fuzzing campaign — this bug class is a logic/lifetime error, not something a malformed-input
fuzzer would surface) of every call site combining a scoped collection/index-catalog acquisition
with extraction of index-catalog-owned metadata. One candidate (`extractGeoNearFieldFromIndexes`)
had the same "return a non-owning view into catalog memory" shape as the disclosed bug and was
worth tracing fully; it turned out to be safe because it doesn't create its own nested acquisition
and the caller copies immediately. Reporting this honestly as a negative result rather than
stretching the geoNear candidate into a claim it doesn't support.

## Scope note

The disclosed CVE (and this sweep) is a **post-auth** bug class — reachable by an authenticated
user with `readWrite` privilege via ordinary query execution racing concurrent index-management
operations, not a pre-auth vector. Recorded here as its own item, separate from this engagement's
pre-auth-only crash-hunting work elsewhere in `security-research/mongodb/`.
