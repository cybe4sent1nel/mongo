# mongodb-mcp-server: deep audit for fresh high/critical bugs (excluding DNS rebinding)

**Status: no fresh confirmed HIGH/CRITICAL vulnerability found in this pass.** Several
promising leads were traced to a concrete conclusion (safe or already-guarded) rather than left
as speculation. Documenting the full trail so the effort isn't repeated, plus two lower-confidence
architecture observations and unaudited areas for a next round.

Scope note per instruction: DNS-rebinding-class findings against the HTTP transport are excluded
as already known/reported and not re-covered here.

Repo: `mongodb-js/mongodb-mcp-server`, `main`, commit `f64f4e52e5f5dab7a95834ec051fd013235b5ca7`
(2026-08-27).

## Leads chased down, ruled out

### 1. MQL security guards (`assertNoServerSideJS`, write-stage detection) — sound

`packages/tools-mongodb/src/helpers/mqlGuards.ts`: `findServerSideJSOperator` recurses fully
through nested objects/arrays, so `$where`/`$function`/`$accumulator` can't hide inside a
sub-pipeline, `$facet`, `$lookup`, etc. to dodge `disableServerSideJs`. Write-stage detection
(`isWriteStage`, `$out`/`$merge`) is deliberately top-level-only, but that matches MongoDB server
semantics — `$out`/`$merge` are documented as disallowed inside `$facet`/`$lookup` sub-pipelines,
so there's no bypass angle there. Every aggregate-capable tool (`aggregate`, `aggregate-db`,
`export`) calls `assertMqlIsAllowed`/`assertOnlyUsesPermittedStages` consistently — no tool found
that runs a pipeline while skipping this check. No generic `run-command`/`eval`-style tool exists
in the tool list at all (checked `packages/tools-mongodb/src/tools/**`), so there's no
alternate code path that reaches the driver while bypassing these guards entirely.

### 2. Request-header/query config overrides (`MDB_MCP_ALLOW_REQUEST_OVERRIDES`) — monotonically restrictive by design, not a bypass

Initially looked like a strong candidate: if an operator turns this on (documented, off by
default) to let per-request callers pick their own connection string, could the same mechanism
also let any caller flip `readOnly`/`disableServerSideJs` off via a header, silently defeating
the safety config regardless of the operator's intent? Checked
`packages/cli/src/config/userConfig.ts` + `configOverrides.ts`: every security-relevant field has
its own `overrideBehavior`:
- `readOnly`, `indexCheck`, `disableServerSideJs`: `oneWayOverride(true)` — verified in
  `configUtils.ts` this only accepts a request value equal to the current value or equal to
  `true`; a request trying to set `false` throws. Can only be tightened, never loosened.
- `connectionString`: `overrideBehavior: "not-allowed"` and `isSecret: true` — can't be touched by
  a request at all.
- `disabledTools`: `overrideBehavior: "merge"` (array union — can only add more disabled tools,
  never remove one).
- Most other fields default to `"not-allowed"`.
No field that gates a destructive/JS-execution capability can be loosened through this mechanism.
Not a vulnerability.

### 3. Export tool file path construction — latent pattern, not currently reachable

`ExportsManager.createJSONExport` (`packages/tools-mongodb/src/common/exportsManager.ts`) builds
`path.join(exportsDirectoryPath, exportNameWithExtension)` from an `exportName` that is
URL-decoded (`decodeAndNormalize`) with **no path-traversal containment check** (no
`path.basename()`, no verification the resolved path still starts with the intended directory).
`path.join` does not stop `../` segments from escaping the base directory. This is the shape of a
real arbitrary-file-write primitive *if* `exportName` were ever attacker-influenced. Traced every
caller:
- The only call site, `packages/tools-mongodb/src/tools/read/export.ts:101`, builds the name
  itself: `` `${new ObjectId().toString()}.json` `` — never derived from any tool-call argument.
- The exports directory itself (`exportsDirectoryPath = path.join(exportsPath, sessionId)`) also
  looked promising to chase (an attacker-controlled HTTP `mcp-session-id` could in principle
  reach a "sessionId" parameter): checked `createExportsManagerFromConfig` /
  `createServerFromConfig` in `packages/cli/src/createServerServices.ts` — `sessionId` is never
  passed through; `ExportsManager.init` always falls back to its own freshly generated
  `new ObjectId().toString()` default, unrelated to the transport-level MCP session id.
- `readExport` only serves names already present in the in-memory `storedExports` map, which is
  only ever populated by the one safe call site above — no independent arbitrary-file-read
  primitive either.

**Conclusion: not exploitable today.** Worth flagging to the maintainers as a defense-in-depth
gap regardless (add a `path.basename()`/containment assertion so this can't turn into a real bug
the next time a caller — export, or a future tool — passes a less-trusted name), but reporting it
as a live vulnerability would overstate what's actually reachable.

### 4. Tool operation-type classification — correct throughout

Cross-checked every create/update/delete tool's declared `static operationType` against what it
actually does (this is the field `readOnly`/`disabledTools` gate on): `create-collection`,
`create-index`, `insert-many` → `create`; `rename-collection`, `update-many` → `update`;
`delete-many`, `drop-collection`, `drop-database`, `drop-index` → `delete`. No mislabeled tool
that could let a destructive operation slip through the `readOnly` gate by claiming to be a
`read` operation.

### 5. `connect` tool accepts any connection string, any host — by design, not chased as a bug

`connect.ts` takes a caller-supplied `mongodb://`/`mongodb+srv://` string with no host allowlist
or private-IP denylist. This is a real SSRF-shaped primitive *if* the MCP server is shared across
mutually-untrusting clients (the server's own docs anticipate multi-client HTTP deployments), but
it's also the tool's entire stated purpose — connecting to a MongoDB instance on the caller's
behalf. Flagging it here for completeness, not filing it as a fresh bug: this is very likely to
be treated by the maintainers as intended behavior rather than a defect, the same way a generic
HTTP-fetching tool is expected to fetch whatever URL it's given.

## Not yet audited (candidates for a next pass)

- `packages/tools-atlas` / `packages/atlas-api-client` — the Atlas Admin API integration and its
  OAuth/service-account credential handling; a completely different attack surface from the
  MongoDB-wire-protocol tools audited here, not touched this round.
- `packages/tools-mongodb/src/common/connectionRegistry.ts` and `MCPConnectionStore` — the
  cross-session connection-sharing logic (`connectionScope: "global"` vs `"session"`) deserves a
  closer look at whether a `"session"`-scoped registry can ever leak or be confused with another
  session's live connection handle; only skimmed this round.
- `packages/tools-mongodb/src/tools/metadata/logs.ts` (the `getLog` passthrough) for whether any
  server-side log content could carry redaction-bypassing secrets back to a caller who shouldn't
  see them.
