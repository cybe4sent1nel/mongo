# Kibana: hunt for fresh prototype-pollution-to-RCE siblings of ESA-2024-22 (CVE-2024-37287)

**Status: in progress, checkpoint. No fresh sibling confirmed yet — the original bug class has
been hardened systemically since the 2024 fix. Documenting what's been ruled out so effort
isn't repeated, and flagging one unrelated, lower-severity side-observation found along the
way.**

## Target and setup

Cloned `elastic/kibana` fresh (shallow, blob-filtered) into
`/home/user/drivers/kibana`, current `main` tip: commit `b75107985e0da4a0226808e1a9b6c57c52b73431`
(2026-08-28), `package.json` version `9.6.0`. Not the mongo repo/branch this engagement otherwise
lives in — Kibana source itself isn't part of `cybe4sent1nel/mongo`, so this is a pure read-only
static-audit exercise; findings get written up here same as the driver audits.

## Recap of the original bug (ESA-2024-22 / CVE-2024-37287)

Prototype pollution in Kibana's Alerting framework, reachable by an attacker who (a) has write
access to the `.ml-anomalies*` indices and (b) has read access to the ML and
Actions-and-Connectors Kibana features — i.e., an attacker who can plant a malicious document in
an ES index that Kibana's own alerting/ML code later reads and turns into template variables,
without needing to compromise a Kibana user directly. CVSS 9.1. Root cause (inferred from the
current hardening, not from the historical patch diff — this shallow clone has no older history
to diff against): a field name straight off an ES document was used as a dotted path and written
into a live object via an unguarded `lodash.set`/`setWith`-shaped operation, allowing
`__proto__`/`constructor.prototype` to be reached and polluting `Object.prototype` for the
Node.js process — eventually converted into RCE via whatever downstream code trusted the
polluted global state.

## What's already been hardened (checked directly against current `main`)

1. **The originally-implicated code, `mustache_renderer.ts`
   (`x-pack/platform/plugins/shared/actions/server/lib/mustache_renderer.ts`)**, which expands
   dotted ES field names (`kibana.alert.rule.name`) into nested objects before Mustache template
   rendering — exactly the shape of transform the original bug would have gone through — now:
   - Uses `setWith` from `@kbn/safer-lodash-set` (a hardened fork), not raw `lodash`.
   - Has an explicit `isUnsafeKey()` guard rejecting `__proto__`, `constructor`, `prototype` as
     path segments *before* `setWith` is ever called (belt-and-suspenders on top of the safer
     library itself).

2. **Repo-wide ESLint enforcement (`.eslintrc.js`)** bans `lodash`'s `set`, `setWith`, `assoc`,
   `assocPath`, and `template` in **both** forms:
   - `no-restricted-imports`: named imports (`import { set } from 'lodash'`) and namespace/fp
     variants (`lodash/fp`, `lodash/set`, `lodash/fp/set`, etc.).
   - `no-restricted-properties`: member access after a default/namespace import
     (`_.set(...)`, `lodash.set(...)`), which `no-restricted-imports` alone would miss.
   - The only files that bypass this ban via `eslint-disable` are the rule's own test fixtures
     (`src/dev/eslint/security_eslint_rule_tests.ts`), confirmed by grep across the whole tree.
   - This specifically targets the `set`/`setWith` shape (not `merge`/`mergeWith` — lodash's own
     `merge` has had its own, separate `__proto__` guard since 4.17.11, and Kibana pins
     `lodash@4.18.1`, well past that fix).

3. **A second, independent custom "set nested property from dotted path" implementation**
   (`x-pack/platform/packages/private/ml/nested_property/src/set_nested_property.ts` — in the ML
   package specifically, the same subsystem implicated in the original CVE) also has its own
   `INVALID_ACCESSORS = ['__proto__', 'prototype', 'constructor']` guard, checked before any
   property is ever written. Its only non-test caller
   (`transform/public/.../get_update_value.ts`) is client-side UI form state, not
   attacker-reachable pre-auth, but it's guarded regardless.

4. **The ML anomaly-detection alerting service**
   (`x-pack/platform/plugins/shared/ml/server/lib/alerts/alerting_service.ts`) — the closest
   living descendant of the exact original threat model (ML job results → alert action
   variables) — was read end-to-end for dynamic-key-from-untrusted-field-name patterns. Found
   one weak pattern, not a real finding: `Object.entries(fieldFormatMap).reduce((acc, [fieldName,
   config]) => { acc[fieldName] = ...; return acc }, {})` (line ~239) does an unguarded bracket
   assignment keyed by `fieldName`, but `acc` is a fresh object literal built for a single call
   and never merged back into shared/global state, and `fieldFormatMap` comes from a
   user-configured index-pattern field-formatter map, not attacker-supplied ES document content.
   Setting `acc.__proto__` here only rewrites that one local object's own prototype pointer, not
   `Object.prototype` globally — not equivalent to the original bug's global pollution.
   `alerts_client.ts:762`'s `for (const key in rawActiveAlerts)` loop was also checked; the only
   assignment inside is keyed by `meta.uuid`, an ID Kibana's own alerting framework generates
   internally, not attacker-supplied field content.

## Side observation (different bug class, not chased further — flagging, not claiming)

While in the area, `x-pack/platform/plugins/shared/ingest_pipelines/server/lib/mapper.ts`
(`fieldPresencePredicate`, used by the CSV→ingest-pipeline UI feature) builds a Painless-script
condition by directly interpolating a CSV column's `source_field`/`destination_field` value into
a script string (`` `ctx.${field} != null` `` / `` `ctx.${fieldPath.join('?.')} != null` ``) with
no escaping, then embeds that string as the pipeline processor's `if` condition. This is
*script-string injection into a Painless condition*, not prototype pollution, and:
- Requires an authenticated user with ingest-pipeline-management privileges uploading their own
  CSV — the attacker and the "victim" (the pipeline's own script context) are the same principal
  in the base case, so it isn't a privilege boundary crossing on its own.
- Painless itself runs sandboxed inside Elasticsearch (restricted API surface, no arbitrary code
  execution by design), so the ceiling here is script-logic manipulation within that sandbox, not
  RCE — a materially different (and almost certainly lower) severity than the prototype-pollution
  class this hunt is targeting.
- Not independently verified with a working PoC payload this round; noting it as an open thread
  for separate follow-up, not as a confirmed vulnerability of any severity.

## Conclusion so far

No fresh prototype-pollution-to-RCE sibling of CVE-2024-37287 confirmed in this pass. The
specific subsystem originally hit, the general `set`/`setWith` pattern repo-wide, and the other
custom implementation of the same "dotted path → nested object" idea in the same ML plugin are
all already guarded, and the guard is enforced by lint rather than just convention. This makes a
byte-for-byte repeat of the 2024 bug unlikely to have slipped back in undetected; a genuinely new
finding would more likely be a *different* mechanism reaching the same "attacker-controlled key →
prototype write" outcome (e.g., a hand-rolled recursive merge/copy loop that never went through
`lodash` or the ML package's setter at all, so neither guard applies) rather than a repeat of the
exact original code shape.

## Not yet checked (candidate areas for continuing this hunt)

- Saved objects import/export (NDJSON) and migration transforms — historically a rich source of
  "attacker-controlled document → internal state" bugs across many products.
- Canvas / expressions engine (`kbn-expressions` and the Canvas plugin) — a scripting-like
  surface with its own history of sandbox-escape-shaped issues, different mechanism than
  prototype pollution but same "malicious data reaches privileged evaluation" family.
- Reporting service and case-management attachments — both take structured, potentially
  externally-influenced input and assemble it into templates/documents server-side.
- Any hand-rolled recursive merge/copy loop that doesn't go through `lodash` or
  `@kbn/safer-lodash-set` at all (a `for...in` + bracket-assignment copy, or a bespoke
  `deepMerge` implementation) — this is the shape most likely to have escaped the existing
  guardrails, since those guardrails are lodash- and ML-package-specific.
