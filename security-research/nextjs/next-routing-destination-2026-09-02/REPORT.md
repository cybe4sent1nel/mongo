# `@next/routing@16.3.4`: the CVE-2026-64645 destination fix was never applied to the sibling package

**Package:** `@next/routing` (`packages/next-routing`), version 16.3.4, published from the
`vercel/next.js` monorepo
**File:** `packages/next-routing/src/destination.ts`, `replaceDestination()`
**Class:** CWE-918 (SSRF) / CWE-601 (open redirect) — the same defect as CVE-2026-64645
**Status:** reproduced by execution against the package source.

## Read this first: what this is and is not

* This is **not an RCE**, and I am not presenting it as one.
* It is **not reachable from a Next.js application.** `@next/routing` is published and versioned
  in lockstep with Next.js, but nothing in `packages/next/` imports it — I grepped the whole
  monorepo and the only references are inside the package's own directory. A `next` app does not
  execute this code.
* What it **is**: the fix that Vercel shipped for CVE-2026-64645 in `next` was not applied to the
  sibling package that reimplements the same logic and is published under the same org and
  version number. Anyone who adopts `@next/routing` for external rewrites gets the vulnerability
  that `next` was patched against four releases ago.

I am reporting it as an incomplete-fix / parallel-implementation issue, not as a Next.js
vulnerability.

## The divergence

`next` was fixed in 16.2.11 —
`packages/next/src/shared/lib/router/utils/prepare-destination.ts:264-270`:

```ts
let destHostnameCompiler
if (destHostname) {
  destHostnameCompiler = safeCompile(destHostname, {
    validate: false,
    encode: encodeURIComponent,   // <-- the CVE-2026-64645 fix
  })
}
```

`@next/routing` has no equivalent — `packages/next-routing/src/destination.ts:5-33`:

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
      result = result.replace(new RegExp(`\\$${i}`, 'g'), value)
    }
    if (regexMatches.groups) {
      for (const [name, value] of Object.entries(regexMatches.groups)) {
        result = result.replace(new RegExp(`\\$${name}`, 'g'), value ?? '')
      }
    }
  }
  for (const [name, value] of Object.entries(hasCaptures)) {
    result = result.replace(new RegExp(`\\$${name}`, 'g'), value)
  }
  return result
}
```

Raw string substitution, no encoding. The result flows straight to a URL that is fetched or
redirected to — `resolve-routes.ts:93` substitutes, then `:191`/`:1044`/`:1225`
`isExternalDestination(match.destination)` and `:158`/`:201` `applyDestination()` →
`new URL(destination)`.

## Proof

`poc/t_next_routing.mjs`, importing the real `destination.ts`. Template
`https://$tenant.api.example.com/data`, capture value varied:

```
  benign
    capture  : {"tenant":"acme"}
    result   : https://acme.api.example.com/data
    -> HOST  : acme.api.example.com

  re-anchor by closing host with /
    capture  : {"tenant":"evil.example.com/"}
    result   : https://evil.example.com/.api.example.com/data
    -> HOST  : evil.example.com

  re-anchor with #
    capture  : {"tenant":"evil.example.com#"}
    -> HOST  : evil.example.com

  re-anchor with ?
    capture  : {"tenant":"evil.example.com?"}
    -> HOST  : evil.example.com

  backslash
    capture  : {"tenant":"evil.example.com\"}
    -> HOST  : evil.example.com

  re-anchor with @ (credentials trick)
    capture  : {"tenant":"x@evil.example.com"}
    result   : https://x@evil.example.com.api.example.com/data
    -> HOST  : evil.example.com.api.example.com
```

Four characters (`/`, `#`, `?`, `\`) move the resolved host to the attacker's domain outright.
The `@` variant re-anchors to `evil.example.com.api.example.com`, a name the attacker can
register under their own domain. `encodeURIComponent` — the fix already in `next` — neutralises
all five.

## Two secondary defects in the same function

Both are consequences of using `String.replace` with untrusted input:

1. **Replacement-pattern injection.** The capture `value` is passed as `replace()`'s second
   argument, so `$&`, `` $` ``, `$'` and `$1` inside an attacker-controlled value are interpreted
   as replacement patterns rather than literal text. Values should be inserted with a replacer
   function (`() => value`), not as a pattern string.
2. **Substitution order dependence.** Numbered groups are replaced before named ones, and each
   substitution rewrites the whole accumulated string, so a value that itself contains `$name`
   can be expanded by a later pass. This is a correctness bug that also widens (1).

## Suggested fix

Apply the CVE-2026-64645 remedy here as well: percent-encode capture values before substituting
them into a destination, at minimum whenever the destination is external. Concretely, encode with
`encodeURIComponent` for the host portion, and insert via a replacer function so `$`-sequences in
values are literal:

```ts
result = result.replace(new RegExp(`\\$${name}`, 'g'), () => encodeURIComponent(value ?? ''))
```

More durably: have `@next/routing` call into the same hardened `prepare-destination` logic that
`next` uses, so the two cannot drift again. This bug exists precisely because the same feature is
implemented twice and only one copy was patched.

## Prior art

CVE-2026-64645 / GHSA-p9j2-gv94-2wf4 covers the `next` implementation, fixed in 15.5.21 and
16.2.11. I found no advisory, issue, or commit addressing `@next/routing`'s copy, which is still
unencoded at 16.3.4.

## AI tooling disclosure

I used an AI coding assistant to read the tree, spot the divergence, and write the PoC and this
report. The substitution results quoted above are literal output from executing the package's own
`destination.ts`; nothing here is asserted from reading alone.
