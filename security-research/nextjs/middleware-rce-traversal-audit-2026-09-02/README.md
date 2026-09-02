# Next.js 16.3.4 — middleware bypass / RCE / path traversal audit

Scope requested: **middleware bypass, RCE, path traversal only** — plus a deep dive on the
React2Shell bug class. DNS-rebinding vectors explicitly out of scope for this pass.

**Outcome of this round: no fresh middleware bypass, RCE, or path traversal found.** Every
surface below was probed against a running `next start` server, not read-only. The negatives are
recorded in detail because they are the expensive part to re-derive, and because several of them
close vectors that are widely assumed to still work.

Lab: `next@16.3.4`, App Router, `next build` + `next start` on :3000, Node v22.22.2.
`middleware.js` protects `/admin/:path*` and returns `401 BLOCKED-BY-MIDDLEWARE` without an
`x-auth` header; `app/admin/page.js` renders `ADMIN-SECRET-CONTENT`.

## React2Shell class (CVE-2025-55182) — the deep dive

React2Shell is a logical deserialization RCE in the RSC Flight protocol: the server resolves
attacker-supplied server-reference IDs into module loads. I traced the whole path in 16.3.4.

**Where the danger is, upstream in React** —
`packages/next/src/compiled/react-server-dom-webpack/cjs/react-server-dom-webpack-server.node.production.js:2303`:

```js
function resolveServerReference(bundlerConfig, id) {
  var name = "", resolvedModuleData = bundlerConfig[id];   // no hasOwnProperty guard
  if (resolvedModuleData) name = resolvedModuleData.name;
  else {
    var idx = id.lastIndexOf("#");
    -1 !== idx && ((name = id.slice(idx + 1)),                 // attacker-chosen export name
                   (resolvedModuleData = bundlerConfig[id.slice(0, idx)]));
```

Two latent hazards: a raw `[id]` lookup that walks the prototype chain, and a `#` fallback that
makes the *export name* attacker-controlled, feeding `requireModule`'s
`moduleExports[metadata[2]]`.

**Why Next.js 16.3.4 is not exploitable through it.** `bundlerConfig` is Next's
`createServerModuleMap()` (`server/app-render/manifests-singleton.ts`), hardened in 16.2.11:

* `new Proxy(Object.create(null), …)` — null prototype, so `constructor` / `__proto__` /
  `toString` resolve to nothing.
* `wellKnownProperties.has(id)` → `Reflect.get`, so React's own probes don't reach the manifest.
* `mightBeServerReferenceId(id)` (a strict length gate) → otherwise **throws**.
* A manifest miss **throws** `getActionNotFoundError` rather than returning `undefined`.

That last point is what closes the `#` fallback: React only reaches it when `bundlerConfig[id]`
is falsy, and under this Proxy a miss can never return falsy — it throws first. The
attacker-controlled-export-name path is therefore unreachable in Next.js.

Also confirmed from the `v16.2.10..v16.2.11` diff: React's `decodeAction` was rewritten so that
a body may resolve **one** action key, where previously every `$ACTION_*` key in the body could
drive its own `loadServerReference` call.

**Upstream observation, not claimed as a Next.js vulnerability.** React's raw `bundlerConfig[id]`
is safe *only because the host passes a null-prototype Proxy*. An RSC host that passes a plain
object is exposed to prototype-chain lookups, and if anything in the process pollutes
`Object.prototype.id` / `.chunks` / `.name`, `resolveServerReference` returns attacker-shaped
metadata straight into `globalThis.__next_require__(metadata[0])`. On its own this is a **gadget,
not a vulnerability** — it needs a separate pollution primitive, and with a clean prototype it
crashes in `preloadModule` rather than executing anything. Worth a `hasOwnProperty` guard
upstream; not reportable as-is.

## Middleware bypass — 46 path forms + 7 header sets, all blocked

`poc/probe_middleware.py`. Baseline verified both ways (401 without `x-auth`, admin content with
it) before trusting any negative.

The matcher is evaluated against **both** the raw and the `decodeURIComponent`'d pathname
(`server/lib/router-utils/resolve-routes.ts:558-577`), which is what kills the encoding family:

| family | tried | result |
|---|---|---|
| single-encoding | `/%61dmin`, `/%61%64%6d%69%6e` | **blocked** (decoded form matches) |
| double-encoding | `/%2561dmin`, `/%2561%2564…` | 404 — router does not double-decode |
| dot segments | `/./admin`, `/foo/../admin`, `/foo/%2e%2e/admin` | **blocked** |
| encoded slash | `/admin%2f`, `/admin%2fx` | **blocked** |
| slash/backslash | `//admin`, `///admin`, `/admin\`, `/admin%5c` | 308 → canonical path, then blocked |
| case | `/ADMIN`, `/Admin` | 404 |
| suffix confusion | `/admin.rsc`, `/admin.segments/_tree.segment.rsc`, `/admin/index`, `/admin?_rsc=1`, `/_next/data/x/admin.json` | **blocked** |
| control chars | `%00`, `%0a`, `%09`, `%c0%af`, `%ef%bc%81` | 404 |
| headers | `x-middleware-subrequest` (incl. the chained CVE-2025-29927 form), `x-nextjs-data`, `x-invoke-path`, `RSC`, `x-middleware-override-headers` + `x-middleware-request-x-auth` | **blocked** |

`x-middleware-subrequest` no longer appears anywhere in the source tree — the CVE-2025-29927 fix
removed the header entirely rather than filtering it.

## Cross-route Server Action invocation — blocked by per-page binding

This is the vector most people assume still works: a Server Action defined inside a
middleware-protected route, invoked by POSTing its ID to an unprotected route, so the matcher
never sees `/admin`.

Confirmed **not** exploitable. `server-reference-manifest.json` binds each action to its page:

```
00717b0dcb47aedc5305c29351a2e544edee1bd952 ['app/admin/page']
00798d7ede0f80629dbb5cbb9551d2d86832dd93a3 ['app/pub/page']
```

and `createServerModuleMap` resolves `workers[normalizeWorkerPageName(workStore.page)]`.

| request | result |
|---|---|
| `POST /admin` + admin action ID, no auth | `401 BLOCKED-BY-MIDDLEWARE` |
| `POST /pub` + **admin** action ID | `200 {}` — action did **not** run |
| `POST /pub` + `/pub`'s own action ID (control) | `200` → `pub-noop`, action ran |

The control matters: it proves the action mechanism was live on that route and the admin action
was rejected specifically, not silently swallowed along with everything else.

One methodology note: the first attempt POSTed to `/`, which is statically prerendered, and got
`200 {}` with `x-nextjs-cache: HIT`. That is the static cache answering, not an action result —
it would have been easy to misread as either a bypass or a clean negative. The dynamic `/pub`
route plus the positive control is what makes the negative trustworthy.

## Path traversal — no escape found

* **ISR cache filename** (the CVE-2026-75604 primitive, still present in shape: a dynamic slug
  becomes `.next/server/app/blog/<slug>.html`). 33 encodings via `poc/probe_traversal.py` —
  raw/encoded/double-encoded `../`, `..\`, `%5c`, `%255c`, mixed separators, `....//`, `..;/`,
  overlong UTF-8, `%00`, `C:`, UNC. **Zero** files created outside the confined directory. The
  `filePath.startsWith(rootDir + path.sep)` check added in 16.3.3 holds. Payloads do survive
  into filenames (`..%5Cpwned.html`, `C:pwned.html`, one containing a raw newline) but none
  escapes.
* **Image cache path.** `join(cacheDir, cacheKey)` where the key is
  `getHash([CACHE_VERSION, href, width, quality, mimeType])` returning **base64url**
  (`A-Za-z0-9-_` only) — structurally incapable of traversal (`image-optimizer.ts:153-163, 543`).
* **`/_next/image?url=/…` local branch.** 9 traversal forms → all `400`, no file content.
  Guarded by `hasLocalMatch(localPatterns, url)` plus a `//` rejection and a recursion check.
* **`/_next/static/…`.** 7 traversal forms → `404`/`308`, no file content.

## Not a vulnerability, but worth someone's attention

`getSharp()` (`image-optimizer.ts:86-127`) does a bare `require('sharp')` with **no runtime
version check** and unconditionally unblocks `VipsForeignLoadHeif`. 16.3.3 (`3a15b4ac6a`)
disabled AVIF decoding as a mitigation; 16.3.4 (`12e173dd73`, "Re-enable AVIF image optimization
and require sharp 0.35.4") reverted it, leaving the compensating control expressed only as
`optionalDependencies: { "sharp": "^0.35.4" }`. That constrains what npm installs *for Next.js*,
not a `sharp` the project installs itself and hoists. Such an install silently returns to the
configuration 16.3.3 mitigated. A version assertion in `getSharp()` would make the mitigation
self-enforcing. Detailed in `../image-optimizer-ssrf-2026-09-02/REPORT.md`.

## Where I would look next

Not yet examined, in rough order of expected yield:

1. **`decodeReply` / `decodeBoundActionMetaData` argument deserialization** — the action *ID* path
   is hardened, but the bound-argument and temporary-reference decoding is a much larger surface
   and is the part of the Flight protocol React2Shell actually abused.
2. **Server Action CSRF** — `Origin`/`Host` comparison and `allowedOrigins` matching (null origin,
   port confusion, case, subdomain suffix bugs).
3. **Cache key vs. render inputs** — anything that changes the rendered output but is absent from
   the response-cache key is a poisoning candidate; the `Vary` set observed on responses is
   narrow.
4. **`next-routing`** — a package new to this tree, unexamined.
5. **Windows-only path semantics** — `path.win32` divergences beyond the one already patched;
   the reference CVE proves this class is live and it cannot be tested from Linux.
