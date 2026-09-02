# Next.js 16.3.4 — exhaustive RCE sink inventory

Systematic sweep of `packages/next/src/` for code-execution primitives, then reachability
analysis from request-controlled input on each. **No request-reachable RCE found.** This is the
record of every sink and why it is or is not reachable, so the ground does not have to be
re-covered.

The one live chain worth continuing on is stated at the end.

## Method

Enumerate sinks by category, then for each ask: can a value derived from an HTTP request reach
it at runtime in a production server? Build-time and dev-only code that executes developer-authored
input (webpack loaders, `next.config.js`, codegen) is **by design** and is excluded — it is not a
vulnerability for a framework to run its own user's code.

## `eval` / `Function` constructor

| site | verdict |
|---|---|
| `build/webpack/plugins/eval-source-map-dev-tool-plugin.ts:249` | build-time dev source maps; emits `eval()` into client bundles. Not server-side, not request-reachable. |

Nothing else in the tree. Notably, the **server** Flight decoder has no `eval` and no
`Symbol.for` case — verified by reading every `parseModelString` branch (see
`flight-argument-decoder-2026-09-02/`).

## `child_process`

| site | verdict |
|---|---|
| `server/lib/start-server.ts:66,81` | `exec(\`lsof -ti:${port} …\`)` / `netstat … ":${port} "`. `port` is a number from CLI/env at startup, not from a request. Not reachable. |
| `trace/upload-trace.ts:24-34` | build/telemetry, spawns a fixed script. Not request-reachable. |

## `vm`

| site | verdict |
|---|---|
| `server/web/sandbox/context.ts:17` (`runInContext`) | the Edge Runtime sandbox. Running the app's own middleware/edge code is the feature. |
| `server/load-manifest.external.ts` (`runInNewContext`) | **`evalManifest()` evaluates a manifest file's contents.** The path is `join(projectDir, distDir, manifest)` — internal constants, never request-derived. **But: any attacker-controlled write into `.next/` becomes RCE here.** This is the sink that made CVE-2026-75604 a Critical rather than a file-write bug. |

## Dynamic `require` / `import`

| site | verdict |
|---|---|
| `server/require.ts:131` `__non_webpack_require__(pagePath)` | the strongest-looking sink: loads a page module by path. `pagePath` comes from `manifest[page]`, and `page` is request-derived. **Safe** — see the lookup analysis below. |
| `server/lib/module-loader/node-module-loader.ts:12` | `id` is a route-module filename from the manifest, not request input. |
| `server/route-matcher-providers/helpers/manifest-loaders/node-manifest-loader.ts:10` | `name` is a constant manifest filename. |
| `server/config.ts:1979` `require(path)` | loads `next.config.js` at startup. By design. |
| `server/render-result.ts:267,310`, `stream-utils/*`, `app-render/app-render-prerender-utils.ts` | hardcoded `'node:stream'`. |

### Why `require.ts` is safe (the closest call)

`getMaybePagePath` does an **unguarded prototype-chain lookup** on request-derived input:

```ts
const checkManifest = (manifest: PagesManifest) => {
  let curPath = manifest[page]        // no hasOwnProperty guard; manifest is a JSON.parse object
```

`manifest` comes from `JSON.parse`, so `Object.prototype` is in its chain and
`manifest['constructor']` would return `Object`. That value flows to `path.isAbsolute(pagePath)`
and then `require(pagePath)`.

It is unreachable because `page` is normalised first:

```ts
page = denormalizePagePath(normalizePagePath(page))
```

`normalizePagePath` ends in `ensureLeadingSlash(page)` and additionally asserts
`posix.normalize(normalized) === normalized` (killing `..`, `//`, `.`). `denormalizePagePath`
preserves the leading slash in every branch. So `page` always starts with `/`, and
`Object.prototype` has no `/`-prefixed keys. `manifest['/constructor']` is `undefined`.

A `hasOwnProperty` guard here would still be worth adding — the safety currently depends entirely
on a normalisation step two calls away.

## Filesystem writes (the `evalManifest` chain)

Because `evalManifest` turns any write into `.next/` into RCE, every runtime write sink was traced:

| sink | path derivation | verdict |
|---|---|---|
| `lib/incremental-cache/file-system-cache.ts` (ISR/pages/app/fetch) | `path.join(rootDir, key)` + `filePath.startsWith(rootDir + path.sep)` containment check added in 16.3.3 | **contained.** 33 traversal encodings fired at the live route produced zero escapes. |
| fetch-cache key | `IncrementalCache.generateCacheKey()` → `hashString(JSON.stringify([...]))` | hashed; no attacker bytes reach the path. |
| `image-optimizer.ts:200-201` | `join(cacheDir, cacheKey)` where key is `getHash([...])` → **base64url** (`A-Za-z0-9-_`); filename is `${maxAge}.${expireAt}.${etag}.${upstreamEtag}.${extension}` | safe. `upstreamEtag` is attacker-influenced (it is the upstream `ETag` header) but `extractEtag` base64url-encodes it, so no separators or dots survive. |
| `app-render/encryption-utils-server.ts:22-24` | fixed cache dir | not request-derived. |
| `lib/router-utils/route-types-utils.ts`, `root-params-type-utils.ts`, `cache-life-type-utils.ts`, `lib/generate-agent-files.ts`, `lib/experimental/create-env-definitions.ts`, `lib/cpu-profile.ts`, `lib/chrome-devtools-workspace.ts` | dev/build codegen | not in the production request path. |

## What this leaves

The only intact RCE chain in the codebase is **arbitrary write into `.next/` → `evalManifest`**.
Every write sink that a request can reach is currently either containment-checked or
hash-derived. Finding an RCE means finding a *new* write primitive, not a new execution sink —
the execution sink already exists and is unguarded by design.

Concretely, the places still worth attacking for a write:

1. **Custom `cacheHandler` implementations** — `incremental-cache/index.ts` delegates to a
   user-supplied handler when configured. The containment check added in 16.3.3 lives in
   `FileSystemCache`, not in the interface, so a third-party handler that joins the key onto a
   path has the original bug. Worth checking what Vercel's own handlers do.
2. **Windows path semantics** beyond the patched backslash case — drive-relative (`C:foo`), UNC
   (`\\?\`), trailing dots/spaces, and 8.3 short names. Untestable from Linux; the reference CVE
   proves the class is live.
3. **`revalidateTag` / `revalidatePath` tag storage**, not yet traced end to end.
4. Multipart/temp-file handling for Server Action file uploads.
