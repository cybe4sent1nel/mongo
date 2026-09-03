# Next.js 16.3.4 — second RCE / path-traversal pass (2026-09-03)

**Ask:** deeply audit for RCE and path-traversal bugs specifically. DNS-rebinding
and TOCTOU explicitly excluded — that class is already covered by
`../image-optimizer-ssrf-2026-09-02` and isn't of interest here.
**Target:** `next@16.3.4` (`299180d331`), live `next start` and `output:
standalone` labs, Node v22.22.2.
**Result: no new bug found this round.** Recorded so the ground isn't
re-covered — this is the second pass on the same target, continuing
`middleware-rce-traversal-audit-2026-09-02`, whose own "where I would look
next" list this round worked through.

## Method

Same two techniques as the WordPress round that immediately preceded this one:

1. **Live testing** against a running server — a `next start` lab plus a
   freshly built `output: standalone` lab (unexamined by the prior round,
   which only tested the ordinary `next start` static paths).
2. **Changelog diffing** — `vercel/next.js` fetched live from `origin/canary`;
   every commit between the `v16.3.4` tag and current canary (490 commits)
   read by commit message for anything RCE/traversal-shaped. A hit here means
   a bug description for something still present in the 16.3.4 release under
   test, the same logic that worked for the WordPress round.

## New surfaces checked this round

### `output: standalone` static file serving — same guarantees as `next start`

The prior round's 33-encoding traversal sweep ran against an ordinary
`next start` server, which serves `/_next/static/` and `public/` through the
normal request router. `output: standalone` produces a **separate** minimal
`server.js` with its own static-serving wiring — genuinely different code to
test, not an assumption carried over. Built and ran it fresh
(`.next/standalone/server.js`, `public/marker.txt` as the confined-directory
canary, `/tmp/outside_secret.txt` and a `.next/standalone/server.js` read
attempt as escape targets). 17 traversal encodings — raw and
percent-encoded `../`, `..\`, mixed/doubled separators, `%2e%2e`, `....//`,
literal `//`, path-appended traversal after a real file (`/marker.txt/../..`),
and a null-byte extension bypass (`poc/probe_standalone_static.py`,
recorded output in the matching `.txt`). **Every attempt returned 404** with
Next's own not-found page; zero bytes of anything outside `public/` were
returned. Same result as the `next start` sweep — the standalone server's
static path resolution goes through the same guarded router logic.

### Edge Runtime `vm` sandbox — traced end to end, no attacker-reachable eval

`server/web/sandbox/sandbox.ts` → `context.ts`'s only `vm` call is
`runInContext(content, ...)` where `content` is `readFileSync(filepath)` and
`filepath` comes from the **build-time** `edgeFunctionEntry`/manifest paths —
the developer's own compiled middleware bundle on disk, never a
request-derived string. Everything from the actual HTTP request (`headers`,
`url`, `body`) enters the sandbox only as **data** passed into the already-
running edge function (`params.request`), never as a string handed to `vm`.
Confirmed no other `vm`/`Function()`/`eval` call site in `server/web/sandbox/`
touches request-derived data. A VM escape here would need a bug in the
*developer's own* middleware code treating request data as code — an
application bug, not a Next.js one, and the standard framework design (data
in, never code in) holds for this version.

### `next/og` (`ImageResponse`) — no injection surface reachable

Read `server/og/image-response.ts` in full. The constructor's arguments are a
**React element tree** (JSX), not a string — `@vercel/og`'s Satori engine
walks that tree the same way React itself would, so user-supplied text
embedded as JSX children (the realistic pattern: `<div>{title}</div>` from a
`searchParams` value) is tree data, not markup to parse; there is no
HTML/SVG-string parsing step for an attacker to inject through. No `eval`,
`Function()`, or shell-out anywhere in this 528-line module pair.

### `child_process` / dynamic `require()` / dynamic `import()` — swept, all build-time or manifest-keyed

* Every `child_process`/`exec`-shaped hit in `server/` is either dev-only
  tooling (hot-reloader, source-map-from-file — not part of the production
  request path) or a `RegExp.prototype.exec()` false positive from the grep
  pattern (`app-render/dynamic-rendering.ts`, `match-bundle.ts`) — verified
  each site individually, not just by the string match.
* The only variable-argument `require()`/module-loader call reachable from a
  request (`next-server.ts:588`, `loader.load(match.definition.filename)`)
  is keyed by `match.definition.filename` — a path resolved from the
  **build-time route manifest**, not the URL string. A dynamic segment
  (`[slug]`) always maps to one compiled page file regardless of the
  runtime value of `slug`; there is no per-request-value path construction
  feeding a `require()`.

## Git-archaeology: 490 post-16.3.4 canary commits, nothing RCE/traversal-shaped

Fetched `origin/canary` live and read every commit between `v16.3.4` and
current canary by message, several keyword passes (`traversal`, `CVE`,
`security`, `inject`, `sanitiz`, `escape`, `arbitrary`, `unsafe`, `bypass`,
`symlink`, `realpath`, `\.\./`, `null.?byte`) plus a scan for any `GHSA`/`CVE`
reference. Two hits worth recording as explicitly checked and ruled out:

* **`Guard filesystem reads against unresolved symlinks (#97902)`** — looked
  exactly like the traversal-via-symlink class. Read the full commit: this is
  a **debug-only, build-time** diagnostic inside `turbo-tasks-fs`/Node File
  Trace (the bundler's own dependency-tracking correctness during `next
  build`), guarding against Turbopack mis-tracking file identity through an
  unresolved symlink — not a runtime guard on any HTTP-request-triggered file
  read. No production request path is affected.
* **`Fix HTML-limited bot matching in prerender bypass rules (#96584)`** —
  bot/crawler detection for which pages skip prerendering; an access-control
  nuance, not RCE or traversal, and not pursued further as out of the
  requested scope.

No commit in the range references a CVE/GHSA ID, and no other hit in any
keyword pass named a request-reachable file-read, deserialization, or
code-execution defect.

## Net

No new low-privilege or pre-auth RCE/path-traversal bug in Next.js 16.3.4
this round. Combined with `middleware-rce-traversal-audit-2026-09-02`'s
already-exhaustive coverage (46 middleware-bypass path forms, cross-route
Server Action binding, 33-encoding ISR cache traversal, image-cache and
`/_next/static` traversal) and `flight-argument-decoder-2026-09-02`'s
Flight-protocol deep dive, the surfaces this program would plausibly reward
for these two bug classes appear to be exhausted for this version on Linux.
The one item neither round can test — Windows-only `path.win32` semantics,
the actual mechanism behind CVE-2026-75604 — remains the most likely place a
fresh instance of this bug class still exists, but requires a Windows host.

## Files

| file | what it is |
|---|---|
| `poc/probe_standalone_static.py` | 17-encoding traversal sweep against `output: standalone`'s static file serving |
| `poc/probe_standalone_static_output.txt` | its recorded output — all 404, no traversal |

## Lab

`next@16.3.4`, Node v22.22.2. Two builds from the same `app/` tree used by
the prior round: ordinary `next start` (port 3000, unchanged) and a fresh
`output: standalone` build (`.next/standalone/server.js`, port 3010) with
`public/marker.txt` as the confined-directory canary.
