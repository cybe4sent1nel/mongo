# Next.js `next dev` — CSRF bypass silently activates the Node.js inspector (unauthenticated remote code execution primitive)

**Component** `packages/next/src/server/lib/router-utils/block-cross-site-dev.ts` (`blockCrossSiteDEV`), gating `packages/next/src/next-devtools/server/attach-nodejs-debugger-middleware.ts` (`/__nextjs_attach-nodejs-inspector`)
**Target** `next@16.3.4` (`299180d331`), `next dev` only — confirmed absent from `next start`/production (see §Scope)
**Class** CWE-352 (CSRF) leading to CWE-306 (missing authentication for a critical function) / an unauthenticated trigger for a full remote-code-execution primitive (the V8 Inspector Protocol)
**Status** Empirically reproduced end-to-end against a real headless-Chromium browser, not simulated headers. **Not a duplicate** of the already-patched `CVE-2026-27977` / `GHSA-jcc7-9wpm-mj36` — see §Not a duplicate for the precise distinction, since both live in the same function.

## Summary

`next dev` exposes `/__nextjs_attach-nodejs-inspector`, an internal endpoint whose entire job is to open the Node.js V8 Inspector Protocol debugger — the same protocol `node --inspect` exposes, which lets anyone who can connect to it run arbitrary JavaScript in the server process via `Runtime.evaluate`. This is guarded by `blockCrossSiteDEV()`, a purpose-built CSRF check applied to every `/__nextjs_*` and `/_next/*` internal endpoint.

That check has a logic gap: for a request whose shape isn't `sec-fetch-mode: no-cors` + `sec-fetch-site: cross-site` (i.e. anything that isn't a `<script>`/`<img>`-style subresource load), it falls back to checking the `Origin` header — and if `Origin` is **absent entirely**, the function returns `false` (not blocked), reasoning (per its own comment) that "those are just GET requests from same-site." That reasoning is correct for `fetch()`/XHR, which always send `Origin` cross-origin. It is **not** correct for a plain cross-site **navigation** — a `<iframe src="...">`, a top-level redirect, or a GET `<form>` submission — which real browsers send with **no `Origin` header at all**.

**Confirmed live, with real headless Chromium:** a page on one origin (`attacker.test`) containing nothing but a hidden `<iframe src="http://victimdev.test:PORT/__nextjs_attach-nodejs-inspector">` causes the Node.js inspector to be opened on the victim's machine — silently, with no visible effect on the attacker's page, no user interaction beyond loading it, and no prior state (the inspector was not running before). The response also contains the `webSocketDebuggerUrl`/session UUID needed to connect and drive the debugger to code execution.

## Reproduction

```
DEV_PORT=3020

# 1. Baseline: inspector is not running.
curl http://127.0.0.1:9229/json/list
# -> connection refused

# 2. A page on a genuinely different site (attacker.test) loads:
#      <iframe src="http://victimdev.test:DEV_PORT/__nextjs_attach-nodejs-inspector">
#    visited in real Chromium.

# 3. Inspector is now open, with a live debug session:
curl http://127.0.0.1:9229/json/list
# -> [ { "webSocketDebuggerUrl": "ws://127.0.0.1:9229/<uuid>", ... } ]
```

`poc/attack.html` is the exact page used; `poc/drive_chromium.js` drives it headlessly; `poc/capture_proxy.js` is a transparent TCP relay placed in front of the real `next dev` server so the **exact bytes** `next dev` received could be captured without touching Next.js itself (`poc/captured_requests.txt`). `poc/evidence_run.txt` is the full annotated before/after run. `poc/run_poc.sh` reproduces the curl-only half (control + bypass + inspector-state check) against a running `next dev`; the browser-navigation half needs Playwright/Chromium, hence the separate `drive_chromium.js`.

The captured request `next dev` actually received:

```
GET /__nextjs_attach-nodejs-inspector HTTP/1.1
Host: victimdev.test:3021
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) ... HeadlessChrome/141.0.0.0 ...
Referer: http://attacker.test:8899/
```

No `Origin` header, confirming the exact code path this exploits.

### Two things this rules out, checked directly rather than assumed

* **The topology matters.** An earlier run using `127.0.0.1:PORT_A` (attacker) against `127.0.0.1:PORT_B` (victim) — same IP, different ports — got `Sec-Fetch-Site: same-site` from Chromium, since the "site" concept is host-based, not port-based, and both `127.0.0.1`/`localhost` are also explicitly in `blockCrossSiteDEV`'s own always-allowed list. That configuration is not a valid test. The reproduction above uses two distinct hostnames (`attacker.test`, `victimdev.test`, both mapped to `127.0.0.1` via `/etc/hosts` purely to make the lab work) so the browser genuinely treats them as cross-site — matching a real attacker on the public internet targeting a developer's local `next dev`.
* **A cross-site `<form method=POST>` submission is correctly blocked.** The same page also auto-submits a POST to `/_next/mcp` (the dev-tools MCP server, gated by the identical `blockCrossSiteDEV` check). Real Chromium *does* send an `Origin` header for cross-site POST navigations (`Origin: http://attacker.test:8899` — captured verbatim, see `poc/captured_requests.txt`), and the request is correctly rejected with `403`. This confirms the gap is specific to GET/navigation-shaped requests without a body, not a wholesale failure of the check — and rules out the MCP endpoint (which can execute arbitrary developer-defined tools) as a route past this specific bug.

## Not a duplicate: CVE-2026-27977 vs. this

`CVE-2026-27977` / `GHSA-jcc7-9wpm-mj36` ("null origin can bypass dev HMR websocket CSRF checks") already patched a related gap in this exact function: a request with the **literal string** `Origin: null` (sent by sandboxed iframes / opaque-origin contexts) was being treated the same as "no origin," and let through. The code now visibly special-cases this:

```ts
const parsedOrigin =
    originHeader && originHeader !== 'null'
      ? parseUrl(originHeader)
      : originHeader
```

— `originHeader === 'null'` still takes the "else" branch, but `originLowerCase` ends up as the **string** `'null'` (not `undefined`), which correctly fails `isCsrfOriginAllowed('null', ...)` and gets blocked. Verified this directly: sending `Origin: null` reproduces a `403`, confirming the patched case holds.

**This report is the other case the patch didn't reach: `Origin` header genuinely absent (no header at all, not the string `"null"`).** Tracing the same few lines for that input: `rawOrigin` is `undefined` → `originHeader` is `undefined` → the ternary's condition `originHeader && ...` is falsy → `parsedOrigin = originHeader` = `undefined` → `originLowerCase = undefined` → the final `originLowerCase !== undefined` check is `false` → the whole expression short-circuits to `false` → **not blocked**. This is a different value reaching the same check by a different route, not a regression of the `'null'`-string fix — the code comment ("Allow requests with no origin since those are just GET requests from same-site") shows this was a **deliberate design assumption**, one that holds for `fetch()`/XHR but not for navigations, which is exactly what real browsers do differently and what this report demonstrates with actual Chromium traffic.

## Impact

* **Confirmed:** an attacker-controlled webpage, loaded in any browser on a machine currently running `next dev`, silently activates the Node.js V8 Inspector Protocol debugger with no interaction beyond the page loading — bypassing a CSRF control purpose-built to prevent exactly this class of cross-site access to internal dev-server endpoints.
* **Confirmed:** the same response discloses the exact `webSocketDebuggerUrl` (including the per-session UUID) needed to drive that debugger to `Runtime.evaluate`-based code execution, to whichever party can read the HTTP response.
* **The remaining gap to a fully self-contained, one-click "attacker gets a shell" chain:** the vector that bypasses the check (a plain cross-site navigation — iframe or top-level) is, by the ordinary Same-Origin Policy, not one whose response body the *initiating* page's own script can read back (a navigated cross-origin document's content isn't exposed to `window`/`document` properties the opener can access, and a bare-GET navigation carries no CORS headers for `fetch()` to read either). I confirmed the WebSocket endpoint itself is not exploitable without the exact UUID (a wrong path is rejected: `curl` upgrade attempt against a guessed path returned HTTP 400). I was not able to identify a second, independent primitive that closes this specific gap within this engagement — so this report stops at the honestly-verified boundary: **an unauthenticated CSRF-triggered activation of a full-RCE-capable debug interface, plus disclosure of its connection secret to whatever can read the response** (same-site pages, a misconfigured `allowedDevOrigins` entry, or any additional local read-primitive an attacker might separately have), rather than a claimed one-request full RCE chain. I'd rather report the verified boundary precisely than round up to "trivial RCE" without a working end-to-end shell.

## Scope

* **`next dev` only.** `getAttachNodejsDebuggerMiddleware` is wired up only from `hot-reloader-webpack.ts`/`hot-reloader-turbopack.ts`, and `blockCrossSiteDEV` is called only from `router-server.ts` — all dev-server-only files, confirmed by grep across `packages/next/src/server`. Production (`next start`, `output: standalone`) does not register this endpoint at all.
* Realistic exposure: developers routinely run `next dev` for extended sessions while also browsing the web in the same browser/machine — the exact threat model CSRF targets. This is also the documented threat model `blockCrossSiteDEV` and the prior `allowedDevOrigins`/CVE-2026-27977 fix were both built to address, so this sits squarely in-scope for the same control.

## Files

| file | what it is |
|---|---|
| `poc/attack.html` | the malicious page: hidden cross-site iframe at the inspector endpoint, plus a form-POST control against `/_next/mcp` |
| `poc/drive_chromium.js` | drives `attack.html` in real headless Chromium via Playwright |
| `poc/capture_proxy.js` | transparent TCP relay in front of `next dev`, logging the exact bytes received with zero modification to Next.js |
| `poc/captured_requests.txt` | the raw captured requests from the Chromium run |
| `poc/evidence_run.txt` | full annotated before/after run (inspector closed → open, with the raw requests and commentary) |
| `poc/run_poc.sh` | the curl-only half of the reproduction (control, bypass, inspector-state check) — needs a running `next dev` plus the two `/etc/hosts` entries noted in the script |

## Lab

`next@16.3.4`, Node v22.22.2, `next dev` on port 3020 (fronted by `capture_proxy.js` on 3021 purely to capture wire bytes — Next.js itself was never modified or instrumented). Chromium 1194 via Playwright, headless. `/etc/hosts`: `attacker.test` and `victimdev.test` both mapped to `127.0.0.1`, needed so Chromium's site-boundary computation treats the two as genuinely cross-site (same-IP-different-port is not sufficient, as documented above).
