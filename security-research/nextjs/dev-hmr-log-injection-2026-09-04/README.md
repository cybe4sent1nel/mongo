# Next.js `next dev` — unauthenticated cross-site injection into the HMR log-forwarding channel: forged log entries, arbitrary ANSI/OSC terminal-escape injection, and clipboard hijack

**Component** `packages/next/src/server/dev/hot-reloader-turbopack.ts` (the `'browser-logs'` HMR client→server message, `client.addEventListener('message', ...)`), sinking into `packages/next/src/server/dev/browser-logs/receive-logs.ts` (`handleLog`) and `packages/next/src/server/dev/browser-logs/file-logger.ts`
**Reached via** `packages/next/src/server/lib/router-utils/block-cross-site-dev.ts` — the same `isInternalEndpoint()` substring bypass from my `dev-csrf-ignorelist-substring-bypass-2026-09-04` report, which is what makes this reachable cross-site with a hostile `Origin` at all
**Target** `next@16.3.4` (`299180d331`), `next dev`, Turbopack (webpack's `getHotReloaderWebSocketServer` has the identical `'browser-logs'` case — not independently re-verified live, but same source pattern)
**Class** CWE-117 (log injection / forging log entries) + CWE-150 (improper neutralization of escape sequences), reaching CWE-1284-adjacent impact — arbitrary terminal-escape execution in the developer's own terminal, including an OSC 52 clipboard write
**Status** Reproduced end to end with real headless Chromium from a genuinely cross-site origin, raw bytes captured on both sides of the one relevant config flag.

## Summary

Next.js's dev overlay forwards the browser's own `console.*` calls to the terminal running `next dev`, so a developer sees `[browser] ...` lines alongside their server logs. The forwarding channel is a `'browser-logs'` message sent over the HMR WebSocket (`/_next/hmr`). The server-side handler in `hot-reloader-turbopack.ts` does this unconditionally for **any** connected client:

```ts
case 'browser-logs': {
  await receiveBrowserLogsTurbopack({
    entries: parsedData.entries,
    router: parsedData.router,
    sourceType: parsedData.sourceType,
    project, projectPath, distDir,
    config: (nextConfig.logging && nextConfig.logging.browserToTerminal) || false,
  })
  break
}
```

`entries`, `router`, and `sourceType` come straight from the WebSocket message with **no check that this connection belongs to the page currently being developed** — any client that can open the socket at all can send this message, and it is processed identically to a real one. `sourceType` is even taken at face value to choose the `[server]`/`[browser]` prefix and the `"source"` field written to disk — so the attacker picks how their forged entry is attributed.

Reaching the socket cross-site is exactly the CSRF gap in my separate `dev-csrf-ignorelist-substring-bypass-2026-09-04` report: `isInternalEndpoint()` skips the whole `blockCrossSiteDEV` check for any URL whose query string contains `/_next/image`, so `ws://victimdev.test:PORT/_next/hmr?x=/_next/image` opens from a hostile `Origin` with no further gate. This report is the payload that bypass carries once the socket is open — a different, independent bug (a missing per-message authorization/attribution check on the log-forwarding channel), reported separately because it stands on its own even against a hypothetical other route into the socket.

The message reaches two sinks, and I checked both configurations to be precise about what each requires:

### 1. The dev log file — on by default, no opt-in required

`experimental.mcpServer` defaults to `true`, and `FileLogger.initialize()` activates unconditionally whenever it is:

```ts
// FileLogger.initialize()
if (!this.mcpServerEnabled) { return }   // mcpServerEnabled defaults true
...
fs.writeFileSync(this.logFilePath, '')   // .next/dev/logs/next-development.log
```

So **with zero configuration**, one hidden cross-site WebSocket message gets a fully-fabricated entry written to `.next/dev/logs/next-development.log`, falsely attributed as server-sourced:

```json
{"timestamp":"00:00:06.056","source":"Server","level":"LOG","message":"]0;PWNED-BY-CROSS-SITE-PAGE[2J[H*** THIS LINE WAS INJECTED BY attacker.test VIA A FORGED HMR MESSAGE ***\n]52;c;cHduZWQtY2xpcGJvYXJkLXdyaXRl"}
```

This file is exactly what the dev MCP server's `get_logs` tool (see `../dev-csrf-ignorelist-substring-bypass-2026-09-04`, already shown reachable through the same CSRF gap) tells an AI coding assistant to read directly — so a cross-site attacker can plant arbitrary, fabricated content into the log an AI dev-tool agent is documented to consume, with no interaction beyond a page load.

### 2. The developer's live terminal — the documented `logging.browserToTerminal` opt-in, with real ANSI/OSC execution

When a project sets `logging: { browserToTerminal: true }` (a real, documented Next.js feature for seeing browser console output in the terminal), the exact same forged message is written with `forwardConsole[method](...)`, which bottoms out in Node's own `console.log` — **no stripping of control characters anywhere in the pipeline** (`stripFormatSpecifiers` only touches `%s`/`%d`-style printf specifiers, never ESC bytes). The raw bytes that hit the dev server's stdout, captured by redirecting it to a file so nothing is lost:

```
[server] <ESC>]0;PWNED-BY-CROSS-SITE-PAGE<BEL><ESC>[2J<ESC>[H*** THIS LINE WAS INJECTED BY attacker.test VIA A FORGED HMR MESSAGE ***
<ESC>]52;c;cHduZWQtY2xpcGJvYXJkLXdyaXRl<BEL>
```

Decoded: `ESC ]0;...BEL` sets the terminal tab/window title; `ESC [2J` `ESC [H` clears the screen and homes the cursor (erasing legitimate output, then printing whatever text the attacker likes in its place); `ESC ]52;c;<base64>BEL` is **OSC 52 — write to the system clipboard**. In any terminal emulator that honours OSC 52 (iTerm2, kitty, foot, WezTerm, several tmux configurations, and others), this silently overwrites the developer's clipboard with attacker-chosen data. That's a documented stepping stone toward getting a developer to paste-and-run a command they never typed themselves — the terminal-injection→clipboard-hijack→social-engineered-execution chain is a recognized attack pattern, not a hypothetical one.

## Reproduction

```
node poc/ws_log_inject.js       # raw WS client: opens the socket via the bypass, sends the forged message
```

`poc/log_inject.html` is the real cross-site attacker page used for the browser-based run (real headless Chromium, `attacker.test` → `victimdev.test`, matching the lab setup in my other two reports this round). `poc/evidence_run.txt` has the full annotated run: the default-config file-log injection, then the same message against a server with `logging.browserToTerminal: true`, with the raw byte dump proving nothing is escaped before it reaches stdout.

## Impact

* **By default, no configuration required:** an unauthenticated, cross-site attacker can inject arbitrary fabricated log entries into `.next/dev/logs/next-development.log`, falsely attributed as server- or browser-sourced, including raw control characters. This is the exact file the dev MCP server's documented `get_logs` tool points AI coding agents at.
* **With the documented `logging.browserToTerminal` feature enabled**, the same attacker writes arbitrary ANSI/OSC escape sequences directly to the developer's live terminal: confirmed a terminal-title spoof, a screen-clear-and-replace (letting an attacker present fabricated text as if it were genuine `next dev` output), and an OSC 52 clipboard write of attacker-chosen data. This is real code running in the developer's terminal emulator's escape-sequence interpreter, not just text — the ceiling depends on which terminal emulator is in use, and I did not have a specific known-vulnerable emulator on hand to push further than the clipboard-write demonstration, so I am stopping at the verified primitive rather than claiming a specific one-shot shell.
* Realistic exposure matches every other finding in this round: a developer running `next dev` while browsing the web in the same browser, the exact scenario `blockCrossSiteDEV`/`allowedDevOrigins` exist to protect.

## What I checked and did not find

* No sanitization anywhere in `receive-logs.ts` strips or escapes ANSI/control characters before they reach `console.log`/`process.stdout` — checked every code path (`prepareConsoleArgs`, `prepareConsoleErrorArgs`, `formatConsoleArgsForFileLogging`, `handleDir`'s `process.stdout.write` capture) and `stripFormatSpecifiers` explicitly only handles `%`-prefixed printf tokens.
* I did not find a way to make the server **re-parse or execute** the injected string itself (e.g. no `eval`/`Function` sink downstream of `handleLog`) — the file-log sink is a plain `JSON.stringify`+append, and the terminal sink is a plain `console.log`. The escalation path is entirely through the *terminal emulator's* own escape-sequence interpreter (or an AI agent's own handling of the log file's content), not through Next.js executing anything itself — stated precisely so the report doesn't round up to more than what's demonstrated.

## Scope

* **`next dev` only**, gated on reaching the HMR WebSocket, which is dev-server-only infrastructure (see the companion CSRF report for exactly where `blockCrossSiteDEV` is wired in). Production (`next start`) has no HMR socket.
* The fix most directly on point: validate that a `'browser-logs'` message actually originated from a client the server itself is tracking for the current render (e.g. tie it to the `htmlRequestId` the server already assigns at upgrade time) rather than accepting `sourceType`/`router`/arbitrary log content from any connected socket at face value. Stripping ANSI/control characters before writing to `process.stdout` (or documenting that `browserToTerminal` inherits the trust level of whatever the browser sends) would independently close the terminal-injection half regardless of the authorization question.

## Files

| file | what it is |
|---|---|
| `poc/ws_log_inject.js` | raw Node `ws` client: opens the HMR socket via the CSRF bypass, sends the forged `browser-logs` message |
| `poc/log_inject.html` | the real cross-site attacker page used for the browser-based run |
| `poc/evidence_run.txt` | full annotated run: default-config file injection, then the raw-byte terminal injection with `logging.browserToTerminal: true` |

## Lab

`next@16.3.4`, Node v22.22.2, `next dev` on port 3020. Chromium 1194 (Playwright), headless, `--no-proxy-server` (this container's outbound proxy otherwise intercepts `ws://`, see the companion CSRF report). `/etc/hosts` maps `attacker.test`/`victimdev.test` to `127.0.0.1` for a genuine cross-site test. Two clean server runs recorded: default `next.config.js` (`module.exports = {}`) for the file-log case, and `logging: { browserToTerminal: true }` for the live-terminal case — both with `.next` removed and rebuilt between runs so neither result carries over stale state.
