# mongodb-mcp-server: checked for a sibling of CVE-2025-53967 (Figma MCP curl command injection)

**Status: checked, not vulnerable to this specific class. Clean negative result.**

## The bug being checked for

CVE-2025-53967 (Framelink Figma MCP Server < 0.6.3, CVSS 3.1 8.0 High,
`AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N`): the server's `fetchWithRetry` helper
(`src/utils/fetch-with-retry.ts`) built a `curl` command line by string-concatenating
attacker-supplied input, and executed it via a shell — shell metacharacters in that input let an
unauthenticated network attacker run arbitrary OS commands with the MCP process's privileges.
The general shape: an MCP server's tool-call handler needs to fetch a URL/resource server-side,
and does it by shelling out to an external binary (`curl`) with request data spliced into the
command string, instead of using an in-process HTTP client.

## What was checked in `mongodb-js/mongodb-mcp-server`

Cloned fresh (`main`, commit `f64f4e52e5f5dab7a95834ec051fd013235b5ca7`, 2026-08-27).

1. **How does this server make outbound HTTP requests?**
   `packages/fetch/src/proxyFetch.ts` — the shared HTTP client used across the server (Atlas API
   calls, any outbound fetch) is built on `@mongodb-js/devtools-proxy-support`'s `createFetch()`,
   which wraps Node's native `fetch`/`undici` with proxy and system-CA support. It's an in-process
   HTTP client call, not a subprocess. There is no `curl` (or any other external binary) being
   invoked to perform a fetch anywhere in this path — so there's no shell-command-string-building
   step for attacker-controlled input to ever reach in the first place. This is the key structural
   difference from the Figma MCP bug: the vulnerability class requires a shell command being
   assembled from untrusted input; if outbound requests never go through a shell, the class
   doesn't apply.

2. **Does anything else in the server shell out to an external process based on tool-call input?**
   Searched the whole monorepo (`packages/*`) for `child_process`, `execSync`, `execFile`,
   `spawn(`, `shell: true`, `execa`, `shelljs`, `cross-spawn`. Every hit is confined to
   build/release tooling and local dev/setup scripts that a developer runs themselves — none are
   reachable via a request to a running MCP server instance:
   - `packages/scripts/src/*` — release-notes generation, SBOM/dependency reporting, UI codegen
     (build-time only).
   - `packages/setup/src/aiTool.ts`, `installSkills.ts` — local CLI setup helpers a user runs to
     configure their own editor/IDE integration, not server request handlers.
   - `packages/mongodb-mcp-server/scripts/createMcpb.ts` — packaging script.
   - `packages/mongodb-mcp-server/e2e-tests/e2eUtils.ts` — test harness only.
   No `execa`/`shelljs`/`cross-spawn` dependency is even present in `package.json`.

## Conclusion

No, this server isn't prone to the Figma MCP bug's specific mechanism: it doesn't shell out to
`curl` or any other external binary to fetch anything on a tool call's behalf, so there is no
attacker-controlled-string-into-a-shell-command step anywhere in its live request-handling code.
The only subprocess invocations in the whole repository are local, developer-run build/setup/test
scripts, not something a remote MCP client request can reach.

This doesn't rule out other, differently-shaped injection risks in this server (e.g., how
tool-call parameters flow into MongoDB queries/aggregation pipelines, or how a user-supplied
connection string is validated) — those are separate bug classes from CVE-2025-53967's shell
command injection and weren't in scope for this specific check.
