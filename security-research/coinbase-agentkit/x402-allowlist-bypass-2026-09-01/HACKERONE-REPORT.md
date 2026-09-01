# AgentKit x402 service allowlist bypass via broken prefix check (`url.startsWith`) — enables SSRF and unattended-payment redirection to attacker-controlled hosts

**Program:** Coinbase (HackerOne) — asset `https://github.com/coinbase/*` (Critical, Eligible)
**Target:** `coinbase/agentkit`, commit `455a6c5a29375de290da0f3b440119ec7f511440` (2026-08-19)
**Affected files (both language packages, identical bug):**
- `typescript/agentkit/src/action-providers/x402/utils.ts` — `isServiceRegistered()` / `isUrlAllowed()`
- `python/coinbase-agentkit/coinbase_agentkit/action_providers/x402/utils.py` — `is_service_registered()` / `is_url_allowed()`

**Class:** CWE-20 (Improper Input Validation) / CWE-668-adjacent authorization bypass via string-prefix confusion — the same bug family as the classic `startsWith(allowedOrigin)` CORS/redirect-allowlist mistakes.

**Status:** Confirmed and reproduced locally with a standalone script that runs the verbatim function body from both the TypeScript and Python source files (no repo build/install required — see PoC section). This is not a prompt-injection finding (out of scope per the repo's own `SECURITY.md`): the bug is a deterministic logic defect in the allowlist implementation itself, independent of anything an LLM decides.

## Summary

`X402ActionProvider` (both the TypeScript `@coinbase/cdp-agentkit` package and the Python `coinbase-agentkit` package) lets an operator restrict which HTTP/x402 endpoints the agent's wallet may call and pay, via a `registeredServices` allowlist:

> "Service URLs the agent can call. Only these services will be allowed for HTTP requests." — `X402Config.registeredServices` doc comment (`schemas.ts`)

This allowlist gates three actions, including one that **pays automatically with no user confirmation**:

- `make_http_request`
- `retry_http_request_with_x402`
- `make_http_request_with_x402` — explicitly documented as "This action automatically handles payments without asking for confirmation!"

The check backing all three, `isServiceRegistered()` / `is_service_registered()`, is:

```ts
// typescript/agentkit/src/action-providers/x402/utils.ts
export function isServiceRegistered(url: string, registeredServices: Set<string>): boolean {
  if (registeredServices.size === 0) {
    return false;
  }
  try {
    const parsed = new URL(url);
    const origin = parsed.origin;
    for (const registered of registeredServices) {
      // Check if origin matches or URL starts with registered prefix
      if (origin === registered || url.startsWith(registered)) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}
```

```python
# python/coinbase-agentkit/coinbase_agentkit/action_providers/x402/utils.py
def is_service_registered(url: str, registered_services: set[str]) -> bool:
    if not registered_services:
        return False
    try:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for registered in registered_services:
            if origin == registered or url.startswith(registered):
                return True
        return False
    except Exception:
        return False
```

The `url.startswith(registered)` branch does a **raw string-prefix comparison, not a origin/host boundary check**. If an operator registers a bare origin — which is exactly the format the project's own README recommends and demonstrates:

```typescript
registeredServices: [
  "https://api.example.com",
  "https://weather.x402.io"
]
```

then **any URL whose host is a dot-suffixed lookalike of a registered origin also passes the check**, because the registered string is a literal prefix of it:

```
registered:  "https://api.example.com"
attacker:    "https://api.example.com.attacker.io/steal-payment"

"https://api.example.com.attacker.io/steal-payment".startsWith("https://api.example.com")
  === true
```

`api.example.com.attacker.io` is a completely different host, fully controlled by the attacker (registerable by anyone — it's just a subdomain of `attacker.io`), yet the function returns `true` — the allowlist is bypassed.

## Impact

Any code path that ends up calling one of the three gated actions with an attacker-influenced `url` string — a user pasting/being served such a URL, content returned by `discover_x402_services` (which surfaces third-party-registered resource URLs from a public x402 discovery facilitator), or any other source of a URL string reaching the tool — defeats the allowlist entirely. Concretely:

- **`make_http_request` / `retry_http_request_with_x402`**: the agent's wallet-bearing process sends an HTTP request (potentially carrying headers/body content) to an attacker-controlled endpoint that the operator's configuration was specifically supposed to exclude — an SSRF-style egress-allowlist bypass.
- **`make_http_request_with_x402`**: the same bypass, but on the action explicitly documented to pay automatically with no human confirmation step. A URL that superficially "starts with" a registered, trusted origin is treated as fully trusted, and if it serves a valid x402 `402 Payment Required` challenge, the agent will autonomously pay it (up to `maxPaymentUsdc`) believing it is paying an approved service, when it is in fact paying an attacker-controlled endpoint.

This directly undermines the one explicit security control this feature provides, and does so identically in **both** the TypeScript and Python packages (the Python code is a line-for-line port of the same broken logic), indicating a shared design defect rather than an isolated typo.

## Why this is not a prompt-injection finding

`SECURITY.md` states: "Prompt injection is inherent to giving an AI agent a wallet and is not treated as a vulnerability in AgentKit itself." This report does not rely on convincing or manipulating the LLM's judgment in any way. The defect is entirely mechanical: given any URL string as input — regardless of how it arrived — `isServiceRegistered()` returns an objectively wrong answer whenever that string is prefixed by a registered origin. The bug is in the deterministic allowlist implementation, not in agent reasoning.

## Suggested fix

Replace the prefix check with a real origin/path-boundary comparison, e.g.:

```ts
function isServiceRegistered(url: string, registeredServices: Set<string>): boolean {
  const parsed = new URL(url);
  for (const registeredRaw of registeredServices) {
    const registered = new URL(registeredRaw);
    if (parsed.origin !== registered.origin) continue;
    // If a path prefix was registered, require it to end on a path boundary.
    if (
      parsed.pathname === registered.pathname ||
      parsed.pathname.startsWith(
        registered.pathname.endsWith("/") ? registered.pathname : registered.pathname + "/",
      )
    ) {
      return true;
    }
  }
  return false;
}
```

i.e. parse *both* sides as URLs and compare `origin` (and, if a path was registered, require the remainder to start with `/`) instead of doing a raw string `startsWith` on the two original strings.

## Proof of Concept

Two standalone scripts are included, each containing the **verbatim function body** copied from the corresponding source file (no repo build/install needed to reproduce):

- `poc_x402_allowlist_bypass.js` — TypeScript/`isServiceRegistered` logic, run with plain Node.js
- `poc_x402_allowlist_bypass.py` — Python/`is_service_registered` logic, run with plain Python 3

Both scripts configure `registeredServices`/`registered_services` exactly as shown in the project's own README example (`["https://api.example.com", "https://weather.x402.io"]`), then show that `https://api.example.com.attacker.io/steal-payment` — a different host, confirmed via `URL(...).hostname`/`urlparse(...).netloc` — is nonetheless reported as registered/allowed.

```
$ node poc_x402_allowlist_bypass.js
...
attacker-controlled URL: https://api.example.com.attacker.io/steal-payment
  isServiceRegistered -> true
...
Same host? false

[CONFIRMED] allowlist bypass: attacker-controlled host passes isServiceRegistered()

$ python3 poc_x402_allowlist_bypass.py
...
attacker-controlled URL: https://api.example.com.attacker.io/steal-payment
  is_service_registered -> True
...
Same host? False

[CONFIRMED] allowlist bypass: attacker-controlled host passes is_service_registered()
```

## Severity assessment

Per the program's general severity language, I'd place this at **High**, not Critical: exploitation requires (a) the operator to have configured `registeredServices` (the allowlist is a no-op / fails closed when empty, so this only matters for deployments that opted into it — which the README actively encourages), and (b) some attacker-influenced URL string to reach one of the three gated actions. Given both conditions are realistic and require no special access (registering a lookalike domain is trivial and free; a URL reaching the tool can happen via ordinary user input or the built-in service-discovery flow), this is not a theoretical concern, but it does require those two realistic preconditions rather than being exploitable with zero preconditions against every deployment — hence High rather than Critical, per the "requires additional — yet realistic — conditions" language.

## Scope note

This report targets `coinbase/agentkit` under the `https://github.com/coinbase/*` scope entry (Critical, Eligible). It is a pure application-logic bug in TypeScript/Python source code, not a Web3/smart-contract finding, so it is squarely a HackerOne-appropriate report rather than a Cantina one.
