# coinbase/agentkit — x402 service allowlist bypass

Confirmed, reproduced finding against `coinbase/agentkit` (commit `455a6c5a293`).

`X402ActionProvider`'s `registeredServices` allowlist — the control that's supposed to restrict
which endpoints the agent's wallet may call/pay via `make_http_request`,
`retry_http_request_with_x402`, and the auto-pay `make_http_request_with_x402` — is checked with
a raw `url.startsWith(registered)` string-prefix test (both the TypeScript and Python packages,
identical logic). A registered origin like `"https://api.example.com"` (the exact format shown in
the project's own README) is a literal string-prefix of any attacker-registered lookalike host such
as `"https://api.example.com.attacker.io/..."`, so the allowlist accepts a completely different,
attacker-controlled host as "registered."

This is a deterministic code bug in the allowlist implementation, not a prompt-injection issue
(explicitly out of scope per the repo's `SECURITY.md`) — no LLM reasoning needs to be manipulated
for the check to return the wrong answer.

See `HACKERONE-REPORT.md` for the full write-up, impact analysis, and suggested fix.

## Files

- `HACKERONE-REPORT.md` — full report
- `poc_x402_allowlist_bypass.js` — standalone Node.js PoC (verbatim TS function body)
- `poc_x402_allowlist_bypass.py` — standalone Python 3 PoC (verbatim Python function body)

Both scripts run standalone with no repo build/install:

```
node poc_x402_allowlist_bypass.js
python3 poc_x402_allowlist_bypass.py
```
