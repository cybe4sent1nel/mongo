# Title

AgentKit x402 provider — the `maxPaymentUsdc`/`max_payment_usdc` spending cap is never enforced on `make_http_request_with_x402`, the action explicitly documented as paying autonomously with no confirmation step, in both the TypeScript and Python packages

## Status note / scope

Found while directly auditing `coinbase/agentkit` at the current public `main` (commit `2e6dbaf725b9ec5f3b53003278100b0e655c214d`, 2026-09-03) for fresh, still-present high/critical bugs, per the user's request after report #3989008 (a different x402 bug — the `isServiceRegistered()` prefix-check allowlist bypass) was closed as a duplicate of #3865773 and "already found internally." This is a **different function, different mechanism, same provider**: it is not the allowlist bug, and it is not fixed by whatever internal fix Coinbase applies for the allowlist issue, since the allowlist and the spending cap are two independent, separately-configured guardrails (`registeredServices` vs. `maxPaymentUsdc`) that this provider advertises as its safety model.

## Summary

`X402Config.maxPaymentUsdc` (TS) / `X402ActionProviderConfig.max_payment_usdc` (Python) is documented as "Maximum payment in USDC whole units" — the one guardrail an operator has against the agent overspending on x402-payable requests. Three actions exist:

- `make_http_request` — no payment, just probes for a 402.
- `retry_http_request_with_x402` (TS) / `retry_with_x402` (Python) — the "review first" two-step flow.
- `make_http_request_with_x402` — documented in its own action description as:
  > "WARNING: This action automatically handles payments without asking for confirmation! ... No chance to review payment details before paying - No confirmation step - Automatic payment processing"

**`make_http_request_with_x402` never references `maxPaymentUsdc`/`max_payment_usdc` anywhere in its body, in either language.** I grepped both function bodies in full:

```
$ awk '/async makeHttpRequestWithX402/,/^  \}$/' x402ActionProvider.ts | grep -n "maxPaymentUsdc\|validatePaymentLimit\|config\."
14:            suggestion: this.config.allowDynamicServiceRegistration
```

The only `this.config.*` reference in the entire function is `allowDynamicServiceRegistration` (used in an error-message suggestion). The Python equivalent (`make_http_request_with_x402`, `x402_action_provider.py:577-676`) has the identical shape: it checks the allowlist, checks the wallet provider type, then goes straight to `x402_requests(client)` — `max_payment_usdc` never appears anywhere in the function.

Compare this to `retryWithX402`/`retry_with_x402`, which *does* call `validatePaymentLimit(paymentAmount, this.config.maxPaymentUsdc)` before proceeding — the cap exists as working code, it's simply never applied to the one-step, no-confirmation action that most needs it. Whoever wrote the two-step flow's check apparently didn't carry it over when writing the one-step flow (or the one-step flow was added later without revisiting it).

## The two-step flow's check is also not real protection

Even where the check exists (`retryWithX402`), it doesn't constrain what actually gets paid:

```ts
// x402ActionProvider.ts:406-424 — validates a value the AGENT supplied as an argument
const paymentAmount =
  args.selectedPaymentOption.maxAmountRequired ??
  args.selectedPaymentOption.amount ??
  args.selectedPaymentOption.price ??
  "0";
const paymentValidation = validatePaymentLimit(paymentAmount, this.config.maxPaymentUsdc);
if (!paymentValidation.isValid) { /* reject */ }

...

// x402ActionProvider.ts:463-465 — the ACTUAL payment
const client = await this.createX402Client(walletProvider);
const fetchWithPayment = wrapFetchWithPayment(fetch, client);
...
const response = await fetchWithPayment(finalUrl, { method, headers, body });
```

`args.selectedPaymentOption` is metadata the *agent* captured from an earlier, separate `make_http_request` call — it's the price the server advertised *then*. The amount actually paid on this call is whatever `wrapFetchWithPayment`'s autonomous re-fetch-and-pay logic sees *now*, on a fresh request to the same URL. I installed the real `@x402/fetch@2.7.0` package this repo depends on (per `typescript/agentkit/package.json`, `"@x402/fetch": "^2.7.0"`) and read its published type declarations directly:

```ts
// node_modules/@x402/fetch/dist/cjs/index.d.ts
/**
 * ...It will:
 * 1. Make the initial request
 * 2. If a 402 response is received, parse the payment requirements
 * 3. Create a payment header using the configured x402HTTPClient
 * 4. Retry the request with the payment header
 * ...
 */
declare function wrapFetchWithPayment(
  fetch: typeof globalThis.fetch,
  client: x402Client | x402HTTPClient
): (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
```

`wrapFetchWithPayment` takes only `fetch` and a signing `client` — there is no amount, no cap, nothing that could constrain which `PaymentRequirements` get paid. It pays whatever the server presents at call time. So a registered endpoint (or one that reaches the allowlist via the separately-reported prefix-check bypass) that returns a cheap 402 on the first probe and a *different, larger* 402 on the retry gets paid the larger amount — `paymentValidation` above checked a number that has no relationship to what `wrapFetchWithPayment` actually authorizes.

## The SDK has the right extension point; AgentKit doesn't use it

I also installed `@x402/core@2.7.0` (the client `x402Client` comes from) and read its type declarations:

```ts
// node_modules/@x402/core/dist/cjs/client/index.d.ts
type PaymentPolicy = (x402Version: number, paymentRequirements: PaymentRequirements[]) => PaymentRequirements[];
...
registerPolicy(policy: PaymentPolicy): x402Client;
```

`x402Client.registerPolicy()` is exactly the hook this provider needs: a `PaymentPolicy` gets to see and *filter* the list of acceptable payment requirements before one is selected and paid. This is the SDK-documented way to enforce "never pay more than X." `createX402Client` (`x402ActionProvider.ts:844-869`) only ever calls `registerExactEvmScheme`/`registerExactSvmScheme` (which register signing capability) — `registerPolicy` is never called anywhere in the file. The capability to fix this correctly and robustly already exists in the dependency; the provider simply never wires it in.

## Impact

- **`make_http_request_with_x402`**: any registered x402 service can charge the agent's wallet an amount with **no ceiling at all**. The operator's `maxPaymentUsdc` configuration — the only spending control this provider offers, and the reason a cautious operator would reach for the two-step flow instead — is silently inapplicable to the action explicitly marketed as safe to use for automatic payments.
- **`retry_http_request_with_x402`**: the cap is checked against stale, agent-supplied data rather than the live payment requirement the SDK will actually act on, so a service that advertises a low price on the initial probe and a higher price on the paid retry is not caught by it either.
- Both are directly reachable by an operator's own configured/registered endpoint behaving unexpectedly (compromised, buggy, or simply pricing dynamically) — no separate vulnerability (like the prefix-check allowlist bypass) is required to trigger this; it's a property of every registered service, by design of how the two functions are wired.
- This is a real-funds, no-human-in-the-loop primitive: Coinbase's own severity rubric calls out "Unauthorized access to Coinbase-owned hot/cold wallet assets" (Extreme) and fund-loss scenarios generally as top-tier; this is the AgentKit-side analog for whichever wallet the operator has connected — an unbounded autonomous spend with the documented safety knob disconnected.

## Weakness

CWE-841 (Improper Enforcement of Behavioral Workflow) / CWE-20 (Improper Input Validation) — a documented spending-limit control is implemented for one code path and never applied to the sibling path that needs it most, and even where implemented, validates the wrong data.

## Component / Version

- Repository: `coinbase/agentkit`
- Confirmed present on `main` (commit `2e6dbaf725b9ec5f3b53003278100b0e655c214d`, 2026-09-03)
- Files:
  - `typescript/agentkit/src/action-providers/x402/x402ActionProvider.ts` — `makeHttpRequestWithX402` (~line 570-635, no `maxPaymentUsdc` reference), `retryWithX402` (~line 377-460, checks stale data), `createX402Client` (~line 844-869, no `registerPolicy` call)
  - `python/coinbase-agentkit/coinbase_agentkit/action_providers/x402/x402_action_provider.py` — `make_http_request_with_x402` (line 577-676, no `max_payment_usdc` reference), `retry_with_x402` (~line 383, checks stale data)
- Confirmed against the real `@x402/fetch@2.7.0` and `@x402/core@2.7.0` packages this repo pins (`typescript/agentkit/package.json`), installed and read directly rather than assumed

## Suggested fix

In `createX402Client`, register a `PaymentPolicy` that filters out any `PaymentRequirements` above the configured cap, e.g.:

```ts
client.registerPolicy((_version, requirements) =>
  requirements.filter(r => isWithinUsdcLimit(r, this.config.maxPaymentUsdc, walletProvider)),
);
```

so the SDK itself can never select an over-the-limit requirement to pay, in *either* `makeHttpRequestWithX402` or `retryWithX402` — this also removes the need for the local, disconnected `validatePaymentLimit` check in `retryWithX402`, since the real constraint would live where the payment is actually decided. Apply the equivalent on the Python side (`x402_requests`/`x402Client` expose the same policy mechanism per the same SDK family).

## Secondary observation (weaker, not filing as primary)

`EnsoActionProvider.route()` (`typescript/agentkit/src/action-providers/enso/ensoActionProvider.ts:86`) validates that a route returned by the Enso aggregator API starts with an expected function selector (`ENSO_ROUTE_SINGLE_SIG`) before sending it, but never validates `routeData.tx.to` against any known/expected Enso router address before calling `walletProvider.sendTransaction({ to: routeData.tx.to, ... })`. This would only matter if Enso's own API/infrastructure were compromised or the response were tampered with in transit — a precondition I can't independently trigger or verify from here, so I'm noting it rather than filing it as a standalone finding.
