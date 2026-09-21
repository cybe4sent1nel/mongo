# Title

AgentKit — `SuperfluidSuperTokenCreatorActionProvider.createSuperToken()` reads an arbitrary ERC20's `name()`/`symbol()` and embeds them unsanitized and length-unbounded into a new on-chain Super Token's own metadata — one call site the same-day "sanitize erc20 token metadata" fix (#1480) missed

## Status note / scope

Found while continuing the broad audit of `coinbase/agentkit` at `main` (commit `2e6dbaf725b9ec5f3b53003278100b0e655c214d`, 2026-09-03) requested after the x402 `maxPaymentUsdc` finding. That exact commit is itself a security fix — `fix: sanitize erc20 token metadata (#1480)` — which added `sanitizeOnchainMetadata()` and applied it at six call sites across `erc20/utils.ts`, `cdp/swapUtils.ts`, `zeroX/utils.ts`, `compound/utils.ts`, `flaunch/flaunchActionProvider.ts`, and `flaunch/swap_utils.ts`, plus Python equivalents in `erc20/utils.py`, `aave/utils.py`, `compound/utils.py`. I grepped every other `readContract` call in the tree for `functionName: "name"`/`functionName: "symbol"` to check whether the fix reached every call site it needed to. One did not get the fix: `typescript/agentkit/src/action-providers/superfluid/superfluidSuperTokenCreatorActionProvider.ts`.

## Why this bug class matters (per the vendor's own fix)

`sanitizeOnchainMetadata` (`typescript/agentkit/src/utils.ts`) strips Unicode `Cc`/`Cf`/`Co`/`Cs` categories (control, format/zero-width/bidi-override, private-use, surrogate characters) and caps length at 50 characters, with the doc comment: *"Sanitizes an untrusted onchain string (e.g. an ERC20 name/symbol) before it is included in agent-facing output."* An ERC20 contract's `name()`/`symbol()` is fully attacker-controlled — anyone can deploy a token with any string there, including bidi-override sequences that make displayed text read differently than it is, zero-width characters that can hide content, or simply an enormous string. The vendor evidently now treats this as a real risk surface for an LLM-driven agent (hidden/disguised content reaching agent-facing text, plus unbounded length), enough to patch it same-day across six call sites in one commit.

## The missed call site

```ts
// typescript/agentkit/src/action-providers/superfluid/superfluidSuperTokenCreatorActionProvider.ts
async createSuperToken(
  walletProvider: EvmWalletProvider,
  args: z.infer<typeof SuperfluidCreateSuperTokenSchema>,
): Promise<string> {
  try {
    const decimals = await walletProvider.readContract({
      address: args.erc20TokenAddress as Hex,
      abi: ERC20ABI,
      functionName: "decimals",
      args: [],
    });

    const name = await walletProvider.readContract({          // <-- untrusted, unsanitized
      address: args.erc20TokenAddress as Hex,
      abi: ERC20ABI,
      functionName: "name",
      args: [],
    });

    const symbol = await walletProvider.readContract({        // <-- untrusted, unsanitized
      address: args.erc20TokenAddress as Hex,
      abi: ERC20ABI,
      functionName: "symbol",
      args: [],
    });

    const createSuperTokenData = encodeFunctionData({
      abi: SuperTokenFactoryABI,
      functionName: "createERC20Wrapper",
      args: [
        args.erc20TokenAddress,
        decimals,
        2, // upgradeable
        `Super ${name}`,      // <-- unsanitized, unbounded-length string goes on-chain
        `${symbol}x`,         // <-- same
      ],
    });
    ...
```

`args.erc20TokenAddress` is an arbitrary address supplied to the action (the action's whole purpose is to wrap *any* ERC20 into a Superfluid Super Token — there's no allowlist and none is implied). Neither `name` nor `symbol` passes through `sanitizeOnchainMetadata` before being interpolated into the new Super Token's own constructor arguments.

## Impact — calibrated honestly, weaker than the six already-fixed sites

I want to be precise about severity rather than inflate it. In this specific function, `name`/`symbol` are **not** echoed directly into the string this action returns to the agent (`return \`Created super token for ${args.erc20TokenAddress}. Super token address at ${superTokenAddress} Transaction hash: ${createSuperTokenHash}\`;` — none of those three interpolated values come from the untrusted token). That's a real difference from the six sites the fix patched, where the unsanitized string was returned in the tool's output on the very next line. So I'm not claiming an immediate agent-facing leak from this call alone.

What *is* real:

1. **The payload propagates on-chain, unbounded and unsanitized, into a brand-new artifact's own metadata.** The newly created Super Token's `name()`/`symbol()` will literally return `Super <attacker string>` / `<attacker string>x` forever after. Any *later* tool call that reads this specific Super Token's metadata back (e.g. `erc20ActionProvider.getBalance()`/`transfer()` on the new Super Token address, in a later turn or a different session) *does* sanitize on read — so the immediate injection risk is caught downstream, but only by coincidence of every other reader being patched, not because this write path is safe. Any consumer of this token that AgentKit doesn't control (a block explorer link the agent might paste back, a wallet UI, a different tool/framework reading the same address) gets the raw, unsanitized string.
2. **No length cap is applied before the value goes into calldata.** A malicious ERC20 whose `name()` returns a very large string turns `createSuperToken` into an expensive-to-execute (or gas-limit-failing) transaction the agent's wallet pays for, entirely at the discretion of a contract the agent doesn't control — a minor gas-griefing/DoS angle specific to this call site that the length cap in `sanitizeOnchainMetadata` exists specifically to prevent elsewhere.
3. It is the same CWE-20/untrusted-input class the vendor fixed same-day at six other call sites, in a function reachable by name (`create_super_token`) with a fully attacker-choosable input address — structurally identical to the patched sites, just with the sanitization boundary crossed one call later.

I'd call this **Medium-to-High** rather than Critical, and said so plainly rather than stretching it — it's a genuine, verified gap in the exact class the vendor is actively hardening, but its blast radius in isolation is narrower than the sites already fixed.

## Verification

- Confirmed via `grep -rln 'functionName:\s*"symbol"\|functionName:\s*"name"'` across `typescript/agentkit/src/action-providers` that exactly 7 files call these functions; the fix commit's diff touches 6 of them (`erc20`, `compound`, `cdp/swapUtils`, `zeroX`, `flaunch` ×2); `superfluid/superfluidSuperTokenCreatorActionProvider.ts` is the 7th and is untouched by that commit or any later one on `main`.
- Checked the Python package for an equivalent action: Python's `superfluid_action_provider.py` only implements `create_flow` (streaming), with no `create_super_token`/wrapper-creation action, so there's no Python sibling of this specific gap.
- Checked `erc721`, `zora`, `clanker`, `opensea`, `wow`, `truemarkets` for the same read-then-echo pattern — none of them call `readContract` for `name`/`symbol`/`tokenURI` on an externally-supplied address (they either don't read existing token metadata at all, or take name/description as agent/operator-supplied *creation* parameters rather than reading them from an untrusted existing contract), so they aren't exposed to this bug class.

## Weakness

CWE-20 (Improper Input Validation) / CWE-1284-adjacent (unchecked length of untrusted data used to build a transaction) — same classification as the fixed sites, reached through the one call path the fix didn't cover.

## Component / Version

- Repository: `coinbase/agentkit`
- Confirmed present on `main` (commit `2e6dbaf725b9ec5f3b53003278100b0e655c214d`, 2026-09-03) — the same commit that introduced `sanitizeOnchainMetadata` and fixed the other six sites
- File: `typescript/agentkit/src/action-providers/superfluid/superfluidSuperTokenCreatorActionProvider.ts`, `createSuperToken()`, the `name`/`symbol` reads and their use in `createSuperTokenData`

## Suggested fix

```ts
import { sanitizeOnchainMetadata } from "../../utils";
...
const name = sanitizeOnchainMetadata(
  await walletProvider.readContract({ address: args.erc20TokenAddress as Hex, abi: ERC20ABI, functionName: "name", args: [] }),
);
const symbol = sanitizeOnchainMetadata(
  await walletProvider.readContract({ address: args.erc20TokenAddress as Hex, abi: ERC20ABI, functionName: "symbol", args: [] }),
);
```

Same one-line change pattern used at the other six sites in the same commit.

## Notes on scope

This was found by treating the HEAD commit itself as the sibling-hunt target (it's dated the same day as the clone and is explicitly a security fix), rather than searching for an unrelated bug class. Continuing the broader audit (CDP spend permissions, wallet-provider key handling, SSH provider, framework-extension adapters, and various DeFi/aggregator providers) turned up no further concrete high/critical findings beyond this one and the previously-reported `maxPaymentUsdc` gap — documented in the parent conversation, not re-filed here.
