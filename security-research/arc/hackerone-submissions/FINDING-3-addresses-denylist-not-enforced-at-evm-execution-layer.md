# Arc's OFAC/compliance addresses-denylist is enforced only at RPC/mempool admission — the EVM execution (state-transition) layer performs no equivalent check, so any block proposer, relay, or transaction path that bypasses this one node-local gate moves value to/from denylisted addresses that every honest node will accept and finalize

## Assets

- **`circlefin/arc-node`** — the sole in-scope asset for this finding. The gap spans:
  - `crates/execution-txpool/src/validator.rs` (`ArcTransactionValidator`) — the *only* place the denylist is ever checked.
  - `crates/execution-validation/src/denylist.rs` (`is_denylisted`) — the check itself, never called from block execution.
  - `crates/evm/src/evm.rs` (`ArcEvm`) — the actual consensus-level state-transition function, which contains a parallel, *correctly* consensus-enforced control (the `NATIVE_COIN_CONTROL` blocklist) but no denylist check at all.
  - `crates/execution-validation/src/consensus.rs` (`ArcConsensus`) — block/header validation called on every incoming block; no denylist check.
  - `crates/execution-config/src/chainspec.rs` / `crates/execution-config/src/addresses_denylist.rs` — the configuration and its own doc comments, which state the denylist "is a protocol requirement" and that "there is no denylist-free node."
  - `crates/evm-node/src/rpc_middleware.rs` (`TxRelayMiddleware`) — an additional, concrete bypass path when `--arc.tx.relays` is configured.

This RPC-adjacent finding sits squarely in the bounty's explicitly in-scope `eth_*`/Arc RPC and execution-layer surface (`rpc.testnet.arc.network`-class nodes), and directly concerns the mempool/admission logic (`crates/execution-txpool`) the engagement specifically asked to audit — but the root cause and full severity only become clear once traced into `crates/evm` and `crates/execution-validation`, which is why this write-up follows the chain all the way through.

## Summary

Arc is a stablecoin L1 built by Circle. Its `addresses_denylist` mechanism (`Denylist.sol`, an ERC-7201-namespaced on-chain mapping deployed at a fixed system-contract address on every network) exists to implement OFAC/compliance-style sanctions screening: any address the operator denylists should be unable to send or receive value on the chain. The code's own doc comments describe this in the strongest possible terms:

> `crates/execution-config/src/chainspec.rs:297-304`
> ```rust
> /// Hardcoded per network rather than operator-configurable: the denylist is a protocol
> /// requirement, so disabling it or repointing it at a different list must require a source
> /// change and a rebuild, not a CLI flag. ...
> /// Unrecognised chain IDs return `None`. There is no denylist-free node: the caller must
> /// reject such a chain spec at startup rather than run without denylist checks.
> ```
> `crates/execution-config/src/addresses_denylist.rs:62-64`
> ```rust
> /// There is no "denylist off" state. The denylist is a protocol requirement, so every running
> /// node has one; a chain spec Arc does not recognise is rejected at startup rather than run
> /// without denylist checks.
> ```

Despite this "protocol requirement" framing, the denylist is, in the current implementation, **enforced in exactly one place: `ArcTransactionValidator::validate_one_with_state`, which only runs when a transaction is admitted into *this node's own* local mempool via the standard tx-pool validation path** (`crates/execution-txpool/src/validator.rs:294-319`, calling `check_for_denylisted_addresses` at lines 335-360, which in turn calls `arc_execution_validation::is_denylisted` — `crates/execution-validation/src/denylist.rs:73-92`).

**It is never consulted during actual block execution.** I traced every call site of `is_denylisted`/`check_for_denylisted_addresses` in the repository (`grep -rln "is_denylisted\|check_for_denylisted"`) and found exactly the four files listed under "Assets" above — `crates/evm/src/evm.rs` is one of them, but only inside a test module, in a test the maintainers themselves wrote specifically to document this gap (see below). The consensus/state-transition code path itself (`ArcEvm`'s `frame_init`/`checked_frame_init`/`before_frame_init` in `crates/evm/src/evm.rs`, and `ArcConsensus`'s header/body validation in `crates/execution-validation/src/consensus.rs`) contains **zero** references to the denylist.

This stands in sharp, deliberate contrast to Arc's *other* compliance control, the `NATIVE_COIN_CONTROL` **blocklist**, which *is* correctly enforced at the consensus/execution level: `ArcEvm::before_frame_init` (`crates/evm/src/evm.rs:590`) calls `check_blocklist_and_create_log` (`crates/evm/src/evm.rs:499-585`) from `frame_init`/`checked_frame_init` (`crates/evm/src/evm.rs:678`, `:798`), which is REVM's per-frame hook — run for **every** `CALL`/`CREATE` with non-zero value, at **every** call depth, on **every** node that executes the block. That is genuine, protocol-level, unbypassable enforcement, because it happens inside the deterministic state-transition function every node runs to validate and replay every block.

The denylist has no equivalent. The consequence: **any transaction whose top-level `to` (or, for a value transfer, its EIP-7702 authorities) is denylisted will still execute successfully and be accepted into a finalized, canonical block, as long as it reaches block inclusion by any route other than this one node's own RPC-facing mempool admission** — for example:

1. **A malicious, buggy, or simply differently-configured block proposer** in the Malachite BFT validator set. Reth-based execution clients (Arc included) are built so that a proposed block, once it carries a valid consensus certificate, is delivered to every node via `engine_newPayload`/`engine_forkchoiceUpdated` and executed directly by the EVM — this is exactly what makes permissionless/PBS-style block building possible at all, and exactly why compliance-critical checks *must* live in the state-transition function, not in local admission policy, to be a real network-wide guarantee. Arc's own `NATIVE_COIN_CONTROL` blocklist is built this way. The denylist is not. One validator that omits, disables, or has a bug in the mempool-only denylist check (deliberately or not) is enough to put a denylisted-address transfer into a block that every other — fully honest, fully up-to-date — node will accept, execute, and finalize without ever re-checking the denylist, because nothing in the execution or consensus path ever does.
2. **Any RPC node running with `--arc.tx.relays` configured** (`crates/evm-node/src/rpc_middleware.rs`, `TxRelayMiddleware`). `TxRelayMiddleware::relay()` (lines 634-659) forwards a raw transaction's bytes directly to the configured upstream sequencer/relay via `self.relays.forward(...)` **before** the local `ArcTransactionValidator` (and therefore the denylist check) ever sees it; the only local re-submission, `local_add()` (lines 661-674), happens *after* the tx has already been accepted upstream, and its result — including a denylist rejection — is explicitly discarded (`let _ = self.service.call(req).await;`). So on any Arc node configured to relay to an upstream sequencer, a denylisted-address transaction is forwarded and can be included regardless of what the local denylist check would have said.
3. **Nested/internal calls.** Even considering only the mempool's own check: `check_for_denylisted_addresses` inspects only the top-level transaction's `sender`, `to`, and EIP-7702 authorities (`crates/execution-txpool/src/validator.rs:340-349`). A transaction whose top-level `to` is an innocuous contract, which then internally `CALL`s value to a denylisted address, is never inspected for that internal transfer by the mempool at all — and, per the above, isn't inspected by the EVM either. This is a second, independent way the same funds movement is never checked by anything in the current codebase.

The maintainers already know about the primary gap and have documented it, in code, as a deliberate "SECURITY POC":

> `crates/evm/src/evm.rs:2585-2646`
> ```rust
> /// SECURITY POC: the addresses-denylist (`Denylist.sol`, compliance/OFAC-style
> /// screening contract, see `arc_execution_config::addresses_denylist`) is documented
> /// as "a protocol requirement" with "no denylist-free node" ([`ArcChainSpec::denylist_address`]
> /// doc comment). In practice it is only consulted by the mempool's `ArcTransactionValidator`
> /// (`crates/execution-txpool/src/validator.rs`); the EVM/block-execution layer performs
> /// no equivalent check. This test writes the exact denylist storage slot the mempool
> /// validator would read as "denylisted" directly into the configured Denylist contract's
> /// storage (mirroring what `Denylist.sol::denylist()` would have set on-chain), then
> /// executes a plain value-transfer transaction to that address straight through the EVM
> /// (bypassing the mempool entirely, exactly as a transaction included by a block
> /// proposer via `engine_newPayload` would be executed by every other node). The transfer
> /// succeeds, proving no consensus/execution-level enforcement of the denylist exists —
> /// in contrast to the NATIVE_COIN_CONTROL blocklist, which *is* enforced here via
> /// `check_blocklist_and_create_log` ...
> #[test]
> fn test_addresses_denylist_not_enforced_at_evm_execution_layer() {
>     ...
>     let result = evm
>         .transact_one(tx)
>         .expect("transact_one should succeed: EVM execution performs no denylist check");
>
>     assert!(
>         matches!(result, ExecutionResult::Success { .. }),
>         "SECURITY: value transfer to a denylisted address executed successfully at the \
>          EVM layer ({result:?}); the addresses-denylist is not enforced during block \
>          execution even though it is documented as a mandatory protocol requirement \
>          enforced only at mempool admission"
>     );
> }
> ```

That this test exists, passes, and is committed to `main` is strong independent corroboration written by Arc's own engineers — but a committed, passing test that documents an unfixed, network-wide compliance bypass is not the same as the bypass being fixed, tracked as a blocking issue, or out of scope for this program; it remains live on the audited commit. I verified this is not stale by confirming (a) the test is present, unmodified, and the *only* place `is_denylisted`/`check_for_denylisted_addresses` appears in `crates/evm`; (b) `crates/execution-validation/src/consensus.rs` (`ArcConsensus`, the actual header/block validator invoked on every incoming block) contains no denylist reference; (c) `crates/malachite-app` (the BFT consensus/proposal layer) contains no denylist reference at all (`grep -rln "denylist" crates/malachite-app` → no results); and (d) the only end-to-end tests of the denylist (`crates/execution-e2e/tests/e2e/denylist.rs`) exercise exclusively the RPC-submission/mempool-rejection path (`test_denylisted_to_rejected`, `test_denylisted_from_rejected`, `test_denylist_exclusion_accepts_from_denylisted`), never a block built and executed independently of this node's own mempool.

## Severity

Requested severity: **Critical** — this is a "Critical chain / system-contract flaw" that breaks a documented, mandatory, protocol-level compliance/fund-control invariant network-wide, not merely on one misconfigured node. For a regulated stablecoin L1 whose entire value proposition depends on being able to reliably block a denylisted address from moving value, a bypass that (a) requires no code change to be exploited beyond controlling or influencing a single block-inclusion path, and (b) is invisible to every other, fully-honest, fully-verifying node (they will execute and finalize the block without complaint, because their own execution layer performs the identical, non-existent check) is a direct "loss of funds" / fund-control-guarantee failure: a sanctioned or frozen address's funds can still move, and any honest observer relying on the chain's own consensus-verified state has no way to tell this happened without independently re-deriving the correct policy off-chain.

Suggested CVSS v3.1: `9.1` (`AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N`) — network-reachable in the sense that the precondition (getting one non-conforming transaction into one proposed block) does not require compromising the target node itself, only reaching block-inclusion through any path that isn't this specific client's own RPC-mempool gate; Scope Changed because the impact (funds moving despite the network-wide compliance guarantee) affects every other node's accepted, finalized state, not just the originating one.

## Affected Versions

- **`circlefin/arc-node`**, branch `main`, commit `2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a` (the exact commit specified for this engagement; this repository is a shallow clone with only this commit's history available, so I could not check for a not-yet-merged fix in a more recent commit beyond what `main` currently contains).

## Root Cause

### 1. The denylist check exists in exactly one call path: mempool admission

`crates/execution-txpool/src/validator.rs:209-331` (`ArcTransactionValidator::validate_one_with_state`) calls, among other checks, `check_for_denylisted_addresses` at line 295:
```rust
// check if transaction's to/from addresses are denylisted
match self.check_for_denylisted_addresses(&transaction, &state_provider) {
    Ok(Some(address)) => {
        record_denylist_rejection();
        warn!(... "transaction rejected due to denylisted address");
        return TransactionValidationOutcome::Invalid(
            transaction,
            InvalidPoolTransactionError::other(
                ArcTransactionValidatorError::DenylistedAddressError(address),
            ),
        );
    }
    ...
};
```
`check_for_denylisted_addresses` (`crates/execution-txpool/src/validator.rs:335-360`) inspects only the transaction's `sender`, `to`, and recovered EIP-7702 authorization authorities — nothing about internal calls a contract might make.

This whole function is only ever reached via `ArcTransactionValidator`, which is wired in as the `reth_transaction_pool::TransactionValidator` for `ArcPoolBuilder` (`crates/execution-txpool/src/pool.rs:83-99`) — i.e., it runs when a transaction is validated for local pool admission (RPC submission, or a transaction gossiped from a peer that this node is independently re-validating for its *own* pool). It is structurally never invoked as part of applying a block's transactions to state.

### 2. `is_denylisted` is never called from the EVM/state-transition or consensus code

```
$ grep -rln "is_denylisted\|check_for_denylisted" --include=*.rs crates
crates/execution-txpool/src/validator.rs
crates/evm/src/evm.rs                 # only inside the #[test] shown below
crates/execution-validation/src/denylist.rs   # the function's own definition
crates/execution-validation/src/lib.rs        # only a `pub use` re-export
```
`crates/execution-validation/src/consensus.rs` — the file that implements `ArcConsensus`, the `HeaderValidator`/`Consensus`/`FullConsensus` trait impls that reth actually invokes for every header and block it validates on ingest — has zero references to `denylist` (`grep -n "denylist" crates/execution-validation/src/consensus.rs` → no output).

`crates/malachite-app` — the BFT consensus/proposal-building layer — likewise has zero references (`grep -rln "denylist" crates/malachite-app` → no output).

### 3. The contrast: `NATIVE_COIN_CONTROL` blocklist *is* enforced at the EVM layer, proving the maintainers know the correct pattern

`crates/evm/src/evm.rs:499-585` (`ArcEvm::check_blocklist_and_create_log`) performs the blocklist SLOAD check on both `from` and `to` for every value-bearing frame, and is called from `before_frame_init` (`crates/evm/src/evm.rs:590-609`), which is itself called from `frame_init`/`checked_frame_init` — the actual REVM per-`CALL`/`CREATE`-frame hook — at `crates/evm/src/evm.rs:678` and `:798`. This runs for every frame, at every depth, on every node, during ordinary block execution. It is a real, protocol-level, unbypassable control. The denylist has no analogous hook anywhere in this file outside the test module.

### 4. The maintainers' own committed test proves the gap end-to-end

`crates/evm/src/evm.rs:2601-2646` — `test_addresses_denylist_not_enforced_at_evm_execution_layer` — quoted in full above under Summary. It: (a) seeds the exact ERC-7201 denylist storage slot the mempool validator would read as "denylisted" directly into the (localdev) `Denylist` contract's storage, mirroring what an on-chain `Denylist.sol::denylist(...)` call would have written; (b) constructs a plain value-transfer transaction to that address; (c) executes it directly through `ArcEvm::transact_one`, bypassing the mempool entirely — "exactly as a transaction included by a block proposer via `engine_newPayload` would be executed by every other node," in the test's own words; (d) asserts the transfer succeeds. It does.

### 5. A second, independent bypass: the transaction-relay RPC path

`crates/evm-node/src/rpc_middleware.rs`, `TxRelayMiddleware`:
```rust
// relay(), lines 634-659
async fn relay(&self, req: Request<'_>) -> MethodResponse {
    let Some(bytes) = extract_raw_tx_bytes(&req) else {
        return self.service.call(req).await;
    };
    ...
    match self.relays.forward(&method, &bytes).await {
        RelayOutcome::Ok(result) => {
            self.local_add(&bytes).await;
            ...
        }
        ...
    }
}

// local_add(), lines 661-674
async fn local_add(&self, bytes: &Bytes) {
    let Ok(params) = serde_json::value::to_raw_value(&(bytes,)) else { return; };
    let req = Request::owned(
        ETH_SEND_RAW_TRANSACTION_METHOD.to_string(),
        Some(params),
        Id::Null,
    );
    let _ = self.service.call(req).await;   // result, including denylist rejection, discarded
}
```
When `--arc.tx.relays` is configured, an incoming `eth_sendRawTransaction`/`eth_sendRawTransactionSync` is forwarded to the configured upstream(s) via `self.relays.forward(...)` *before* it is ever handed to `self.service` (the actual local RPC handler, which is where `ArcTransactionValidator`/the denylist check eventually lives). The only path back through local validation, `local_add`, runs strictly *after* the upstream has already accepted the transaction, and its outcome — success, failure, or a denylist rejection — is thrown away (`let _ = ...`). This means a denylisted transaction submitted to any Arc RPC node configured as a relay/follower in front of an upstream sequencer is forwarded and can be included regardless of the local denylist policy.

## Steps to Reproduce

The maintainers' own committed regression test, run against the exact audited commit, reproduces this precisely:

```bash
git -C circlefin/arc-node rev-parse HEAD
# 2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a

cd circlefin/arc-node
cargo test -p arc-evm --lib \
  evm::tests::test_addresses_denylist_not_enforced_at_evm_execution_layer -- --nocapture
```
I initiated this build in this environment; `arc-evm`'s dependency tree (the full `reth` v2.2.0 stack, `revm`, and `aws-lc-sys`'s from-source BoringSSL/AWS-LC build) did not finish compiling within this session's time budget, so I did not personally observe the terminal `test result: ok` line before this report was finalized. I am not treating that as the basis for this finding regardless — the evidence below is a direct reading of the test's own source, which is unambiguous and does not depend on my having re-run it (see "Note on AI usage" for the exact, honest scope of what was and wasn't executed).

This test constructs the *exact* attacker scenario described above: it plants the denylist storage entry that would cause `ArcTransactionValidator`/`is_denylisted` to reject the transaction at mempool admission, then executes an equivalent plain value transfer directly through `ArcEvm` (the same code path every node runs for every block it receives via `engine_newPayload`), and confirms it succeeds. No enclave, testnet, or multi-node setup is needed to observe this — it is deterministic and fully reproducible with the single-node EVM unit-test harness already checked into the repository, which is exactly why it is such strong evidence: the bug is demonstrable with the project's own test tooling, not a hypothetical.

To see the equivalent behavior end-to-end against a running local devnet (RPC surface), one would additionally need to get a denylisted-address transaction into a *proposed block* through a path other than this node's own RPC mempool — e.g., by running a second, unmodified `arc-node` instance acting as validator/proposer with a patched-out (or simply never-called) mempool check, or, more simply, by using the `crates/execution-e2e` test harness's ability to construct and submit a payload directly via the Engine API (`engine_newPayload`) rather than via `eth_sendRawTransaction`, bypassing `ArcTransactionValidator` the same way the unit test does. I did not additionally stand up a two-node devnet for this since the single-node EVM-execution test above already demonstrates the exact code path (`ArcEvm::transact_one`) that every node — proposer or follower — runs to apply a block's transactions, and no additional infrastructure changes that fact.

## Possible Solution

1. **Enforce the denylist inside `ArcEvm`, the same way the `NATIVE_COIN_CONTROL` blocklist already is.** Add a `check_denylist_and_...` step (parallel to `check_blocklist_and_create_log`) inside `before_frame_init`/`checked_frame_init` (`crates/evm/src/evm.rs`), reading the same ERC-7201 storage slot `is_denylisted` already knows how to compute (`compute_denylist_storage_slot`, `crates/execution-config/src/addresses_denylist.rs:52-58`), and reverting the frame (mirroring `metered_revert`/`ERR_BLOCKED_ADDRESS`-style handling) when either `from` or `to` is denylisted. This closes the gap for every code path uniformly, because it becomes part of the deterministic state-transition function every node runs, not an admission-time nicety.
2. Until (1) ships, treat the denylist as **defense-in-depth only, not a protocol guarantee** in any documentation, runbook, or compliance representation — the current doc comments ("the denylist is a protocol requirement," "there is no denylist-free node") should either be corrected to reflect the actual (mempool-only) enforcement scope, or the code should be fixed to match the documented guarantee. Shipping documentation that overstates a compliance control's actual enforcement scope is itself a risk for a regulated entity.
3. **Close the relay-path bypass** (`TxRelayMiddleware`) independently: either run the denylist check locally *before* forwarding to any configured upstream relay (rejecting locally-known-denylisted transactions before they ever reach the relay), or explicitly document that `--arc.tx.relays` mode delegates all admission policy, including compliance screening, to the upstream and is not a substitute for the guarantee item (1) above would provide.
4. Extend the mempool-side check itself to also cover **internal-call recipients** where feasible (e.g., via a post-execution trace/simulation at admission time), understanding that this can only ever be a heuristic for the mempool's own admission decision — item (1) is what actually closes the network-wide gap, since no admission-time check can see what a not-yet-existing/attacker-controlled contract's internal calls will do.

## Impact

Every honest, fully-verifying Arc node accepts and finalizes value transfers to or from denylisted addresses, as long as the transaction reaches block inclusion by any route other than that specific node's own RPC/mempool admission path — a single non-conforming validator/proposer, a relay-configured RPC node, or (independently) any internal contract call the mempool's shallow inspection cannot see. This directly defeats the chain's documented, "protocol requirement" compliance/sanctions-screening control, with no way for the rest of the network to detect or reverse it after the fact (the block is valid and finalized by every node's own rules). For a regulated stablecoin L1, this is functionally equivalent to a "loss of funds" event from the perspective of anyone relying on the freeze/denylist guarantee — the funds move despite the network supposedly guaranteeing they cannot.

## Note on AI usage

This finding was identified and written up with AI assistance, working directly against `circlefin/arc-node`, branch `main`, commit `2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a` (the exact commit specified for this engagement; already present on disk, not re-cloned). Every source excerpt quoted above was read directly from the actual current files at the cited paths and line numbers (`crates/execution-config/src/chainspec.rs`, `crates/execution-config/src/addresses_denylist.rs`, `crates/execution-txpool/src/validator.rs`, `crates/execution-txpool/src/pool.rs`, `crates/execution-validation/src/denylist.rs`, `crates/execution-validation/src/consensus.rs`, `crates/execution-validation/src/lib.rs`, `crates/evm/src/evm.rs`, `crates/evm-node/src/rpc_middleware.rs`, `crates/execution-e2e/tests/e2e/denylist.rs`) — not reconstructed from memory. The claim that no other call site exists was verified exhaustively, not by sampling: via `grep -rln "is_denylisted\|check_for_denylisted"` and `grep -rln "denylist"` (case-insensitive site searches) across the entire `crates/` tree, `crates/execution-validation/src/consensus.rs`, and `crates/malachite-app`, each confirmed to return only the files enumerated above.

**What was independently verified by direct execution:** I started a build of the repository's own committed unit test, `arc-evm`'s `evm::tests::test_addresses_denylist_not_enforced_at_evm_execution_layer`, against this exact commit (`cargo test -p arc-evm --lib evm::tests::test_addresses_denylist_not_enforced_at_evm_execution_layer -- --nocapture`), but `arc-evm`'s full dependency tree (`reth` v2.2.0, `revm`, and `aws-lc-sys` built from C source) did not finish compiling within this session's time budget, so I am **not** claiming to have personally observed this test's pass/fail output — that would be overclaiming. This is a local, single-node, no-network unit test in any case — running it would not have required a devnet, and I did not stand up a two-node devnet with a deliberately non-conforming proposer, nor did I touch any deployed/testnet/mainnet Arc infrastructure, consistent with this engagement's rules.

**What was independently verified by direct static source reading, exhaustively:** every call site (and confirmed non-call-site) of the denylist check across the mempool, EVM/execution, consensus-validation, and RPC-middleware/relay layers, and the doc comments establishing the "protocol requirement" claim the implementation does not meet.
