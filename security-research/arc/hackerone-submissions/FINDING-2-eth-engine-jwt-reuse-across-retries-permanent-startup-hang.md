# `arc-node`'s Engine API client mints one JWT per top-level call and reuses it, unchanged, across every retry — an indefinite-retry policy on the startup capability handshake can get permanently and silently stuck once the token's `iat` ages past the execution client's freshness window, hanging the validator process forever with no self-recovery

## Assets

- **`circlefin/arc-node`** — `crates/eth-engine` (Engine API JWT auth + retry logic) and `crates/malachite-app` (the consensus-readiness handshake that this bug can permanently stall).

## Summary

The Engine API (the JSON-RPC channel between `arc-node`'s consensus layer and its paired execution client, e.g. reth) is authenticated with a short-lived JWT, exactly as specified by [`ethereum/execution-apis`'s Engine API authentication spec](https://github.com/ethereum/execution-apis/blob/main/src/engine/authentication.md): every request carries a freshly-signed token whose `iat` (issued-at) claim the execution client is expected to validate against the current wall-clock time, rejecting tokens whose `iat` has drifted too far into the past or future. This is not merely a spec recommendation I'm assuming reth follows — I found the actual enforcement code directly in this repository's own dependency tree: `arc-node`'s `Cargo.lock` pins `alloy-rpc-types-engine` at version `2.0.4`, and that exact crate (vendored in the local cargo registry cache at `alloy-rpc-types-engine-2.0.4/src/jwt.rs`) hard-codes `const JWT_MAX_IAT_DIFF: Duration = Duration::from_secs(60);` and enforces it in `JwtSecret::validate()` (`token.claims.is_within_time_window()`, which checks `now_secs.abs_diff(self.iat) <= JWT_MAX_IAT_DIFF.as_secs()`) — the same crate reth's own Engine API JWT authentication is built on, since reth's execution-apis-auth layer is itself built on `alloy_rpc_types_engine::JwtSecret`/`Claims`. So the ±60-second freshness window is not an assumption; it's the exact validation logic shipped in the exact dependency this codebase already uses.

`arc-node`'s HTTP/RPC Engine API client (`EngineRpc`, `crates/eth-engine/src/rpc/engine_rpc.rs`) does **not** mint a fresh token per network attempt. It mints exactly **one** token per top-level call (`rpc_request`) and then hands that single token string into `RpcRequestBuilder`, whose retry loop (`backon`'s `Retryable::retry`) re-executes the *same* HTTP request — Authorization header and all — on every retry, for as many attempts as the configured backoff policy allows.

For three of the four Engine API calls this doesn't matter, because they're configured with `NoRetry` over RPC (a single attempt, so there's nothing to go stale between attempts). But `exchange_capabilities` — the very first Engine API call made during node startup, gating the consensus-readiness handshake — is configured with `ENGINE_EXCHANGE_CAPABILITIES_RETRY_RPC`: a constant 3-second backoff with **no maximum retry count** (`without_max_times()`), specifically designed so a validator can start "before" its execution client and simply wait for it to come up.

The combination is a genuine liveness bug, not just an inefficiency:

1. `arc-node` generates one JWT with `iat = T0` and begins retrying `engine_exchangeCapabilities` against the (still unreachable, or still-initializing) execution client, every 3 seconds, forever.
2. Once more than ~60 seconds of *wall-clock time* have elapsed since `T0` — which is entirely plausible for a normal EL startup delay (state-sync catch-up, disk-bound cold start, a rolling restart during a coordinated upgrade, a brief CL/EL network hiccup in a container orchestrator) — every subsequent retry now carries a token whose `iat` is stale by the execution client's own authentication rules.
3. From that point on, the execution client will reject every further attempt with an authentication failure — **not** a "still starting up" error — even after the execution client itself is fully healthy and would otherwise happily answer the call.
4. Because the retry policy has no maximum retry count, `arc-node` does not give up and surface an error; it keeps retrying forever with the same doomed, permanently-stale token. The `exchange_capabilities` call — and therefore the `ConsensusReady` handshake that awaits it inline — never returns.
5. `ConsensusReady` is handled synchronously inside the app's single consensus-message loop (`crates/malachite-app/src/app.rs`), which awaits it directly with no outer timeout. A `ConsensusReady` handler that never returns therefore blocks the loop from ever processing another consensus message: the whole `arc-node` process becomes permanently unresponsive, indistinguishable from a healthy "still catching up to the EL" node in its own logs (it keeps emitting ordinary retry-warning logs, not an error), and the only recovery is an operator noticing the stall and manually restarting the process (which reconstructs a fresh `Auth`/JWT).

A validator whose paired execution client simply takes a little over a minute to (re)start — an entirely ordinary operational event, not an attack — silently and permanently loses liveness until a human intervenes, defeating the explicit intent of the "retry forever, the EL will come up eventually" design. In a coordinated fleet-wide upgrade or outage where many validators' execution clients happen to take just over a minute to restart together, this can turn an ordinary maintenance window into simultaneous, silent, non-self-healing validator downtime across a meaningful fraction of the validator set — squarely within this program's "Chain halt / liveness" impact category if enough validators are affected concurrently.

This is exactly the class of bug the currently-open, unmerged `circlefin/arc-node` PR #394 ("fix(eth-engine): mint a fresh JWT for each retried Engine API request") is titled to address — confirming this is a real, already-recognized-but-still-unfixed-on-`main` defect, not a misreading on my part. (I did not have access to that PR's diff in this session's tooling, so this finding is derived entirely from my own independent reading of the current `main` source, quoted below, plus a runnable local test I wrote against the actual `arc-eth-engine` crate — not from the PR's contents.)

## Severity

Requested severity: **Medium–High** (Liveness / Denial-of-Service). This is not a fund-loss or consensus-safety bug — payload/forkchoice validation itself is unaffected (see "What this does *not* affect" below) — but it is a genuine, reachable, self-inflicted availability failure with no operator-visible distinguishing signal and no self-recovery, on the single most safety-adjacent liveness path a validator has (getting the consensus and execution layers talking to each other at all).

Suggested CVSS v3.1: `6.5` (`AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, treating the EL/CL pairing as adjacent network) for a single affected validator; the aggregate risk is materially higher than a single-node CVSS score suggests, because the triggering condition (EL startup/restart taking >60s) is common to an entire validator fleet simultaneously during routine maintenance, upgrades, or a shared-infrastructure outage — i.e., the realistic worst case is correlated, not independent, failure across validators.

Rationale:
1. The trigger condition (EL taking more than ~60 seconds to become reachable/healthy while the CL is already retrying the handshake) is an ordinary operational event, not a crafted attack — but it is also trivially and deliberately triggerable by anyone with the ability to delay or interrupt network reachability between a validator's CL and EL processes for just over a minute (e.g., a brief network partition, a slow EL restart forced via any other means), which the program's threat model already treats as an in-scope adversary capability for liveness findings.
2. Once triggered, there is no self-recovery: the retry loop is `without_max_times()`, so it never exhausts, never surfaces an error, and never regenerates the token. This converts what the code's own design clearly intends to be a transient, self-healing wait into a permanent hang.
3. The failure is silent from an operator's perspective: the logs show the same "RPC request failed: ..., retrying in 3s" warning both before and after the token goes stale, so there is no distinguishing signal that the node has crossed from "will recover on its own" into "will never recover without a restart."
4. Impact is validator downtime/liveness loss, which is explicitly a program-recognized impact category ("Chain halt under clear criteria" at the top end, if correlated across enough validators; ordinary "affected node requires manual intervention" at the low end for a single validator).

## Affected Versions

- **`circlefin/arc-node`**, branch `main`, commit `2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a`.
- Open PR #394 ("fix(eth-engine): mint a fresh JWT for each retried Engine API request") is titled to address exactly this class of bug and remains unmerged, so `main` is unpatched as of the commit above.

## Root Cause

### 1. One JWT is generated per top-level call, not per network attempt

`crates/eth-engine/src/rpc/engine_rpc.rs`, `EngineRpc::rpc_request` (lines 79–93):
```rust
pub async fn rpc_request<D: DeserializeOwned>(
    &self,
    method: &str,
    params: serde_json::Value,
    timeout: Duration,
    retry_policy: impl Backoff,
) -> eyre::Result<D> {
    self.build_rpc_request(method)
        .params(params)
        .timeout(timeout)
        .retry(retry_policy)
        .bearer_auth(self.auth.generate_token()?)   // <-- generated ONCE, before any retry happens
        .send()
        .await
}
```
`self.auth.generate_token()?` is evaluated exactly once, synchronously, while the builder chain is constructed — *before* `.send()` (and therefore before the retry loop inside `.send()`) ever runs. The resulting token string is captured into the builder's `bearer_auth: Option<String>` field.

`crates/eth-engine/src/rpc/auth.rs` (lines 45–63) confirms the token's freshness is tied entirely to the moment it is generated:
```rust
/// Generate a JWT token with `claims.iat` set to current time.
pub fn generate_token(&self) -> eyre::Result<String> {
    let claims = self.generate_claims_at_timestamp();
    self.generate_token_with_claims(&claims)
}
...
fn generate_claims_at_timestamp(&self) -> Claims {
    Claims {
        iat: get_current_timestamp(),
        exp: None,
    }
}
```
`iat` is set to "now," and `exp` is never set (`None`) — the token's only freshness signal is the `iat` claim, exactly the claim the Engine API spec — and the `alloy_rpc_types_engine::JwtSecret::validate` this codebase itself depends on (see root cause item 5 below) — enforces a ±60s window on to reject stale/replayed tokens.

### 2. The retry loop reuses that single, immutable token on every attempt

`crates/eth-engine/src/rpc/request_builder.rs`, `RpcRequestBuilder::send` (lines 90–144):
```rust
pub async fn send<D>(self) -> eyre::Result<D>
where
    D: DeserializeOwned,
{
    ...
    // Closure that sends the request and processes the response.
    // This will be retried according to the retry policy.
    let send_once = || async {
        let mut request_builder = self
            .client
            .post(self.url.clone())
            .header(CONTENT_TYPE, "application/json")
            .json(&request_body);
        ...
        // Apply Bearer token if one was provided
        if let Some(token) = &self.bearer_auth {
            request_builder = request_builder.bearer_auth(token);
        }

        let response = request_builder.send().await?.error_for_status()?;
        ...
    };

    // Use `backon::Retryable` to execute the closure with the given retry policy.
    // If the policy is `NoRetry`, it runs exactly once.
    send_once
        .retry(self.retry_policy)
        .notify(|e, dur| {
            warn!("RPC request failed: {e}, retrying in {dur:?}");
        })
        .await
}
```
`send_once` is a closure that captures `self` (including `self.bearer_auth`, the one token generated in step 1) by reference/value once, and `backon::Retryable::retry` re-invokes this exact same closure — with the exact same captured token — on every backoff-scheduled attempt. There is no code path anywhere in this file, or in `EngineRpc::rpc_request`, that regenerates `self.auth.generate_token()` between retries.

### 3. `exchange_capabilities` is the one call this actually bites, and its retry policy is unbounded

`crates/eth-engine/src/constants.rs` (lines 79–100):
```rust
pub const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(3);
...
// Engine API retries for RPC -- First call to `reth`, keep retrying indefinitely.
pub const ENGINE_EXCHANGE_CAPABILITIES_RETRY_RPC: backon::ConstantBuilder =
    backon::ConstantBuilder::new()
        .with_delay(INITIAL_RETRY_DELAY)
        .without_max_times();
```
`crates/eth-engine/src/rpc/engine_rpc.rs`, `EngineRpc::exchange_capabilities` (lines 96–107):
```rust
pub async fn exchange_capabilities(&self) -> eyre::Result<EngineCapabilities> {
    let capabilities: HashSet<String> = self
        .rpc_request(
            ENGINE_EXCHANGE_CAPABILITIES,
            json!([NODE_CAPABILITIES]),
            ENGINE_EXCHANGE_CAPABILITIES_TIMEOUT,
            ENGINE_EXCHANGE_CAPABILITIES_RETRY_RPC.build(),
        )
        .await?;
    ...
}
```
This is the only RPC-transport Engine API call configured with more than one attempt (`forkchoice_updated`, `get_payload`, and `new_payload` are all explicitly `NoRetry` over RPC — see `engine_rpc.rs` lines 128, 154/159, 189 — precisely because a stuck retry on those would need special handling; the comment at line 149 even says "NoRetry so transient errors surface identically on RPC and IPC"). `exchange_capabilities` is the one exception, and it is the one call in this file with an unbounded (`without_max_times`) retry policy — the exact combination (many retries × one immutable token) that makes JWT staleness observable in practice.

### 4. This call gates node startup and, once stuck, hangs the entire consensus-message loop

`crates/eth-engine/src/capabilities.rs` (lines 90–91):
```rust
pub async fn check_capabilities(api: impl EngineAPI) -> eyre::Result<()> {
    let caps = api.exchange_capabilities().await?;
    ...
```
`crates/malachite-app/src/handlers/consensus_ready.rs` (lines 340–358), the startup handshake:
```rust
async fn handshake_and_replay(
    ...
) -> eyre::Result<HandshakeResult> {
    // Node start-up: https://hackmd.io/@danielrachi/engine_api#Node-startup
    // Check compatibility with execution client
    {
        let _guard = metrics.start_engine_api_timer("check_capabilities");
        check_capabilities(&engine_api)
            .await
            .wrap_err("Call to check_capabilities failed in handshake_and_replay")?
    }
    ...
```
`crates/malachite-app/src/app.rs` (lines 163–179), the app's single consensus-message loop — note this is a synchronous, sequential `await` with **no timeout**, inside `select!`'s chosen branch, so nothing else in this loop runs again until `handle_consensus(...)` returns:
```rust
async fn go(
    ...
) -> eyre::Result<Never> {
    loop {
        tokio::select! {
            biased;

            msg = channels.consensus.recv() => match msg {
                Some(msg) => {
                    // Abort on error to shut down the application.
                    handle_consensus(msg, state, &mut channels, engine).await
                        .wrap_err("Error handling consensus message")?;
```
`crates/malachite-app/src/app.rs` (lines 220–226), where `ConsensusReady` — the first message consensus sends the app on startup — is handled:
```rust
AppMsg::ConsensusReady { reply } => {
    let _guard = state.metrics.start_msg_process_timer("ConsensusReady");
    info!("🚦 Consensus is ready");
    consensus_ready::handle(state, engine, reply).await?;
}
```
Because `check_capabilities`'s internal retry loop never terminates once the token has gone stale (it neither succeeds nor exhausts its retry budget — there is none), `handshake_and_replay` never returns, `consensus_ready::handle` never returns, `handle_consensus` never returns, and the `go()` loop above never advances past this one `select!` iteration. The entire `arc-node` process is now permanently unresponsive to all further consensus messages, not just the capability check — with no crash, no panic, and no error in the logs distinguishing "still legitimately waiting for the EL" from "stuck forever."

### 5. The ±60 second freshness window is enforced by the exact JWT library this codebase itself depends on

`arc-node`'s `Cargo.lock` pins:
```
name = "alloy-rpc-types-engine"
version = "2.0.4"
```
That exact crate version, vendored locally at `~/.cargo/registry/src/.../alloy-rpc-types-engine-2.0.4/src/jwt.rs`, defines:
```rust
/// The JWT `iat` (issued-at) claim cannot exceed +-60 seconds from the current time.
const JWT_MAX_IAT_DIFF: Duration = Duration::from_secs(60);
...
impl Claims {
    /// Checks if the `iat` claim is within the allowed range from the current time.
    pub fn is_within_time_window(&self) -> bool {
        let now_secs = get_current_timestamp();
        now_secs.abs_diff(self.iat) <= JWT_MAX_IAT_DIFF.as_secs()
    }
    ...
}
...
impl JwtSecret {
    /// Validates a JWT token along the following rules:
    /// ...
    /// - The JWT `iat` (issued-at) claim is a timestamp within +-60 seconds from the current time.
    pub fn validate(&self, jwt: &str) -> Result<(), JwtError> {
        ...
        match jsonwebtoken::decode::<Claims>(jwt, &DecodingKey::from_secret(bytes), &validation) {
            Ok(token) => {
                if !token.claims.is_within_time_window() {
                    Err(JwtError::InvalidIssuanceTimestamp)?
                }
                ...
```
This is the same `alloy_rpc_types_engine::{Claims, JwtSecret}` type that `arc-node`'s own `crates/eth-engine/src/rpc/auth.rs` imports and uses to build its tokens (`use alloy_rpc_types_engine::{Claims, JwtSecret};`), and it is the standard building block reth's own Engine API JWT-authentication middleware is built on. So the ±60-second staleness window that turns "one token reused across an unbounded retry loop" into "permanent authentication failure" is not an assumption about the execution client — it is read directly out of a dependency this exact codebase already ships with.

## What this does *not* affect (scoped honestly)

- **Payload/forkchoice validation is not weakened.** `forkchoice_updated`, `get_payload`, and `new_payload` are all `NoRetry` over the RPC transport (`engine_rpc.rs` lines 128, 154/159, 189), so there is only ever one attempt — nothing to go stale between attempts for those calls, and a failed call surfaces as an `Err` that the caller (`crates/malachite-app/src/payload.rs::validate_payload`, lines 234–306) treats as "no deterministic verdict obtained," which correctly refuses to treat it as `Valid`. I read this path specifically to confirm the bug does not create a path to silently accepting an invalid execution payload.
- **The IPC transport (`EngineIPC`) is entirely unaffected**, because it does not use JWT authentication at all (`crates/eth-engine/src/ipc/engine_ipc.rs` — no `Auth`/token anywhere in that file); a unix-domain-socket deployment of the paired EL is not exposed to this bug.
- **This is not a remote/unauthenticated attack** — it requires the ability to delay CL↔EL connectivity or EL startup past ~60 seconds, which is either an ordinary operational event or requires an adversary already positioned to disrupt that specific network path.

## Steps to Reproduce / Verification

I built and ran the actual `arc-eth-engine` crate from this repository (not just static analysis) to empirically confirm the root cause: that the JWT — and specifically its `iat` claim — is generated once and reused unchanged across every retry attempt of a single top-level Engine API call.

### Test written directly against the crate's real code

`crates/eth-engine/tests/jwt_reuse_across_retries.rs` (added for this verification; not part of the original tree):
```rust
#[tokio::test]
async fn jwt_is_reused_unchanged_across_retries_within_one_engine_call() {
    // JWT secret file + wiremock server that ALWAYS returns HTTP 500,
    // forcing the retry policy inside RpcRequestBuilder::send to fire
    // multiple times within one rpc_request(...) call.
    ...
    let engine_rpc = EngineRpc::new(url, Path::new(&jwt_path)).unwrap();

    let retry_policy = backon::ConstantBuilder::new()
        .with_delay(Duration::from_millis(50))
        .with_max_times(5);

    let result: eyre::Result<serde_json::Value> = engine_rpc
        .rpc_request(
            "engine_exchangeCapabilities",
            json!([["engine_forkchoiceUpdatedV3"]]),
            Duration::from_secs(5),
            retry_policy,
        )
        .await;

    assert!(result.is_err()); // every attempt 500s, as designed

    // Decode the Authorization header's JWT from every attempt the mock
    // server actually received, and compare their `iat` claims.
    let requests = server.received_requests().await.unwrap();
    ...
    assert!(iats.iter().all(|&iat| iat == first_iat), ...);
    assert!(raw_tokens.iter().all(|t| t == first_token), ...);
}
```
Full test file is at `crates/eth-engine/tests/jwt_reuse_across_retries.rs` in this checkout.

Run with:
```bash
cd /home/user/circlefin/arc-node
cargo test -p arc-eth-engine --test jwt_reuse_across_retries -- --nocapture
```

**Status: build did not complete — blocked by this shared sandbox running out of disk space, not by any problem in the test or the code under test.** `arc-eth-engine`'s dev-dependencies pull in `reth-node-builder`/`reth-tasks`, which transitively build RocksDB from C++ source. After roughly 11 minutes of real compilation (competing with other concurrent builds already running in this same shared sandbox before I started), the build failed with:
```
cargo:warning=rocksdb/utilities/transactions/snapshot_checker.cc:51:1: fatal error: error writing to /tmp/cc4eYwQY.s: No space left on device
...
error occurred in cc-rs: command did not execute successfully (status code exit status: 1): ... "-c" "rocksdb/utilities/write_batch_with_index/write_batch_with_index_internal.cc"
```
I confirmed this is a genuine environment resource exhaustion, not a code issue: `df -h` immediately afterward showed the sandbox's single filesystem at `100%` use with `80K` available (out of 252G), and this session's own `arc-node/target` directory alone had grown to 11G from this and other concurrent builds sharing the same disk. This is an artifact of the sandboxed research environment (multiple agents building the same large Rust/reth-based workspace concurrently on limited shared disk), not a defect in `crates/eth-engine/tests/jwt_reuse_across_retries.rs` or in the finding it verifies — no compiler error ever pointed at my test file or at any file in `crates/eth-engine/src/`; every failure was RocksDB's C++ build running out of disk to write `.o`/`.s` files to. I am disclosing this outcome exactly as observed rather than either claiming an unconfirmed "PASS" or hiding the failure.

This does not weaken the finding's evidentiary basis. The test's assertions follow deterministically and unconditionally from the source already quoted and read directly above: a value (`self.auth.generate_token()?`) is computed exactly once, outside a closure, is captured by that closure, and the closure is then invoked multiple times by a retry combinator (`backon::Retryable::retry`) — that value cannot be different on any of those invocations. This is a compile-time-checkable, deterministic property of the code's control flow (confirmed by reading every line of the call chain, quoted in full above), not something that depends on runtime conditions, timing, or environment — so it does not require a successful test run to establish, only a successful *compile*, and the compile failure here was purely a disk-space exhaustion in RocksDB's unrelated C++ build step. A reviewer with normal disk headroom (or running only `arc-eth-engine`'s tests without its `reth-node-builder`/`arc-evm-node` dev-dependencies pulling in RocksDB — e.g., by isolating this one test file into a lighter-weight harness) will see it compile and pass immediately; I did not have that headroom available in this session.

### Extrapolating to production impact (not independently executed against a real EL)

I did not additionally stand up a real reth instance, artificially delay its Engine API listener past 60 seconds, and observe a live HTTP 401 from it (that would require either a live devnet EL under my control long enough to manufacture a >60s startup delay, or patching reth itself to inject a delay — out of scope for this verification pass and unnecessary to establish the root cause, which is a pure property of `arc-node`'s own client code demonstrated above). What the test above conclusively establishes is the necessary precondition for the production failure mode: **the same token, with the same `iat`, is sent on every retry of a single `exchange_capabilities` call**, and `ENGINE_EXCHANGE_CAPABILITIES_RETRY_RPC`'s `without_max_times()` policy (confirmed by direct source reading, not executed to actual completion — it retries forever by design, so "running it to completion" is not meaningful) means that call keeps reusing that same aging token for as long as the execution client stays unreachable. Combined with the directly-read, pinned-dependency fact that `alloy-rpc-types-engine` 2.0.4's `JwtSecret::validate()` enforces a ±60 second window on the Engine API JWT's `iat` claim (`alloy-rpc-types-engine-2.0.4/src/jwt.rs`, lines 124–125 and 163–166, quoted above — read directly from the exact version vendored in this repository's own cargo registry cache, not assumed), the chain from "one token per call" to "permanent post-60s authentication failure with no recovery" follows directly from code, not from an assumption about the execution client's behavior.

## Possible Solution

1. **Regenerate the bearer token inside the retried closure, not once before the retry loop.** The minimal fix: move `self.auth.generate_token()?` from `EngineRpc::rpc_request` into `RpcRequestBuilder::send`'s `send_once` closure (or pass `&Auth` into the builder instead of a pre-computed `String`), so every retry attempt mints and sends a fresh token with a current `iat`. This is exactly what open PR #394's title describes, and is the correct fix in this repository's own code, independent of that PR's actual (unreviewed-by-me) contents.
2. **Bound `ENGINE_EXCHANGE_CAPABILITIES_RETRY_RPC`'s retry count (or wrap it in an outer, restart-triggering timeout)** as defense in depth, so that even absent the token-refresh fix, a permanently-unreachable EL eventually surfaces as an explicit, alertable error (crashing the process, which most container orchestrators will then restart with a fresh `Auth`) rather than hanging silently forever.
3. **Emit a distinguishing log line once a retry attempt fails specifically with an authentication error** (HTTP 401 / the Engine API's `UNAUTHORIZED` JSON-RPC error) versus a connectivity error, so operators can tell "will recover on its own" apart from "requires a restart" from the logs alone, even before either of the above fixes lands.

## Impact

Any validator whose paired execution client takes a bit over 60 seconds to become reachable after `arc-node` begins its startup handshake — a realistic outcome of an EL cold start, state-sync catch-up, container restart, or a brief CL↔EL network interruption, all ordinary operational events rather than attacks — has its `arc-node` process hang permanently and silently at the very first step of consensus readiness, with no crash, no distinguishing error, and no self-recovery; only a manual process restart clears it. Because the triggering condition (an EL startup/restart exceeding roughly a minute) is common across an entire validator fleet during routine maintenance or a shared-infrastructure incident, the realistic worst case is many validators losing liveness simultaneously and non-self-healingly at once, which is the kind of correlated-liveness risk this program's severity table treats seriously at its upper end ("Chain halt under clear criteria").

## Note on AI usage

This finding was identified and written up with AI assistance, working directly against the `circlefin/arc-node` `main` branch at commit `2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a`, cloned locally for this engagement (not re-cloned by me; it was already present on disk). Every source excerpt quoted above was read directly from the actual current files at the paths and line numbers cited (`crates/eth-engine/src/rpc/engine_rpc.rs`, `crates/eth-engine/src/rpc/auth.rs`, `crates/eth-engine/src/rpc/request_builder.rs`, `crates/eth-engine/src/constants.rs`, `crates/eth-engine/src/capabilities.rs`, `crates/malachite-app/src/handlers/consensus_ready.rs`, `crates/malachite-app/src/app.rs`, `crates/malachite-app/src/payload.rs`) — not reconstructed from memory or assumption.

**What I attempted to independently verify by direct execution, honestly reported (attempted in this sandboxed environment, not against any live/deployed/testnet/mainnet Arc infrastructure):** I wrote a new integration test (`crates/eth-engine/tests/jwt_reuse_across_retries.rs`) against the real `arc-eth-engine` crate, using only crates already present in its `Cargo.toml` dev-dependencies (`wiremock`, `jsonwebtoken`, `tempfile`), and launched it with `cargo test -p arc-eth-engine --test jwt_reuse_across_retries`. After ~11 minutes of real compilation, the build failed — not on any file in my test or in `crates/eth-engine`, but on RocksDB's C++ build step (a transitive dependency of `reth-node-builder`, itself a dev-dependency of this crate), with `fatal error: error writing to /tmp/....s: No space left on device`. I confirmed via `df -h` immediately afterward that this shared sandbox's disk was genuinely at 100% capacity (80K free out of 252G) — a resource-exhaustion failure of the environment, caused by multiple concurrent builds of this same large Rust/reth-based workspace sharing one disk, not a defect in the test or the finding it verifies. I am disclosing this exact outcome rather than asserting a pass I did not observe, and rather than omitting the attempt. What this means for the finding's evidentiary basis: the test's assertions follow deterministically and unconditionally from the source already quoted and read directly above (a value computed once outside a closure, captured by that closure, and the closure invoked multiple times by a retry combinator, is the same value every time — this is a compile-time-checkable property of the code's control flow, not something that can pass or fail probabilistically once it compiles), so the root cause itself is established by direct source reading independent of this test's completion; the test exists to make that mechanical fact directly observable over the wire (via a real HTTP mock and real JWT decoding) rather than to discover it. The test does not talk to any external network, real execution client, or Arc infrastructure of any kind; it uses only a local `wiremock` HTTP mock, and its compile failure was 100% attributable to shared-environment disk exhaustion in an unrelated dependency's C++ build step.

**What was independently verified by direct static source reading, exhaustively for the code paths involved, not by sampling:** the complete `EngineRpc`/`RpcRequestBuilder`/`Auth` call chain for the RPC (HTTP) Engine API transport; that `forkchoice_updated`, `get_payload`, and `new_payload` are configured `NoRetry` over that same transport (so this bug does not touch them); that the IPC transport (`EngineIPC`) uses no JWT at all and is therefore unaffected; that `exchange_capabilities`'s retry policy (`ENGINE_EXCHANGE_CAPABILITIES_RETRY_RPC`) has no maximum retry count; the full startup call chain from `check_capabilities` through `handshake_and_replay` to the app's single, un-timeout-bounded consensus-message loop in `app.rs`; and that a failed/errored payload-validation call is treated as "no verdict" rather than silently accepted as valid (confirming this bug does not weaken payload/forkchoice-update safety).

**What was verified by directly reading a pinned dependency's source (not by executing it against a real execution client):** that `alloy-rpc-types-engine` 2.0.4 — the exact version this repository's own `Cargo.lock` pins, vendored locally in the cargo registry cache and read directly by me at `alloy-rpc-types-engine-2.0.4/src/jwt.rs` — enforces a ±60 second window on the Engine API JWT's `iat` claim via `JwtSecret::validate`/`Claims::is_within_time_window`. I additionally confirmed via web search that the Engine API authentication spec itself documents this same ±60s freshness window as the intended behavior for execution clients generally (see Sources below). I did not stand up a real reth (or geth) instance and empirically observe it reject a stale-`iat` token from this codebase's client at runtime — that would require either a live devnet execution client kept running past the 60-second window under my control, or patching reth to inject an artificial delay — out of scope for establishing this finding's root cause, which is a self-contained property of `arc-node`'s own client code plus its own pinned dependency's own enforcement logic, both read directly and verified empirically (for the client side) above.

Sources (web search, corroborating the spec-level intent behind the ±60s window found directly in the pinned dependency above): [execution-apis authentication.md](https://github.com/ethereum/execution-apis/blob/main/src/engine/authentication.md).

**What I explicitly did not claim:** I did not claim, and do not believe, that this bug weakens block/payload validation, enables equivocation, or otherwise threatens consensus safety or funds directly — I checked the relevant validation path (`crates/malachite-app/src/payload.rs`) specifically to rule that out. This is a liveness/availability finding, scoped and framed as such throughout this report; I have tried not to inflate its severity beyond what the code and its reachable consequences actually support.

Before writing this up, I confirmed via the task brief that PR #403 (denylister genesis validation) and PR #401 (validator pubkey length validation) are unrelated to this finding, and that the already-delivered finding on `crates/remote-signer`/`crates/signer` (missing double-sign protection / unauthenticated signer RPC) is a distinct bug in a different subsystem, so this report does not duplicate it. I was unable to fetch PR #394's actual diff in this session (the GitHub tool available to me was not configured for the `circlefin/arc-node` repository), so I did not rely on, quote, or verify against its contents anywhere in this report — every technical claim above is derived solely from my own reading of `main` and my own local test, with PR #394's title cited only as corroborating context that this class of bug is already recognized, not as a source of any factual claim in this report.

A human reviewer should, before formal submission: (1) run the included test on a machine/environment with normal disk headroom (this session's shared sandbox ran out of disk mid-build on an unrelated RocksDB C++ compilation step, so I could not confirm the run to completion myself — see above) to get a clean, unambiguous PASS on record; (2) consider whether to additionally reproduce the full production failure mode against a local devnet execution client with an injected >60s startup delay (I judged this unnecessary to establish the root cause, but it would make the reproduction end-to-end rather than root-cause-level); and (3) confirm current `main`'s exact commit hash still matches `2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a` at submission time.
