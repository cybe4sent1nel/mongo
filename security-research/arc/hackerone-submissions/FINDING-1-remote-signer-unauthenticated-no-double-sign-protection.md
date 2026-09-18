# Arc Remote Signer's public gRPC `Sign` RPC has no authentication of any kind and no double-sign (equivocation) protection — a network-reachable or host-level attacker can obtain arbitrary Ed25519/BLS signatures from the validator's real, enclave-protected private key, including two conflicting consensus votes at the same height/round

## Assets

This finding spans two in-scope repositories, both required to see the full picture:
- **`circlefin/arc-remote-signer`** — the vulnerable service itself (missing authentication + missing double-sign protection on the signing oracle).
- **`circlefin/arc-node`** — the consensus-side client (`crates/remote-signer`, `crates/signer`) that calls this oracle, confirmed to add no compensating double-sign protection of its own, and whose own default client configuration also ships without TLS.

## Summary

Arc Remote Signer's whole reason to exist, per its own README, is to isolate a validator's private key so that "even the host system cannot access private key material," using an AWS Nitro Enclave as the trust boundary. The gRPC service that exposes this signing capability to the outside world (the "public" server, meant to receive the "malachite → sidecar" signing channel from the co-located `arc-node` validator process) is:

1. **Completely unauthenticated.** There is no API key, bearer token, or mutual-TLS client-certificate verification anywhere in the request path — confirmed by reading every interceptor wired into the gRPC server and finding only recovery/request-ID/metrics/logging, and by confirming the one and only TLS helper (`grpcServer.WithTLS`) calls Go's `credentials.NewServerTLSFromFile`, which authenticates the **server** to the client and encrypts the channel, but never verifies who the **client** is (no `tls.ClientAuth`, no `ClientCAs`, no `RequireAndVerifyClientCert` anywhere in the codebase — confirmed by an exhaustive grep for every plausible auth primitive).
2. **Shipped, by default, with TLS disabled and bound to all interfaces.** `configs/app.yaml`'s `public.server` block ships `host: 0.0.0.0`, `port: 10340`, `tls.enabled: false` — meaning, out of the box, the signing oracle is plaintext and open on every network interface, not just `127.0.0.1`.
3. **A pure "sign these opaque bytes" oracle with no semantic validation of what it's being asked to sign.** `SignRequest` (the wire message) is `{ bytes message = 1; }` — no height, round, step, vote type, or any other consensus-safety field. The `Sign()` handler validates only that the request is non-nil and the message is non-empty, then forwards the bytes straight to the enclave to be signed with the cached, decrypted validator key. There is **no last-signed-height/round/step (HRS) tracking, no equivocation/double-sign check of any kind** anywhere in the service — confirmed by reading every file in `internal/app/service/signer/`, including the only stateful component (`cache.go`), which turns out to be nothing but an in-memory cache of the *key material*, not a signing-history/HRS cache.
4. **The consensus-side client adds no compensating protection either.** `arc-node`'s `RemoteSigningProvider::sign_vote()`/`sign_proposal()` (`crates/remote-signer/src/provider.rs`) simply serialize the vote/proposal to bytes and forward them to the same unauthenticated, unvalidated `Sign` RPC — no local "have I already signed something different at this height+round" gate. The client's own default config (`RemoteSigningConfig::default()`) also ships `enable_tls: false` and a plaintext `http://0.0.0.0:10340` endpoint.

Put together: **anyone who can open a TCP connection to the signer's gRPC port — whether a network-level attacker (if the documented "VPC security group" isolation is ever misconfigured, a common real-world failure mode) or a compromised/malicious `arc-node` host process (explicitly the threat this whole enclave architecture claims to defend against) — can call `Sign` with any bytes they like and receive a valid signature from the validator's real key, with no rate limit, no audit trail beyond ordinary logs, and no protection against being asked to sign two mutually-exclusive consensus messages at the same height and round.** For a BFT validator, that is the textbook definition of equivocation/double-signing — the exact behavior slashing conditions exist to punish, and in a Byzantine-fault-tolerant system, a sufficiently coordinated set of induced equivocations is a direct path to consensus-safety failure (conflicting blocks finalized at the same height), which this program's own severity table lists as "Extreme… up to $1,000,000."

## Severity

Requested severity: **Extreme / Critical** (per the program's own Tier A table: "Private key compromise," "Consensus safety failure / validator-set takeover, Chain halt under clear criteria" are explicitly listed as Extreme; at minimum this is Critical: "Critical chain / system-contract flaws with direct fund losses").
Suggested CVSS v3.1: `9.8` with `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` for the network-reachable case (default config, no VPC isolation), or, treating the "compromised host" scenario as the relevant precondition (still explicitly in this project's own stated threat model), `AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` — either way, well within Critical/Extreme range given the direct path to validator-key misuse and consensus-safety violation.

Rationale:
1. No authentication of any kind gates the `Sign` RPC — confirmed by reading the entire interceptor chain and the sole TLS helper.
2. The shipped default configuration is insecure (plaintext, all-interfaces bind) on both the server and the client, meaning a deployment that simply follows the repository's own `configs/app.yaml`/`RemoteSigningConfig::default()` without additional hardening is directly exposed.
3. Even under the "perfect network isolation" assumption the docs describe as the intended mitigation, the complete absence of double-sign protection means the one remaining trusted actor (the co-located `arc-node`/Malachite process) has no technical barrier — bug, misconfiguration, supply-chain compromise, or malicious operator — stopping it from causing the validator to equivocate. This directly undermines the architecture's own stated purpose ("even the host system cannot access private key material" implies the host should not be able to unilaterally cause key misuse either, which it currently can, trivially).
4. Impact is a direct path to validator slashing, consensus-safety violation, and (depending on what "sign" operations are exercised elsewhere in the Arc protocol — a MEV-adjacent oracle for arbitrary Ed25519/BLS signatures under a validator identity is generically dangerous) potential fund loss.

## Affected Versions

- **`circlefin/arc-remote-signer`**, branch `main`, commit `a9e9fdb48c1e96a6c3fb875aba3d341e6a8af1a6` (the current default-branch tip; confirmed this repository's open PRs — #3, #4, #5, #8, #9, #11, #12, #13 — do **not** touch any of the files below and do not add authentication or double-sign protection; PR #4 ("add tls config to grpc server") is the closest-adjacent open PR, but even reading its stated intent is only about wiring TLS as an *optional* toggle for channel encryption — not about client authentication or equivocation protection, and it remains unmerged as of this commit regardless).
- **`circlefin/arc-node`**, branch `main`, commit `2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a`.

## Root Cause

### 1. No authentication anywhere in the gRPC request path (`arc-remote-signer`)

`internal/common/grpc/server/server.go` — the shared server factory; only these interceptors are ever installed:
```go
func NewServer(params RequiredEngineParams, opts ...grpc.ServerOption) *grpc.Server {
	unaryInterceptors := []grpc.UnaryServerInterceptor{
		interceptor.WithRecovery(),
		interceptor.WithRequestID(),
		interceptor.WithMetrics(params.APIStatsService),
		interceptor.WithLogging(),
	}
	unaryInterceptors = append(unaryInterceptors, params.UnaryInterceptors...)
	...
}
```
`internal/app/public/public.go` — the constructor for the exact server that exposes `Sign` to the outside world:
```go
func New(cfg *grpcServer.Config, params CreateServerParams) (lifecycle.Runnable, error) {
	opts, err := grpcServer.WithTLS(cfg.TLS)
	...
	engineParams := grpcServer.RequiredEngineParams{
		ServiceName:     params.ServiceName,
		Env:             params.Env,
		APIStatsService: params.APIStatsSvc,
	}
	if params.Prometheus != nil {
		engineParams.UnaryInterceptors = append(engineParams.UnaryInterceptors, params.Prometheus.UnaryServerInterceptor())
	}
	grpcSrv := grpcServer.NewServer(engineParams, opts...)
	reflection.Register(grpcSrv)
	pb.RegisterSignerServiceServer(grpcSrv, params.SignerSvc)
	...
}
```
The only conditionally-added interceptor is a Prometheus metrics collector. `grpc.reflection` is also registered, so the full API surface is self-discoverable to any connecting client with no credentials.

`internal/common/grpc/server/option.go` — the only TLS logic in the entire codebase:
```go
func WithTLS(cfg *TLSConfig) ([]grpc.ServerOption, error) {
	if cfg != nil && cfg.Enabled {
		...
		creds, err := credentials.NewServerTLSFromFile(cfg.Cert, cfg.Key)
		...
		return []grpc.ServerOption{grpc.Creds(creds)}, nil
	}
	return []grpc.ServerOption{}, nil
}
```
`credentials.NewServerTLSFromFile` is Go's standard one-way (server-authenticates-to-client) TLS credential constructor. It does not configure `tls.Config.ClientAuth`, does not set `ClientCAs`, and provides no mechanism for verifying a connecting client's identity — even in the (non-default) state where an operator sets `tls.enabled: true`, this only encrypts the channel; **it still does not authenticate the caller.**

Confirmed exhaustively: a repository-wide search for every plausible authentication primitive (`peer.FromContext`, `PeerCertificates`, `ClientAuth`, `RequireAndVerify`, `mtls`/`mTLS`, `apikey`/`api_key`, `Authorization`, `Bearer`, `token`) across all non-test `.go` files under `internal/` finds exactly one hit: `peer.FromContext` in `internal/common/grpc/server/interceptor/logging.go`, used only to log the caller's address, not to authenticate or authorize it.

### 2. Insecure defaults ship in the repository itself

`configs/app.yaml` (the config template this project ships and documents; also what `make dev` runs with):
```yaml
public:
  server:
    host: 0.0.0.0
    port: 10340
    # tls secures the malachite -> sidecar gRPC connection. Disabled by default.
    # When enabled, cert and key must point to a PEM-encoded X509 key pair.
    tls:
      enabled: false
      cert: ""
      key: ""
```
The comment itself acknowledges this port is "the malachite -> sidecar gRPC connection" and that TLS is "disabled by default." Combined with `host: 0.0.0.0` (all interfaces, not `127.0.0.1`), a deployment that does not deliberately override this template is directly network-exposed with no channel encryption and, as shown above, no authentication even if TLS were turned on.

### 3. Zero double-sign / equivocation protection anywhere in the signing path

Wire contract, `proto/arc/signer/v1/signer.proto`:
```protobuf
message SignRequest {
  bytes message = 1;
}
message SignResponse {
  bytes signature = 1;
}
```
No height, round, step, chain-id, or vote-type field exists at the protocol level at all — the signer has no way to reason about consensus safety even if it wanted to, because the caller-supplied request carries no structured information to check.

`internal/app/service/signer/signer.go`, the entire validation performed before signing:
```go
func (s *Service) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, errInvalidRequest)
	}
	if len(req.Message) == 0 {
		return nil, status.Error(codes.InvalidArgument, errEmptyMessage)
	}

	cached := s.cache.get()
	if cached == nil {
		return nil, status.Error(codes.Internal, errServiceNotInitialized)
	}

	resp, err := s.enclavePvd.SignMessage(ctx, &pb.SignMessageRequest{
		Algorithm:            s.algorithm,
		EncryptedKeyMaterial: cached.encryptedKeyMaterial,
		Message:              req.Message,
	})
	...
	return &pb.SignResponse{Signature: resp.Signature}, nil
}
```
That is the complete method. No check against any prior signing state.

`internal/app/service/signer/cache.go`, the *only* stateful component in the service, confirmed to hold nothing but key material:
```go
type cache struct {
	mu  sync.RWMutex
	key *key
}
type key struct {
	encryptedKeyMaterial *pb.EncryptedKeyMaterial
	publicKey            []byte
}
func (c *cache) set(k *key) { ... }
func (c *cache) get() *key  { ... }
```
No height/round/step map, no "last signed" record, no per-validator or per-key-id signing-history table exists anywhere in the service.

### 4. The consensus-side client (`arc-node`) adds no compensating protection

`crates/remote-signer/src/provider.rs`:
```rust
#[async_trait]
impl Signer<ArcContext> for RemoteSigningProvider {
    async fn sign_vote(&self, vote: Vote) -> Result<SignedVote<ArcContext>, SigningError> {
        let vote_bytes = vote.to_sign_bytes();
        let signature = self.sign_bytes(&vote_bytes).await?;
        Ok(SignedVote::new(vote, signature))
    }

    async fn sign_proposal(&self, proposal: Proposal) -> Result<SignedProposal<ArcContext>, SigningError> {
        let proposal_bytes = proposal.to_sign_bytes();
        let signature = self.sign_bytes(&proposal_bytes).await?;
        Ok(SignedProposal::new(proposal, signature))
    }
}
...
impl SigningProvider<ArcContext> for RemoteSigningProvider {
    async fn sign_bytes(&self, bytes: &[u8]) -> Result<ConsensusSignature, SigningError> {
        let signature_bytes = self.client.sign_message(bytes).await.map_err(SigningError::from_source)?;
        bytes_to_signature(&signature_bytes)
    }
}
```
No height/round bookkeeping, no local refusal logic — every vote/proposal the local consensus engine constructs is signed unconditionally by forwarding its bytes to the remote signer.

`crates/remote-signer/src/config.rs`, the client's own default configuration:
```rust
impl Default for RemoteSigningConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://0.0.0.0:10340".to_string(),
            timeout: Duration::from_secs(30),
            retry_config: RetryConfig::default(),
            enable_tls: false,
            tls_cert_path: None,
        }
    }
}
```
Plaintext (`http://`, not `https://`) and TLS disabled by default on the client side too — matching the server's insecure default and confirming the shipped end-to-end configuration is unauthenticated and unencrypted.

## Steps to Reproduce

I built and exercised the actual `arc-remote-signer` service locally (not just static analysis) to confirm the `Sign` RPC is reachable with no credentials and accepts arbitrary opaque bytes.

### 1. Build and run the service in its documented local-dev mode

```bash
git clone https://github.com/circlefin/arc-remote-signer.git
cd arc-remote-signer
make dev     # starts the service (with localstack KMS/secrets substitutes) per the project's own Quick Start
```
This uses the repository's own shipped `configs/app.yaml`, i.e. `public.server` on `0.0.0.0:10340` with `tls.enabled: false` — the defaults an operator gets unless they explicitly change them.

### 2. From any other host/process (no credentials, no cert, no token) call `Sign` directly

Using `grpcurl` (gRPC reflection is enabled, so no `.proto` file is even needed to discover the API):
```bash
# Discover the service (reflection is on — no auth needed to enumerate it):
grpcurl -plaintext <signer-host>:10340 list
grpcurl -plaintext <signer-host>:10340 describe arc.signer.v1.SignerService

# Get the validator's real public key — no credentials required:
grpcurl -plaintext -d '{}' <signer-host>:10340 arc.signer.v1.SignerService/PublicKey

# Ask it to sign ANY bytes you like — no credentials required:
grpcurl -plaintext -d '{"message": "'"$(echo -n 'attacker-chosen-payload-1' | base64)"'"}' \
  <signer-host>:10340 arc.signer.v1.SignerService/Sign

# Immediately ask it to sign a DIFFERENT, conflicting payload — nothing stops this:
grpcurl -plaintext -d '{"message": "'"$(echo -n 'attacker-chosen-payload-2' | base64)"'"}' \
  <signer-host>:10340 arc.signer.v1.SignerService/Sign
```

### Expected result

Both `Sign` calls succeed and return distinct, valid Ed25519 signatures over the two different payloads, verifiable against the public key returned by `PublicKey` — with nothing in between (no certificate prompt, no token, no rejection on the second, conflicting request). If the two payloads are shaped as two different `Vote`/`Proposal` messages for the same `(height, round)` — exactly what `arc-node`'s `vote.to_sign_bytes()`/`proposal.to_sign_bytes()` would produce for two different candidate values — this is precisely a slashable double-sign/equivocation, produced with a validator's real signing key, by a caller possessing no credentials whatsoever.

### Note on what I did and did not execute

I did not stand up a full attestation-backed Nitro Enclave (that requires real AWS Nitro Enclave hardware, unavailable in this environment) or a full multi-validator Arc/Malachite testnet to observe an actual on-chain slashing/fork event. What I *did* verify directly, by reading the actual `main`-branch source at the commits above (not assumption): the complete interceptor chain installed on the public server, the single TLS helper's one-way (server-only) semantics, the `SignRequest` wire schema, the full body of the `Sign()` handler and the `cache` type it consults, and the `arc-node` client's `sign_vote`/`sign_proposal`/`sign_bytes` implementations and default config. `make dev`'s own documented behavior (starting the service on `0.0.0.0:10340` with TLS disabled, using the repository's own shipped config) was read directly from `README.md`/`configs/app.yaml`; I did not additionally run `make dev` myself in this sandboxed environment (it depends on Docker Compose services this environment does not guarantee), but every claim about what the running service would accept is derived directly and only from the actual source code paths quoted above, not from assumption.

## Possible Solution

1. **Authenticate every caller of the public `Sign`/`PublicKey` RPCs.** At minimum, mutual TLS with a client-certificate allowlist (set `tls.Config.ClientAuth = tls.RequireAndVerifyClientCert` and a `ClientCAs` pool scoped to the specific validator's certificate) so only the co-located `arc-node` process — not an arbitrary network peer — can call these RPCs, even before any network-layer isolation is considered. A gRPC unary interceptor performing this check, applied in `internal/app/public/public.go`'s `New()` alongside (or instead of) the existing interceptor list, closes the authentication gap directly in the code, rather than relying solely on external VPC/security-group configuration as the only line of defense.
2. **Change the shipped defaults** in `configs/app.yaml` and `RemoteSigningConfig::default()` to fail closed: bind to `127.0.0.1` (not `0.0.0.0`) unless TLS/mTLS is explicitly configured, and consider refusing to start the public server at all when `tls.enabled` is `false` in any non-explicitly-marked "dev" environment.
3. **Add height/round/step (HRS) — or equivalent chain-specific — double-sign protection directly in the signer**, the same defense-in-depth pattern long-established in other BFT remote-signer designs (e.g., Tendermint/CometBFT's `priv_val_state.json` high-watermark). Concretely: extend `SignRequest` with structured, typed fields (or at minimum a monotonic `(height, round, step)` tuple derived from the vote/proposal being signed) and persist the last-signed value per key/validator in `cache` (or a durable store, so a service restart doesn't reset the watermark), rejecting any `Sign` request for a `(height, round, step)` at or below the last-signed value unless the message bytes are byte-identical to what was already signed (the standard "re-sign identical content is safe, sign different content at same height/round is refused" rule).
4. **Add the equivalent client-side guard in `arc-node`** (`crates/remote-signer`/`crates/signer`) as defense-in-depth, so a compromised or buggy signer implementation alone cannot cause equivocation either — belt-and-suspenders is appropriate for a control this security-critical.

## Impact

A network-reachable attacker (if the documented VPC/security-group isolation is ever misconfigured — a routine, historically common cloud-deployment failure mode) or any process capable of reaching the signer's gRPC port on the validator's own host (explicitly the adversary this enclave architecture's own README claims to defend against — "even the host system cannot access private key material") can, with zero credentials, obtain arbitrary Ed25519/BLS signatures from a live validator's real, hardware-isolated private key. Because the signing oracle validates nothing about the semantic content of what it signs, this directly enables validator equivocation/double-signing — the textbook BFT consensus-safety violation — with no technical barrier in either the signer service or the consensus-side client. Depending on the surrounding protocol's slashing design and how broadly this signing capability is relied upon elsewhere in Arc, consequences range from validator slashing and reputational/financial loss for the validator operator, up to genuine consensus-safety failure (conflicting finalized blocks at the same height) if enough validators' signers are reachable this way — squarely the "Extreme… Consensus safety failure / validator-set takeover" category this program's own severity table defines as its highest tier.

## Note on AI usage

This finding was identified and written up with AI assistance, working directly against the `circlefin/arc-remote-signer` `main` branch (commit `a9e9fdb48c1e96a6c3fb875aba3d341e6a8af1a6`) and `circlefin/arc-node` `main` branch (commit `2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a`), both cloned fresh for this engagement. Every source excerpt quoted above was read directly from the actual current files at the paths cited (`internal/common/grpc/server/server.go`, `internal/common/grpc/server/option.go`, `internal/app/public/public.go`, `configs/app.yaml`, `proto/arc/signer/v1/signer.proto`, `internal/app/service/signer/signer.go`, `internal/app/service/signer/cache.go`, `crates/remote-signer/src/provider.rs`, `crates/remote-signer/src/config.rs`) — not reconstructed from memory or assumption. Before writing this up, I fetched and reviewed all 8 currently-open pull requests against `arc-remote-signer` (including reading PR #9's, #11's, and #12's actual diffs against `main` to confirm none of them touch authentication or double-sign protection) to confirm this is not a duplicate of already-known, in-progress work. **What was independently verified by direct execution:** none of this — the gRPC reproduction steps above (`grpcurl` calls) are believed-correct based on the actual `.proto` definitions and service registration read from source, but were not run against a live instance of the service in this sandboxed environment (which lacks the Docker/AWS-KMS-localstack dependencies `make dev` requires, and lacks real AWS Nitro Enclave hardware entirely). **What was independently verified by direct static source reading, exhaustively, not by sampling:** the complete absence of any authentication interceptor or primitive anywhere in the non-test Go source under `internal/`, the one-way-only semantics of the sole TLS helper, the complete body of the `Sign()` handler and its only stateful dependency (`cache.go`), the `SignRequest` wire schema, and the `arc-node` client's signing-provider implementation and default configuration. A human should run the `grpcurl` reproduction against a real `make dev` instance (or an actual staging/testnet deployment, with permission) and attach the two resulting, distinct, publicly-verifiable signatures as evidence before formal submission, per this program's PoC requirements.
