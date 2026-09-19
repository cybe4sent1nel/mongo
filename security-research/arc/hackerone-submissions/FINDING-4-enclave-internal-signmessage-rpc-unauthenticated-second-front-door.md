# Arc Remote Signer's internal Enclave gRPC service (`SignMessage`/`GetPublicKey`/`GenerateKey`) is a second, independently unauthenticated signing oracle — reachable over plain, unencrypted TCP whenever `nitroEnclave.enabled: false`, with no TLS capability even as an option, and taking the raw encrypted key material as a caller-supplied parameter rather than a fixed server-side value

## Assets

- **`circlefin/arc-remote-signer`** — the sole in-scope asset for this finding.
  - `internal/enclave/public/public.go` — the constructor for the enclave-side gRPC server; the only interceptor installed is a protobuf field-shape validator, no authentication of any kind.
  - `internal/enclave/service/enclave/enclave.go` — the `SignMessage`/`GetPublicKey`/`GenerateKey` handlers, which accept `EncryptedKeyMaterial` (the full `{EncryptedPrivateKey, EnclaveEncryptedDataKey, Nonce}` triple) directly as a caller-supplied request parameter, not a fixed value the server alone controls.
  - `internal/enclave/enclave.go` (`Run`) — wires `cfg.NitroEnclave.Enabled` straight into the transport choice with no independent guard.
  - `internal/common/grpc/server/option.go` (`WithListener`) — confirms `ListenerTransportTCP` binds `host:port` from config, while `ListenerTransportVSOCK` ignores `host` entirely and only takes `port`.
  - `configs/enclave.yaml` — the shipped default configuration for this exact server.
  - `internal/common/grpc/client/client.go` (`InsecureDialOptions`) — confirms the host↔enclave gRPC channel is `grpc.WithTransportCredentials(insecure.NewCredentials())` regardless of transport.
  - `deployments/docker-compose.yaml` — the project's own shipped dev-deployment manifest, which sets `APP_NITROENCLAVE_ENABLED: false` for the `enclave` service and publishes `ports: - "10350:10350"` — see "Confirmed live, not hypothetical" below.

## Confirmed live, not hypothetical: the project's own shipped `docker-compose.yaml`

After writing the analysis below from source alone, I checked `deployments/docker-compose.yaml` — the exact manifest this repository's own tooling uses (referenced by the same `make dev` workflow FINDING-1's reproduction steps use) — and it removes any doubt that this is a contrived scenario:

```yaml
services:
  enclave:
    image: "nitro-enclave-signer-internal:local"
    environment:
      ...
      APP_NITROENCLAVE_ENABLED: false        # <-- non-Nitro TCP mode, explicitly
    ulimits:
      memlock: -1
    ports:
      - "10350:10350"                        # <-- explicitly published to the host
    healthcheck:
      test: ["CMD", "grpc_health_probe", "-addr=127.0.0.1:10350", "-service=arc.enclave.v1.EnclaveService"]
    entrypoint: ["/usr/local/circle/run_enclave.dev.sh"]
```

This is not a matter of an operator having to remember to flip a flag differently from the shipped template — **the project's own default dev deployment runs the enclave binary with `NitroEnclave.Enabled=false` and explicitly publishes port `10350` to the host**, exactly the precondition this finding requires. Every environment that runs this stack — CI, local dev, or any deployment that copies this compose file as a starting point without hardening it (the same class of deployment behavior FINDING-1's own severity argument already relies on) — has this unauthenticated, unencrypted signing oracle reachable the moment the host's `10350` is reachable from anywhere else (another container on the same Docker network, or the host's own network interface if not additionally firewalled).

## Summary

This report is a follow-up to FINDING-1 (public `SignerService.Sign`/`PublicKey` has no authentication). That finding, and the two independent HackerOne submissions from another researcher that were subsequently closed as duplicates of it, both focus on the **outer, host-facing** `SignerService` (`internal/app/service/signer`, port `10340`). This report identifies a **second, structurally identical, and independently reachable** unauthenticated signing oracle one layer deeper: the **`EnclaveService`** gRPC server (`internal/enclave/service/enclave`, port `10350`), which is the component that actually holds/decrypts the validator's private key and performs the cryptographic signing operation.

Under the intended production posture (`nitroEnclave.enabled: true`), this service binds via AWS Nitro's `AF_VSOCK` transport, which is hypervisor-isolated and not reachable over any network — this is a legitimate, sound security boundary and I am not disputing it. The problem is what happens when that one flag is `false`:

1. **The exact same shipped config value (`host: 0.0.0.0`) that FINDING-1 flags for the outer service also exists for this inner service, in `configs/enclave.yaml`**, and unlike the outer service, it is **live and network-reachable the moment `nitroEnclave.enabled` is anything other than `true`** — a real, non-hypothetical deployment mode this exact codebase supports and documents (`configs/app.yaml`'s adjacent `provider.enclave.client.baseURL: localhost:10350` comment: *"Used when nitroEnclave.enabled=false (TCP gRPC target)"*). Running without real Nitro Enclave hardware (local/on-prem/non-AWS deployment, cost-saving, or simply an operator toggling the flag without also changing the host binding) is a config a normal person can reach with one changed line, not a hypothetical.
2. **This inner service has no authentication of any kind either** — the only interceptor wired into it (`internal/enclave/public/public.go`) is `protovalidatemw.UnaryServerInterceptor`, a **shape/format** validator (protobuf field constraints), not an identity or authorization check. There is no analog to even the disabled-by-default TLS option the outer service has.
3. **This inner service has *no TLS code path at all*, not even an unused option.** `internal/enclave/public/public.go`'s `New()` never calls `grpcserver.WithTLS` or passes any `grpc.Creds(...)` server option — compare this to the outer `internal/app/public/public.go`, which at least *has* a `cfg.TLS`-gated `WithTLS(...)` call (disabled by default, per FINDING-1, but present). At this layer, TLS isn't merely off by default — it doesn't exist as a capability in the code.
4. **Its `SignMessage`/`GetPublicKey`/`GenerateKey` RPCs take the full encrypted key material as an explicit, caller-supplied request field** (`req.EncryptedKeyMaterial`), rather than a fixed value only the trusted host process ever supplies internally. This is architecturally different — and in one specific way, *worse* — than the outer service: the outer `SignerService.Sign` always signs with one server-cached key the caller cannot choose; this inner `EnclaveService.SignMessage` will decrypt and sign with **whatever key material triple the caller hands it**, provided that triple is well-formed. And that exact triple is sent, unencrypted, from host to enclave on **every single legitimate `Sign` call** the outer service ever makes (`signer.go`'s `Sign()`: `EncryptedKeyMaterial: cached.encryptedKeyMaterial`) — over the same plaintext, insecure gRPC channel (`InsecureDialOptions`) regardless of which transport is in use.

Put together: in any deployment where `nitroEnclave.enabled: false` (a supported, documented mode of this exact codebase, not a hypothetical), an attacker who can reach TCP port `10350` gets a **second, independent** door to the real validator key with zero authentication — and one that is *more* dangerous than the first, because (a) it doesn't require the outer service to be fixed or even present to exploit, and (b) a passive network observer on the plaintext host↔enclave link (relevant whenever the two processes are not sharing a single loopback interface — e.g., separate containers on a Docker/Kubernetes bridge network, or separate hosts in a non-Nitro deployment) can capture one legitimate `EncryptedKeyMaterial` triple off the wire and then replay it directly against this exposed, unauthenticated `SignMessage` RPC indefinitely, entirely bypassing whatever fix is eventually applied to the outer `SignerService` alone.

## Severity

Requested severity: **Extreme / Critical**, for the same reason FINDING-1 is: this is a second path to the identical impact (arbitrary signatures from the real validator key, with no double-sign protection at this layer either — `enclaveSvc.SignMessage` performs no HRS/equivocation check, matching FINDING-1's Report-2-equivalent gap independently at this layer).
Suggested CVSS v3.1: `9.8` (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) for the network-reachable, non-Nitro-deployment case; even restricted to "same-host/same-network-segment attacker," this remains Critical given the direct path to key misuse.

Rationale:
1. Zero authentication gates `EnclaveService`'s RPCs, confirmed by reading the complete interceptor chain in `internal/enclave/public/public.go`.
2. The shipped default config (`configs/enclave.yaml`) contains the same `host: 0.0.0.0` value FINDING-1 flags for the outer service, and it becomes live, unauthenticated, and unencrypted the moment `nitroEnclave.enabled` is toggled off — a supported deployment mode this codebase explicitly documents, not a contrived edge case.
3. Unlike the outer service, there is no TLS option here at all, and the host↔enclave channel that carries the actual key material is unconditionally plaintext, so the exposure compounds: an eavesdropper doesn't even need this RPC to be reachable from far away — capturing one legitimate request off a shared network segment is sufficient to obtain replayable credentials for it.
4. Fixing FINDING-1 alone (adding auth to the outer `SignerService`) does **not** close this gap — it is an independent code path with its own, separate authentication surface.

## Affected Versions

- **`circlefin/arc-remote-signer`**, branch `main`, commit `a9e9fdb48c1e96a6c3fb875aba3d341e6a8af1a6` (same commit as FINDING-1).

## Root Cause

### 1. The enclave-side server installs no authentication interceptor

`internal/enclave/public/public.go`:
```go
func New(cfg *grpcserver.Config, params CreateServerParams) (lifecycle.Runnable, error) {
	validator, err := protovalidate.New()
	...
	grpcServer := grpcserver.NewServer(grpcserver.RequiredEngineParams{
		ServiceName:     params.ServiceName,
		Env:             params.Env,
		APIStatsService: nil,
		UnaryInterceptors: []grpc.UnaryServerInterceptor{
			protovalidatemw.UnaryServerInterceptor(validator),
		},
	})
	pb.RegisterEnclaveServiceServer(grpcServer, params.EnclaveService)

	transport := grpcserver.ListenerTransportTCP
	if params.NitroEnclaveEnabled {
		transport = grpcserver.ListenerTransportVSOCK
	}

	return grpcserver.NewRunnable(
		params.ServiceName,
		grpcServer,
		grpcserver.WithListener(transport, cfg.Host, uint32(cfg.Port)),
		grpcserver.WithHealthServer(pb.EnclaveService_ServiceDesc.ServiceName),
	)
}
```
`protovalidatemw.UnaryServerInterceptor` enforces protobuf field constraints (e.g., a field is present, within a length range) — it has no concept of caller identity. No `grpc.Creds(...)`, no TLS, no API key/token check is ever installed here.

### 2. The transport choice is a single boolean, and only one branch is safe by construction

`internal/common/grpc/server/option.go`:
```go
func WithListener(transport ListenerTransport, host string, port uint32) RunnableOption {
	return func(r *RunnableImpl) error {
		switch transport {
		case ListenerTransportTCP:
			listener, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
			...
		case ListenerTransportVSOCK:
			listener, err := vsock.Listen(port, &vsock.Config{})   // host is silently ignored
			...
		}
	}
}
```
When `NitroEnclaveEnabled` is `true`, `host` is discarded entirely and the listener is bound via `AF_VSOCK`, which only the co-located hypervisor/enclave pair can reach — genuinely safe. When it is `false`, the exact same `host`/`port` values from config become a real TCP bind.

### 3. The shipped default config sets that same dangerous value

`configs/enclave.yaml` (the complete file):
```yaml
public:
  server:
    host: 0.0.0.0
    port: 10350
nitroEnclave:
  enabled: true
```
`host: 0.0.0.0` sits right next to `nitroEnclave.enabled: true` — i.e., the file ships a "safe under the current flag value" host binding with no comment, guard, or validation tying the two together. Flip the one boolean (a one-line change, and per `configs/app.yaml`'s own adjacent comment, an explicitly supported non-Nitro TCP mode: *"Used when nitroEnclave.enabled=false (TCP gRPC target)"*) and the host binding silently becomes live and dangerous. Nothing in `cmd/run_enclave.go` or `internal/enclave/enclave.go` validates this combination or refuses to start:
```go
// cmd/run_enclave.go
Run: func(_ *cobra.Command, _ []string) {
	neCfg = enclave.NewConfig()
	config.LoadConfig(neCfg, neCfgFile)
	err := enclave.Run(neCfg)   // no validation of host+nitroEnclave.enabled combination
	if err != nil {
		panic(err)
	}
},
```

### 4. The RPCs take the actual key material as a caller-supplied parameter

`internal/enclave/service/enclave/enclave.go`:
```go
func (s *Service) SignMessage(ctx context.Context, req *pb.SignMessageRequest) (*pb.SignMessageResponse, error) {
	alg, err := toAlgorithm(req.Algorithm)
	...
	secretKey, err := s.resolveSecretKey(ctx, alg, req.EncryptedKeyMaterial)   // caller-supplied
	...
	signature, err := secretKey.SignMessage(req.Message)
	...
	return &pb.SignMessageResponse{Signature: signature}, nil
}

func (s *Service) resolveSecretKey(ctx context.Context, alg crypto.Algorithm, material *pb.EncryptedKeyMaterial) (crypto.Key, error) {
	plainDataKey, err := s.loadDataKey(material.EnclaveEncryptedDataKey)
	...
	return s.loadSecretKey(ctx, alg, material.EncryptedPrivateKey, plainDataKey, material.Nonce)
}
```
Compare this to the outer `SignerService.Sign`, which always uses one fixed, server-cached `cached.encryptedKeyMaterial` — the caller there cannot select or supply key material at all. Here, the caller supplies the full triple. It is still AES-GCM-authenticated ciphertext (a forged/corrupted triple fails to decrypt), so this is not itself a bypass of the encryption — but it does mean that anyone who *legitimately obtains* one valid triple (see #5) can present it to this RPC directly and receive signatures, independent of the outer service's state, cache, or any future fix applied only there.

### 5. The triple in question crosses an unauthenticated, unencrypted wire on every legitimate call

`internal/app/service/signer/signer.go`, `Sign()`:
```go
resp, err := s.enclavePvd.SignMessage(ctx, &pb.SignMessageRequest{
	Algorithm:            s.algorithm,
	EncryptedKeyMaterial: cached.encryptedKeyMaterial,   // sent over the wire, every call
	Message:              req.Message,
})
```
`internal/common/grpc/client/client.go`:
```go
func InsecureDialOptions(cfg Config, extraInterceptors ...grpc.UnaryClientInterceptor) []grpc.DialOption {
	...
	return []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),   // no TLS, regardless of transport
		grpc.WithChainUnaryInterceptor(unaryInterceptors...),
	}
}
```
This is the dial option used by `internal/app/provider/enclave/enclave.go`'s `New()` for every host→enclave connection. In non-Nitro/TCP mode, this is a genuine plaintext network channel (not vsock), so `EncryptedKeyMaterial` — including, per `prepareEncryptedKeyMaterial`'s own doc comment, the **plaintext** AES data key in non-Nitro mode (`newEncryptedKeyMaterial(encryptedPrivateKey, plainDataKey, nonce)`) — is visible to any passive observer positioned on that network path.

## Steps to Reproduce

I performed direct static verification of the full code path described above (server construction, transport selection, config defaults, RPC handler bodies) against the commit cited. I did not stand up the actual Docker/localstack environment `make dev` requires in this sandboxed environment, so the network reproduction below is derived directly from the source, mirroring the same verified `grpcurl` pattern FINDING-1 used successfully against the outer service (same server framework, same absence-of-auth pattern, same `reflection`-adjacent discoverability at the gRPC level via `protoc`/`grpcurl` against the `.proto` definitions in `proto/arc/enclave/`).

1. Deploy `arc-remote-signer` in the documented non-Nitro mode: set `nitroEnclave.enabled: false` in the enclave service's config (a one-line change from the shipped `configs/enclave.yaml`, and the exact mode `configs/app.yaml`'s own comment describes as supported), while leaving `public.server.host` at its shipped default (`0.0.0.0`) — or simply run the two binaries in separate containers on a shared bridge network with the enclave container's port `10350` published, a routine Docker Compose misconfiguration.
2. From any other host/container that can reach port `10350`:
   ```bash
   grpcurl -plaintext <enclave-host>:10350 list
   grpcurl -plaintext <enclave-host>:10350 describe arc.enclave.v1.EnclaveService
   ```
3. Passively capture one legitimate `SignMessage` request between the host and enclave processes (e.g., `tcpdump`/Wireshark on the shared network segment, since the channel is plaintext gRPC/HTTP2 with no TLS) to obtain a valid `EncryptedKeyMaterial` triple, **or** obtain it via any other means (log capture, memory disclosure, etc.).
4. Replay it directly against the exposed enclave port with an attacker-chosen message:
   ```bash
   grpcurl -plaintext -d '{
     "algorithm": "ALGORITHM_ED25519",
     "encryptedKeyMaterial": { "encryptedPrivateKey": "<captured>", "enclaveEncryptedDataKey": "<captured>", "nonce": "<captured>" },
     "message": "<base64 of attacker-chosen bytes>"
   }' <enclave-host>:10350 arc.enclave.v1.EnclaveService/SignMessage
   ```

### Expected result

A valid signature over attacker-chosen bytes, produced by the real validator key, with zero credentials presented at any point — independent of whatever state or protections exist in the outer `SignerService`.

## Possible Solution

1. **Authenticate `EnclaveService`'s RPCs independently of the outer `SignerService` fix.** Fixing FINDING-1 alone does not address this. At minimum, mutual TLS between the two co-located processes even in non-Nitro/TCP mode (the enclave-side server currently has no TLS code path at all — one needs to be added, not merely enabled).
2. **Never bind `EnclaveService` to `0.0.0.0` in TCP mode.** When `nitroEnclave.enabled: false`, default `public.server.host` to `127.0.0.1`, and consider refusing to start (or requiring an explicit, separately-named "insecure dev mode" flag) if it is ever set to a non-loopback address without TLS.
3. **Validate the `host`/`nitroEnclave.enabled` combination at startup** in `internal/enclave/enclave.go`'s `Run()` or `cmd/run_enclave.go`, refusing to serve on a non-loopback TCP address without explicit operator acknowledgment.
4. **Add the same HRS/equivocation double-sign protection this program already needs at the outer layer (per FINDING-1) at this layer too** — `EnclaveService.SignMessage` currently has no such check either, and any independent fix path (e.g., a future signer implementation that talks to `EnclaveService` directly, bypassing `internal/app/service/signer`) would otherwise reintroduce the exact equivocation risk FINDING-1 already describes.

## Impact

Everything FINDING-1 describes — arbitrary signatures from the real, hardware-isolated validator key, with no double-sign protection, obtainable with zero credentials — is independently reproducible through this second, deeper service, in a documented and supported deployment mode (`nitroEnclave.enabled: false`) that this exact codebase ships config templates for. Because this layer additionally carries the actual key material in plaintext on the wire on every legitimate call, it introduces a passive-eavesdropping path to the same impact that does not exist at all in the outer service (whose `Sign` RPC never transmits key material to its caller). A fix scoped only to `internal/app/public/public.go`/`internal/app/service/signer` (the natural first read of FINDING-1) would leave this path completely open.

## Note on AI usage

This finding was identified and written up with AI assistance, as a direct follow-up to FINDING-1, working against the same `circlefin/arc-remote-signer` `main` branch commit `a9e9fdb48c1e96a6c3fb875aba3d341e6a8af1a6`, cloned fresh for this follow-up pass. Every source excerpt above was read directly from the actual files at the paths cited — `internal/enclave/public/public.go`, `internal/enclave/service/enclave/enclave.go`, `internal/enclave/enclave.go`, `cmd/run_enclave.go`, `internal/common/grpc/server/option.go`, `configs/enclave.yaml`, `configs/app.yaml`, `internal/app/service/signer/signer.go`, `internal/common/grpc/client/client.go` — not reconstructed from memory. I traced the transport-selection logic (`WithListener`'s TCP vs. VSOCK branches) directly to confirm the `host` config value is genuinely dead code under the shipped `nitroEnclave.enabled: true` default and genuinely live under the documented `false` alternative, rather than assuming this from the config file alone. I did not execute the `grpcurl`/`tcpdump` reproduction against a live instance in this sandboxed environment (no Docker/AWS-KMS-localstack dependencies available here); the steps above follow the same pattern independently verified working against the sibling outer service in FINDING-1's reproduction. A human should run this against a real non-Nitro deployment (or a deliberately misconfigured Nitro one) before formal submission, per this program's PoC requirements.
