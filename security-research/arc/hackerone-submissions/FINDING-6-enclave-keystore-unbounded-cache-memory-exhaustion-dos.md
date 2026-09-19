# Arc Remote Signer: Unbounded in-process keystore cache on the Enclave gRPC service allows trivial unauthenticated memory-exhaustion DoS of the validator's signer

## Assets

- Repository: `circlefin/arc-remote-signer`
- Commit: `a9e9fdb48c1e96a6c3fb875aba3d341e6a8af1a6`
- Component: `internal/enclave/provider/keystore/keystore.go` (`ProviderImpl`), consumed by
  `internal/enclave/service/enclave/enclave.go` (`Service.loadDataKey`, `Service.loadSecretKey`, `Service.GenerateKey`)
- Reachability precondition: the enclave-internal `EnclaveService` gRPC server (port 10350).
  This is the exact same reachability this report's companion finding
  (FINDING-4, "Enclave-internal SignMessage RPC unauthenticated, second front door")
  already demonstrated is **live by default** in the project's own shipped
  `deployments/docker-compose.yaml` (`APP_NITROENCLAVE_ENABLED: false` +
  `ports: - "10350:10350"`, i.e. plain unauthenticated TCP, not VSOCK).

## Summary

`EnclaveService.GetPublicKey` and `EnclaveService.SignMessage` both accept a caller-supplied
`EncryptedKeyMaterial.EnclaveEncryptedDataKey` field. In non-Nitro (plain TCP) mode this field
is treated as the raw 32-byte AES-256 data key itself (see FINDING-4's root cause #4). The
handler validates only that the value is exactly 32 bytes
(`internal/enclave/common/crypto/aes/aes.go:Deserialize`), then unconditionally stores it in
a package-level, mutex-guarded Go map (`keystore.ProviderImpl.store`) **keyed by the attacker-supplied
bytes themselves**, with no size cap, no entry limit, no TTL, and no eviction policy of any kind.

Because the cache key is derived directly from attacker input, and caching happens
*before* the (separate) AES-GCM decrypt of the private key is attempted — so it happens
even when that decrypt subsequently fails — every RPC call carrying a distinct, well-formed-length
data key value permanently adds one entry to this map for the lifetime of the process. There is
no authentication, no rate limiting, and no per-client quota anywhere in this call path
(confirmed in the earlier sweep: the interceptor chain is `WithRecovery/WithRequestID/WithMetrics/WithLogging`
plus `protovalidatemw`, none of which throttle or bound repeated calls; no `MaxRecvMsgSize`/`MaxConcurrentStreams`
limits are configured on the gRPC server either, see `internal/common/grpc/server/server.go`).

An attacker who can reach the enclave gRPC port can therefore grow the enclave process's heap
without bound simply by sending a stream of `GetPublicKey` (or `SignMessage`) requests, each with
a fresh random 32-byte `EnclaveEncryptedDataKey` and arbitrary `EncryptedPrivateKey`/`Nonce` values.
Each call is cheap to construct (no cryptographic work required client-side) and is answered with
an error (decrypt failure) but still leaves a permanent map entry behind. Sustained traffic will
exhaust the enclave's memory and crash the process (Nitro Enclaves have a fixed, provisioned memory
allocation with no host swap), taking down the validator's ability to sign — a liveness/availability
failure for the exact system this project exists to keep highly available.

## Root Cause

**1. Keystore has no bound at all** (`internal/enclave/provider/keystore/keystore.go:34-53`):

```go
type ProviderImpl struct {
	mu    sync.RWMutex
	store map[string]crypto.Key
}

func (p *ProviderImpl) Set(ciphertext []byte, secretKey crypto.Key) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.store[hex.EncodeToString(ciphertext)] = secretKey
	return nil
}
```

No max-size check, no LRU/TTL eviction, no metric even tracking map size. `Set` cannot fail
(always returns `nil`), so nothing upstream ever backs off.

**2. The cache key is attacker-controlled, and caching happens unconditionally on the data-key path**
(`internal/enclave/service/enclave/enclave.go:169-200`):

```go
func (s *Service) loadDataKey(enclaveEncryptedDataKey []byte) ([]byte, error) {
	if dataKey := s.keystore.Get(enclaveEncryptedDataKey); dataKey != nil {
		return dataKey.Serialize()
	}
	plainDataKey := enclaveEncryptedDataKey
	if s.nitroEnclaveEnabled {
		... // KMS decrypt path, not relevant to the TCP-mode attack
	}
	dataKey, err := aesCommon.Deserialize(plainDataKey)  // only checks len == 32
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to deserialize data key")
	}
	if err := s.keystore.Set(enclaveEncryptedDataKey, dataKey); err != nil { // unconditional cache
		return nil, status.Error(codes.Internal, "failed to cache data key")
	}
	return dataKey.Serialize()
}
```

`aesCommon.Deserialize` (`internal/enclave/common/crypto/aes/aes.go:55-62`) performs exactly one
check:

```go
func Deserialize(data []byte) (*Key, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("invalid key size: expected %d, got %d", 32, len(data))
	}
	return &Key{secretKey: data}, nil
}
```

Any random 32-byte value passes. It is then cached under its own hex encoding as the map key
before the caller's actual goal (decrypting `EncryptedPrivateKey` with it, in `loadSecretKey`)
is even attempted — so a request that is guaranteed to fail the subsequent GCM auth check
(because the "private key" ciphertext and nonce are also attacker junk) *still* leaves a
permanent entry in `store`.

**3. Both `GetPublicKey` and `SignMessage` reach this path directly from the wire**
(`internal/enclave/service/enclave/enclave.go:113-167`), with no request-level authentication or
per-caller quota anywhere in the interceptor chain (confirmed via `internal/enclave/public/public.go`,
which registers only `protovalidatemw` beyond the shared base chain
`WithRecovery/WithRequestID/WithMetrics/WithLogging` from `internal/common/grpc/server/server.go`).
`protovalidatemw` checks field *shape* (e.g. required-ness), not distinctness or rate.

**4. No gRPC server-side resource limits are configured** (`internal/common/grpc/server/server.go:30-48`):

```go
opts := []grpc.ServerOption{
	grpc.ChainUnaryInterceptor(baseInterceptors...),
	grpc.StatsHandler(otelgrpc.NewServerHandler()),
}
return grpc.NewServer(opts...)
```

No `grpc.MaxConcurrentStreams`, no connection-level rate limiting, nothing that would slow an
attacker opening many streams/connections and firing requests as fast as the network allows.

## Steps to Reproduce (not executed live; static call-chain trace)

Precondition: enclave gRPC service reachable over plain TCP (confirmed live default per
FINDING-4, e.g. `deployments/docker-compose.yaml`, or any Nitro deployment operated with
`nitroEnclave.enabled: false`).

```bash
# Pseudocode / grpcurl loop — each iteration uses a FRESH random 32-byte value
# for enclave_encrypted_data_key, and arbitrary bytes for the other two fields.
for i in $(seq 1 5000000); do
  DATA_KEY_B64=$(head -c 32 /dev/urandom | base64)
  CIPHER_B64=$(head -c 32 /dev/urandom | base64)
  NONCE_B64=$(head -c 12 /dev/urandom | base64)
  grpcurl -plaintext -d "{
    \"algorithm\": \"ALGORITHM_ED25519\",
    \"encrypted_key_material\": {
      \"encrypted_private_key\": \"$CIPHER_B64\",
      \"enclave_encrypted_data_key\": \"$DATA_KEY_B64\",
      \"nonce\": \"$NONCE_B64\"
    }
  }" enclave-host:10350 arc.enclave.v1.EnclaveService/GetPublicKey >/dev/null 2>&1 &
done
```

Each request is rejected (decrypt failure), but each *also* leaves a permanent ~(32-byte key +
map/string overhead) entry in `ProviderImpl.store`. At sufficient request volume/concurrency
(bounded only by network throughput — no auth, no rate limit, no backoff), the enclave's
fixed, non-swappable memory allocation is exhausted and the process is OOM-killed, taking the
validator's signer offline until manually restarted.

## Possible Solutions

1. Bound the keystore: cap `len(store)` and evict (LRU or TTL) once the cap is reached, or
   reject new insertions past a configured maximum with a clear `ResourceExhausted` gRPC status
   instead of silently growing forever.
2. Do not cache data-key material derived from a request that has not yet been fully validated
   end-to-end (i.e., only cache after the corresponding private-key decrypt succeeds), so a flood
   of doomed-to-fail requests cannot populate the cache at all.
3. This is a second, independent reason (beyond FINDING-4's authentication gap) to require
   authentication and per-caller rate limiting on the `EnclaveService`, and/or restrict it to
   VSOCK-only transport with no TCP fallback in any deployment profile.
4. Set `grpc.MaxConcurrentStreams` and connection/request-rate limits on the shared gRPC server
   builder (`internal/common/grpc/server/server.go`) as defense-in-depth against this and similar
   resource-exhaustion patterns on any current or future RPC.

## Severity

**High** (CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = 7.5, using network as the attack
vector since this shares FINDING-4's confirmed-live TCP-reachable default; if scored purely for
a correctly configured Nitro/VSOCK-only deployment, the attack vector drops to Adjacent and the
score to `AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = 6.5, still High). This is a pure availability
issue — no key material or signing capability is exposed by this bug on its own — but for a
remote signer whose entire purpose is keeping a validator continuously available to sign, an
easy, unauthenticated, unbounded-memory DoS against the signing process itself is a serious
liveness risk (missed signing duties / potential downtime penalties depending on the consensus
protocol using this signer).

## Impact

Any party able to reach the enclave's gRPC port (confirmed to be the plain, unauthenticated
TCP default per FINDING-4) can crash the enclave process — and therefore stop the validator
from signing — with a trivial, cheap, unauthenticated flood of malformed requests. No
cryptographic material is exposed by this specific bug; the impact is availability, not
confidentiality or integrity. It compounds the severity of FINDING-4: that finding shows the
port is reachable and unauthenticated for signing abuse, and this finding shows the same
reachability is also sufficient to kill the process outright.

## Note on AI usage

This finding was produced through static source review (reading the actual Go source in this
repository at the commit above) by an AI assistant (Claude), guided by a human researcher. The
reproduction steps above are a call-chain trace through the real code, not the output of an
executed exploit — no live enclave was stood up to trigger and confirm the OOM condition. The
severity/impact analysis should be verified empirically (e.g., running the actual enclave binary
in non-Nitro mode locally and observing map growth/RSS under the described load) before this is
treated as fully confirmed; the code-level claims (unbounded map, unconditional caching before
decrypt success, no rate limiting anywhere in the interceptor chain or server options) were
directly verified by reading the cited files in full.
