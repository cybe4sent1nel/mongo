# Arc Node: `RemoteSigningProvider` never verifies the remote signer's own signature response before use, and defaults to an unencrypted, unauthenticated channel to it

## Assets

- Repository: [`circlefin/arc-node`](https://github.com/circlefin/arc-node)
- Commit: [`2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a`](https://github.com/circlefin/arc-node/tree/2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a)
- Component: [`crates/remote-signer/src/provider.rs`](https://github.com/circlefin/arc-node/blob/2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a/crates/remote-signer/src/provider.rs), [`crates/remote-signer/src/config.rs`](https://github.com/circlefin/arc-node/blob/2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a/crates/remote-signer/src/config.rs)

## Summary

`RemoteSigningProvider` implements both `SigningProvider` (used to sign the node's own votes/proposals) and `Verifier` (used to verify *other* validators' votes/proposals). The `Verifier` implementation correctly calls `verify_signed_bytes`, which does a real Ed25519 verification against the claimed public key:

```rust
async fn verify_signed_bytes(
    &self,
    bytes: &[u8],
    signature: &ConsensusSignature,
    public_key: &PublicKey,
) -> Result<VerificationResult, SigningError> {
    Ok(VerificationResult::from_bool(
        public_key.verify(bytes, signature).is_ok(),
    ))
}
```

But `sign_bytes` — the method that takes whatever came back from **this node's own remote signer** and hands it to consensus to gossip as this validator's vote/proposal signature — never calls that same verification function on its own output:

```rust
async fn sign_bytes(&self, bytes: &[u8]) -> Result<ConsensusSignature, SigningError> {
    let signature_bytes = self.client.sign_message(bytes).await.map_err(SigningError::from_source)?;
    bytes_to_signature(&signature_bytes)
}
```

`bytes_to_signature` performs exactly one check — a length check:

```rust
pub fn bytes_to_signature(signature_bytes: &[u8]) -> Result<ConsensusSignature, SigningError> {
    if signature_bytes.len() == 64 {
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(signature_bytes);
        Ok(ConsensusSignature::from_bytes(sig_array))
    } else {
        Err(SigningError::from_source(eyre!(
            "Invalid signature length: expected {} bytes, got {}",
            signature_bytes.len(), signature_bytes.len()
        )))
    }
}
```

Any syntactically valid 64-byte blob returned by the signer is accepted and used as-is. The code to catch a bad one — cryptographically verifying it against `self.public_key()` and the exact `bytes` that were sent — already exists in this exact file and is exercised by this node against *other* validators, it is simply never invoked on the node's own signing round-trip.

## Attack / Failure Scenario

This is a missing fail-closed check, not by itself a forgeable-signature bug — other honest validators still independently verify any gossiped vote/proposal against the claimed public key before counting it, so a garbage signature from this gap doesn't get miscounted elsewhere. What it removes is this node's own ability to immediately detect, at the moment of signing, that its remote signer returned:
- a signature that doesn't actually verify against its own known public key and the exact bytes it asked to be signed (e.g. a bug in the signer, a version-mismatch between the signer's key material and the node's expected key, or partial data corruption on the signer side reaching just past the length check), or
- (in combination with FINDING-6 in `arc-remote-signer`, the enclave's unbounded keystore cache) a signature produced against attacker-influenced key material if the signer process were itself compromised or misconfigured.

Instead of failing closed at the source, a bad signature is gossiped to the network as this validator's own vote/proposal, where it will simply be rejected by peers as an invalid signature — turning what could have been an immediate, precise, node-local error ("my signer returned garbage, stop and alert") into a network-visible bad vote that peers have to independently detect and discard, and that this validator won't otherwise know to investigate.

Compounding this: `RemoteSigningConfig::default()` sets `enable_tls: false` —

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

so unless an operator explicitly opts into TLS, the channel between `arc-node` and its remote signer is plaintext and unauthenticated on the client side too — matching (and doing nothing to independently compensate for) the sibling `arc-remote-signer` repo's already-reported lack of authentication on that same port (`10340`).

## Severity

**Medium.** Bounded impact: no forged signature is ever actually counted by the network, since every other validator independently re-verifies. What's lost is a cheap, already-implemented, fail-closed defense-in-depth check on this node's own hot signing path, plus an insecure-by-default transport setting that removes a layer of protection an operator would otherwise have to know to opt into. This matches this program's "Medium: bounded impact with compensating controls" bar — the compensating control here being independent peer-side signature verification across the rest of the network.

## Possible Solutions

1. In `sign_bytes`, after receiving a signature from the remote signer, call `self.verify_signed_bytes(bytes, &signature, &self.public_key().await?)` (the exact function already implemented in this file) before returning it to the caller, and fail loudly/alert if it doesn't verify.
2. Set `enable_tls: true` as the default in `RemoteSigningConfig::default()`, requiring an explicit opt-out rather than an explicit opt-in, so a default/forgotten configuration is the secure one.

## Note on AI usage

This finding was produced through static source review by an AI assistant (Claude), guided by a human researcher, using a fresh clone of the repository at the commit above. All cited line numbers and code excerpts (`provider.rs`'s `sign_bytes`/`verify_signed_bytes`/`bytes_to_signature`, `config.rs`'s `Default` impl) were directly verified by reading the actual source files, independently of an automated sub-agent's initial pass. No live exploit was executed against a running node or signer.
