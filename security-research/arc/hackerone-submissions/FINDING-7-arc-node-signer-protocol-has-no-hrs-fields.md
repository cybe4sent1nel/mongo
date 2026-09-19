# Arc Node: the node-defined remote-signer wire protocol carries no height/round/step/chain-id fields, making double-sign protection structurally impossible to add on the signer side alone

## Assets

- Repository: [`circlefin/arc-node`](https://github.com/circlefin/arc-node)
- Commit: [`2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a`](https://github.com/circlefin/arc-node/tree/2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a)
- Component:
  - [`crates/remote-signer/proto/arc/signer/v1/signer.proto`](https://github.com/circlefin/arc-node/blob/2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a/crates/remote-signer/proto/arc/signer/v1/signer.proto)
  - [`crates/remote-signer/src/client.rs`](https://github.com/circlefin/arc-node/blob/2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a/crates/remote-signer/src/client.rs)
- Related sibling-repo finding: `circlefin/arc-remote-signer`'s own `Sign` RPC was already found (and reported/closed as duplicate) to have no height/round/step double-sign protection. This finding traces that gap to its root: it is not just an implementation oversight in the signer, it is baked into the interface **arc-node itself defines and calls**.

## Summary

`arc-node`'s own `.proto` contract for talking to a remote signer is:

```proto
service SignerService {
  rpc PublicKey(PublicKeyRequest) returns (PublicKeyResponse) {}
  rpc Sign(SignRequest) returns (SignResponse) {}
}

message SignRequest {
  bytes message = 1;
}
message SignResponse {
  bytes signature = 1;
}
```

There is no `chain_id`, `height`, `round`, or vote/proposal-type field anywhere on the wire — `Sign` is "sign these opaque bytes," full stop. The client-side call site confirms this is exactly what's sent (`crates/remote-signer/src/client.rs:229-231`):

```rust
let request = Request::new(proto::SignRequest {
    message: message.to_vec(),
});
```

The actual height/round/vote-type information exists only *inside* the SSZ-serialized `Vote`/`Proposal` payload that gets encoded into `message` (see `crates/types/src/vote.rs`'s and `crates/types/src/proposal.rs`'s `to_sign_bytes()`). A signer would have to understand arc's specific SSZ vote/proposal encoding just to *extract* height/round/step from an opaque byte blob before it could enforce any watermark — the protocol gives it no structured, signer-agnostic way to do so. (The `.proto` file's own header comment credits it as derived from AvalancheGo's raw-bytes signer design — a different consensus model that doesn't need HRS watermarking, which explains why this shape was chosen but doesn't make it safe for a Tendermint/Malachite-style BFT signer.)

**Practically, this means double-sign protection cannot be fixed by patching the signer in isolation** (e.g. `arc-remote-signer`) — the wire protocol itself has to grow explicit height/round/step/chain-id fields, and `arc-node`'s client has to start sending them, before any signer implementation (remote or local) can enforce a watermark without fragile, arc-specific SSZ parsing on the signer side.

## Root Cause

**1. The `.proto` message has no consensus-identifying fields at all**
([`signer.proto#L34-L39`](https://github.com/circlefin/arc-node/blob/2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a/crates/remote-signer/proto/arc/signer/v1/signer.proto#L34-L39)):

```proto
message SignRequest {
  bytes message = 1;
}
```

**2. The client sends exactly that — raw bytes, no metadata**
([`client.rs#L229-L231`](https://github.com/circlefin/arc-node/blob/2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a/crates/remote-signer/src/client.rs#L229-L231)):

```rust
let request = Request::new(proto::SignRequest {
    message: message.to_vec(),
});
```

**3. Default endpoint matches the sibling repo's known-unauthenticated public port**
([`crates/remote-signer/src/config.rs#L33-L42`](https://github.com/circlefin/arc-node/blob/2a3e8ab10c0ac97bf1a2628a325eb98d4a468b1a/crates/remote-signer/src/config.rs#L33-L42)):

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

This is the exact port (`10340`) that `arc-remote-signer`'s public `SignerService` listens on with zero authentication by default — confirming end-to-end that arc-node's default client configuration, the wire protocol it speaks, and the signer's default posture all line up to produce the same gap from both directions.

## Attack / Failure Scenario

This is primarily an **operational-precondition** issue rather than something a pure remote attacker can trigger against a single, correctly-run validator: Malachite's write-ahead log (`crates/malachite-app/src/node.rs`) gives a validator's own process some protection against re-signing after a simple restart. The realistic scenario is:

- An operator runs (even briefly, e.g. during a blue/green deploy, HA failover, or disaster-recovery restore from an older snapshot) **two `arc-node` processes pointed at the same remote signer key**, or restores validator state from a backup that predates the signer's own knowledge of what it already signed.
- Because the wire protocol carries no height/round/step/chain-id, the signer has no signer-agnostic way to notice that request A (from process 1) and request B (from process 2) are for conflicting content at the same height/round — it only sees two opaque byte blobs and (per the sibling finding) signs both.
- Both conflicting precommits are now validly signed by the same validator key — a real equivocation, contributing directly toward a consensus safety violation if enough validators are simultaneously affected (e.g. a fleet-wide migration procedure repeated across many operators).

## Severity

**High.** The worst-case blast radius (equivocation contributing to a BFT safety violation) is Extreme-tier *in kind*, but actually reaching it requires an operational precondition (dual live signer clients against one key, or a state restore that loses the local WAL) rather than being triggerable by an unprivileged remote attacker against a single well-run validator — consistent with this program's own framing that operational/preconditioned issues sit at High rather than Extreme. I'm deliberately not claiming Extreme here: I have not demonstrated a path where a remote, unprivileged attacker alone (with no operational misstep on the validator operator's part) can force this condition.

## Possible Solutions

1. Extend `SignRequest`/`SignResponse` (and the equivalent local-signing path) with explicit `chain_id`, `height`, `round`, and vote/proposal-type fields, so any conforming signer implementation can enforce a last-signed watermark without needing to parse arc's internal SSZ encoding.
2. Until the protocol is extended, document prominently (and ideally enforce operationally, e.g. via a leader-election/lock mechanism) that exactly one live `arc-node` process may ever be configured against a given remote-signer key at a time.
3. See also FINDING-8 (same repo) for a related, independently exploitable gap: the client doesn't even verify the signer's response is valid for what it asked to be signed, which would at least provide fail-closed defense-in-depth against a misbehaving/compromised signer if implemented.

## Note on AI usage

This finding was produced through static source review by an AI assistant (Claude), guided by a human researcher, using a fresh clone of the repository at the commit above. All cited line numbers and code excerpts were directly verified by reading the actual source files (not taken solely from an automated sub-agent's initial pass, which was independently re-checked line-by-line). No live network/exploit was executed; the attack scenario is a reasoned trace through the real code, and its likelihood/severity assessment should be validated against Circle's actual operational deployment/runbook practices, which this review has no visibility into.
