# MongoDB 8.3.8 — pre-auth OOM/DoS static audit (2026-08-28)

**Status: static-only.** This session's container has no `mongod` binary available (see
`2026-08-28-container-reset-recovery-note.md`) and both `fastdl.mongodb.org` and Docker Hub's blob
CDN (`production.cloudfront.docker.com`) are policy-blocked, so none of this could be dynamically
re-verified this pass. Every citation below is against a fresh `git fetch` of the exact `r8.3.8`
commit (`d100bf19961251f273e1d0bd8ce66fc60634f53c`, pulled directly from `github.com/mongodb/mongo`
— that path isn't blocked, only bulk binary/image downloads are).

**Scope:** code paths reachable by a connection that has sent bytes but not yet completed
authentication — the wire-protocol message framing/decompression layer and the pre-auth/post-auth
transition itself. Three concrete hypotheses traced end to end; all three closed (properly
guarded), confirmed by reading the actual enforcement code rather than assuming maturity implies
safety.

## 1. Wire-protocol decompression bomb — closed

Classic pre-auth DoS shape: a small compressed `OP_COMPRESSED` message claiming a huge declared
uncompressed size, forcing a large allocation before (or instead of) any real decompression work.
Traced `MessageCompressorManager::decompressMessage()`
(`src/mongo/transport/message_compressor_manager.cpp:124-186`):

- `compressionHeader.uncompressedSize < 0` is rejected outright.
- The claimed size is checked against a caller-supplied `maxMessageSize` **before** any allocation:
  `bufferSize > maxMessageSize` → rejected with `"Decompressed message would be larger than
  maximum message size"`.
- Independently, each compressor's own `getMaxDecompressedSize(input)` (implemented by all three —
  zstd, zlib, snappy; none default to `nullopt`/unchecked) cross-validates the claimed size against
  what the actual compressed bytes could plausibly decompress to, rejecting a mismatch before
  decompression runs.
- Only after both checks pass is `SharedBuffer::allocate(bufferSize)` called.

This alone would already be a solid defense at the default post-auth ceiling
(`MaxMessageSizeBytes = 48,000,000`, `rpc/message.h:52`, a fixed compile-time constant, not
attacker-influenceable) — but see #2 for how it's tightened specifically for pre-auth traffic.

## 2. Pre-auth message-size ceiling — separately configured, and correctly threaded through decompression

MongoDB maintains a **separate, much tighter** size ceiling specifically for not-yet-authenticated
connections: `preAuthMaximumMessageSizeBytes` (`transport_options.idl:193-200`, default **16,384
bytes** — roughly 3,000x smaller than the 48MB post-auth ceiling). Confirmed this is:

- Enforced on the raw wire-level message length **before** any decompression, in
  `CommonAsioSession::sourceMessageImpl()` (`transport/asio/asio_session_impl.cpp:660-693`):
  `msgLen > maxMessageSize` is rejected, where `maxMessageSize` is
  `isPreauthIngress() ? gPreAuthMaximumMessageSizeBytes.loadRelaxed() : MaxMessageSizeBytes`.
- **Also** threaded through to the *decompression* size check specifically — this is the part
  worth tracing explicitly rather than assuming, since a smaller raw-wire cap doesn't automatically
  imply a smaller decompressed-size cap if the two checks aren't wired together. Confirmed they
  are: `SessionWorkflow::Impl::WorkItem::decompressRequest()`
  (`transport/session_workflow.cpp:631-641`):
  ```cpp
  _in = isPreAuth(_swf->client())
      ? uassertStatusOK(compressorMgr().decompressMessage(
            _in, &cid, gPreAuthMaximumMessageSizeBytes.loadRelaxed()))
      : uassertStatusOK(compressorMgr().decompressMessage(_in, &cid));
  ```
  A pre-auth connection's `decompressMessage()` call explicitly passes the 16KB pre-auth ceiling as
  `maxMessageSize`, not the default 48MB — closing the specific gap this audit set out to check
  (a small on-wire message that decompresses to something far larger, before the connection has
  authenticated).

## 3. Pre-auth/post-auth classification — correctly tied to real authentication state, not spoofable

Whether a connection gets the tight 16KB ceiling or the normal 48MB one depends on
`isPreAuth(Client*)` (`session_workflow.cpp:395-406`):
```cpp
if (!AuthorizationSession::exists(client)) {
    return true;
}
const auto authorizationSession = AuthorizationSession::get(client);
if (authorizationSession->shouldIgnoreAuthChecks()) {
    return false;  // auth disabled entirely -- never pre-auth
}
return !authorizationSession->isAuthenticated();
```
This is re-evaluated (not cached-and-forgotten) at the two call sites that matter
(`session_workflow.cpp:432` on session construction, `:837` per-request) via
`session()->setPreauthIngress(isPreAuth(client()))`, and keys off
`AuthorizationSession::isAuthenticated()` — the real, load-bearing authentication flag SASL/x.509
completion actually sets — not a weaker proxy like "has sent a `hello`" or "has picked a
compressor." No path was found where a connection could get reclassified as post-auth (and thus
the larger message-size ceiling) without genuinely completing authentication.

## Net result

Three real, deliberately-engineered defenses against pre-auth memory-amplification DoS, all traced
to the actual enforcement code and confirmed intact in `r8.3.8` — this reads as mature,
purpose-built hardening (consistent with this class of bug having real historical precedent against
MongoDB), not something to expect a fresh gap in without a considerably larger investment than a
single static pass. No new pre-auth OOM/DoS bug found this round.

## Not yet covered in this pass (candidates for a follow-up static or live round)

- SASL/SCRAM conversation handling (`saslStart`/`saslContinue`) — mechanism negotiation, nonce/salt
  parsing, iteration-count handling; all genuinely pre-auth by definition.
- X.509 certificate/DN parsing during the TLS handshake — already covered by an earlier pass in
  this broader program, not re-audited fresh in this session (not reconstructed here since the
  earlier pass's specific write-up wasn't recoverable — see the recovery note).
- Connection-acceptance/backlog behavior under a raw connection flood (distinct from the
  message-content-based vectors checked above).
- `hello`/`isMaster`'s own arbitrary client-metadata BSON field — bounded indirectly by the 16KB
  pre-auth message-size ceiling and the standard 200-level BSON depth limit, both already confirmed
  above and elsewhere in this program, so not expected to be a fresh avenue without finding a way
  around either of those ceilings first.

This is a static-only pass. Live pentesting against these (and any other) surfaces remains blocked
until a `mongod` binary is available again in this environment.
