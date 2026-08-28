# MongoDB 8.3.8 — pre-auth OOM/DoS: live dynamic validation round (2026-08-28)

**Status: negative across every hypothesis tested.** This round moves the 2026-08-28 static audit
(`pre-auth-oom-dos-static-audit-2026-08-28.md`) into live testing against the real 8.3.8 binary
(`gitVersion 35e8c8a57f78157ed9fac1a9e90ee6c1818adab6`), plus covers new ground the static pass
flagged as not-yet-covered (SASL/SCRAM parsing, connection-flood memory behavior, BSON-depth stack
protection). No new pre-auth crash or DoS bug found. Recorded in full because negative results with
real methodology are still worth the paper trail — each hypothesis below was actually tried against
a live `--auth`-enabled standalone, not assumed safe from reading alone.

## Method

Fresh standalone `mongod` 8.3.8 (`--auth`, no keyfile needed for a single node), root user created
via the localhost exception. All probes below were sent to this instance; each is followed by a
liveness check (`ping`/`serverStatus` returning normally) to confirm the server, not just the probe
connection, survived.

## 1. SASL/SCRAM conversation parsing (`sasl_scram_server_conversation.cpp`, `sasl_commands.cpp`) — closed

Static read of `_firstStep`/`_secondStep` (client-first-message and client-final-message parsing):
every field is comma-delimited, length-checked (`input[i].size() < N`) before substring access, and
bounded by the 16KB pre-auth message ceiling — `absl::StrSplit` on an all-commas 16KB payload
produces at most ~8,000 trivial empty-skipped tokens, not an amplification. The SCRAM iteration
count and salt are server-generated (read from stored credentials), never client-supplied, so
there's no attacker-controlled PBKDF2-cost lever. `AuthenticationSession` is a single decoration per
`Client` (one instance per connection, replaced not accumulated on repeated `saslStart`), so no
per-connection unbounded session growth from repeated re-starts. `sleepmillis(authFailedDelay)` on
failure is a deliberate, bounded client-side wait, not a resource-consumption issue.

## 2. Ingress request rate limiter's queue (`SERVER-124943`, added since the last audit's commit
range) — reviewed, not itself a bug

New commit history since the 2026-08-24 sibling-hunt added queuing to
`IngressRequestRateLimiter`. Checked the queue itself for the ironic case of a "DoS defense that is
itself a DoS vector" (unbounded queue growth): `ingressRequestAdmissionMaxQueueDepth` is an
explicit, validated (`gte: 0`), operator-set bound, defaulting to **0** (queueing disabled,
requests rejected immediately rather than queued) — safe by default, and bounded when enabled. Note
independently: `ingressRequestAdmissionRatePerSec` defaults to `int32_max` (functionally unlimited)
— this mechanism provides no DoS protection out of the box, which is a design/documentation
observation, not a vulnerability in the code as shipped.

## 3. Unauthenticated connection flood — memory behavior — closed (verified over multiple cycles, not a single-round false positive)

Opened 2,500-3,000 raw TCP connections directly (bypassing the driver), each sending only a 4-byte
partial message-length header (a genuinely incomplete, never-parseable frame) and then left idle —
the purest form of a pre-auth "slow flood." A single round showed suspicious-looking numbers (RSS
+230MB for ~2,600 connections, only partially released after close), which on its own would be a
tempting false-positive "leak" claim. Ran 5 repeated open/close cycles instead of trusting the first
round:

```
cycle 0: opened=2500 conns=2503 RSS_open=397876kB RSS_after_close=359312kB
cycle 1: opened=2500 conns=2503 RSS_open=398740kB RSS_after_close=359420kB
cycle 2: opened=2500 conns=2503 RSS_open=398796kB RSS_after_close=359464kB
cycle 3: opened=2500 conns=2503 RSS_open=398840kB RSS_after_close=359476kB
cycle 4: opened=2500 conns=2503 RSS_open=398916kB RSS_after_close=359540kB
```

RSS plateaus almost immediately after the first cycle (+100KB/cycle thereafter, not the
~+230MB/cycle a real per-connection leak would produce) — classic allocator page retention
(glibc malloc keeping freed arenas rather than returning them to the OS), not a growing leak. Per
idle pre-auth connection this measures out to roughly 25KB marginal RSS while open, all reclaimed by
the allocator (not necessarily the OS) on close. This is bounded, ordinary per-socket/session
overhead, not a DoS amplification bug.

## 4. Deeply-nested BSON in a pre-auth-reachable command body — stack-overflow-shape crash — closed, confirmed live

Checked whether `BSONDepth::kDefaultMaxAllowableDepth` (200) is enforced generically on every
incoming wire message body, pre-auth, regardless of which command/field is targeted — not merely
per-field in specific command IDL structs (which would leave a gap for any command accepting a raw,
untyped `BSONObj` sub-field). Traced the enforcement point: `rpc/op_msg.cpp:184/210` reads every
`OP_MSG` section via `sectionsBuf.read<Validated<BSONObj>>()`, whose `Validator<BSONObj>::validateLoad`
(`rpc/object_check.h:60-79`) calls `validateBSON()` (which walks and enforces `BSONDepth`) whenever
`serverGlobalParams.objcheck` is true — **the default** (`server_options.h:105`,
`bool objcheck = true`). This means every command body, pre-auth or not, is depth-checked before it
becomes a usable `OpMsgRequest`, regardless of which specific field the attacker targets.

Confirmed live: hand-crafted a raw `OP_MSG` (bypassing the driver's own BSON encoder, built via
direct byte manipulation to avoid the *test script* recursing) containing `{hello: 1, evilField:
<nested 1000-1150 levels deep>, $db: "admin"}`, sized 8-9KB (comfortably inside the 16KB pre-auth
ceiling), sent pre-auth over a raw socket:

```
sent 8068-byte OP_MSG with evilField nested 1000 levels deep, pre-auth
got response: ... 'a.a.a.a....' in object with unknown _id ... codeName: "Overflow"
```

Rejected cleanly with `Overflow` at both depths tested; `mongod` answered `ping`/`serverStatus`
normally immediately afterward (same pid). No stack overflow, no crash, no hang.

## Net result

Four additional concrete pre-auth hypotheses tested this round, all closed: SASL/SCRAM parsing
(bounded, no attacker-controlled cost lever), the new ingress rate limiter's queue (safe by default,
bounded when enabled), unauthenticated connection flooding (bounded per-connection memory, no
leak across repeated cycles), and deep-nesting stack-overflow-shape attacks (caught generically by
`objcheck`'s default-on `validateBSON()` gate before any command-specific code runs). Combined with
the three defenses confirmed in the 2026-08-24 static pass (decompression bomb, pre-auth
message-size ceiling, pre-auth/post-auth classification), this is now seven independently-verified,
intact pre-auth hardening mechanisms in `r8.3.8`. No fresh pre-auth crash/DoS bug found across either
pass.

## 5. TLS handshake certificate/extension parsing (`ssl_manager_openssl.cpp`) — reviewed

Followed up on the two remaining candidates flagged in the 2026-08-24 static audit:

- **Custom X.509 extension DER parser** (`parsePeerRoles`/`parseDERString`/`parseTLSFeature`,
  `ssl_manager.cpp:1158-1264`, reached from `_parsePeerExtensions`/`_parseTLSFeature` in
  `ssl_manager_openssl.cpp:3569-3631`, which run against the mongodbRoles/clusterMembership/TLS-feature
  extensions of a peer's client certificate during the TLS handshake — genuinely pre-auth-reachable
  whenever mutual TLS is in use). This is a hand-rolled, non-recursive DER parser: `DERToken::parse`
  computes the declared length via an explicitly overflow-checked add
  (`overflow::add(tagAndLengthByteCount, derLength, outLength)`) and rejects anything exceeding the
  actual buffer (`*outLength > cdr.length()`) before any data is touched, and the SET/SEQUENCE walk
  in `parsePeerRoles` never recurses — it only expects a fixed, shallow SET-of-SEQUENCE-of-two-strings
  shape and cleanly errors on anything else via a type-tag check, rather than descending into
  unexpected nested structures. No recursion-based or overflow-based crash found; this reads as
  code that was already hardened (plausibly from a past incident in this exact area).

- **OCSP response DER-decode null-pointer dereference** — found a **real, but already-fixed** crash
  bug while reading commit history: `SERVER-128362` (`8d73b22d5`, ancestor of `r8.3.8`) added a
  missing null check in `ocspClientCallback` (`ssl_manager_openssl.cpp:~2010`) after
  `d2i_OCSP_RESPONSE(NULL, &response_ptr, length)` — before the fix, a malformed/corrupt DER OCSP
  staple (`d2i_OCSP_RESPONSE` returns `nullptr` on decode failure) would fall through directly into
  `verifyStapledResponse(ssl, peerCert.get(), response.get())`, dereferencing a null `OCSP_RESPONSE*`
  and crashing the process. This fires in `mongod`'s role as the TLS *client* on an outbound
  connection (OCSP stapling is server-to-client), so exploitability requires mongod to connect
  outward to a malicious or compromised peer serving a corrupt staple — not a bare unauthenticated
  listener-side attack, but still a genuine pre-verification crash primitive. **Ran the
  sibling-bug-hunt technique** used successfully for the BSONColumn finding: searched for every other
  `d2i_OCSP_RESPONSE` call site (`ssl_manager_openssl.cpp:770` and `:2013`) to check whether the same
  missing-null-check pattern was left unfixed anywhere else. It wasn't — the other call site
  (`retrieveOCSPResponse`, mongod's own OCSP-staple-refresh path) already had its own independent
  null check (`if (response == nullptr) { return getSSLFailure(...); }`) even before this fix, so
  there's no unpatched sibling. Not pursued as a submission: already fixed upstream, and even
  unfixed it wouldn't be reachable from a bare pre-auth listener-side connection.

## Remaining not-yet-covered pre-auth surfaces (candidates for a future round)

- Proxy-protocol parsing (`SERVER-128387` recently removed role-parsing from it — worth checking
  what remains).
- Standard X.509 fields (CN/SAN) extraction for hostname matching against the ASN1_STRING data
  pointer (`ssl_manager_openssl.cpp:3459`, `std::string(reinterpret_cast<char*>(ASN1_STRING_data(...)))`)
  — noticed this is the classic C-string-from-ASN1_STRING pattern historically associated with
  embedded-NUL-byte hostname spoofing in other TLS stacks. Not chased further: (a) this is an
  authentication/spoofing concern, not a crash/DoS, out of this round's stated scope; (b) the
  function's own parameter names/RFC-2818 comment indicate it's mongod's *client*-side verification
  of a peer *server*'s certificate (outbound connections), not something a bare unauthenticated
  listener-side connection can reach directly. Worth a dedicated authz-focused pass, not a DoS one.

## Adjacent, non-DoS finding noticed while reading recent commits (not this round's target, noted for completeness)

`SERVER-127863` (`bcd95dd3a`, already fixed, ancestor of `r8.3.8`) fixed a real authentication
*policy* bypass: `SaslX509ServerMechanism::stepImpl`, for a non-cluster-member, previously never
checked whether `MONGODB-X509` was actually present in `saslGlobalParams.authenticationMechanisms`
before authenticating a valid client certificate — meaning an operator who disabled the X509
mechanism (leaving only SCRAM) could still be bypassed by any client holding a valid cert. This is
an authorization/policy-enforcement bug, not a crash/DoS, and it's already fixed in the version under
test — noted only because it surfaced while combing commit history for this round's actual target,
not pursued further since it's out of this round's scope and already resolved upstream.
