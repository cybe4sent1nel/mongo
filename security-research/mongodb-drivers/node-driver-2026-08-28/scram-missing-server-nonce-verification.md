# Node.js driver — SCRAM-SHA-1/SCRAM-SHA-256 omit the RFC 5802-mandated server-nonce-prefix check

**Status: confirmed via static analysis, cross-checked two independent ways. This is a
real, previously-undocumented gap, not a re-report.**

Target chosen at the user's explicit request: deep static-analysis-only audit of
`mongodb/node-mongodb-native`. Checked out at `d0c57c03` (2026-08-26,
"chore(NODE-7794): Revert temporary `_BUILD` test environment variables").

## The bug

`src/cmap/auth/scram.ts`, `continueScramConversation` (used by **every** SCRAM-SHA-1 and
SCRAM-SHA-256 login — the default password-auth mechanisms for MongoDB, both direct and
speculative/piggybacked on the initial handshake):

```ts
const dict = parsePayload(payload);
...
const salt = dict.s;
const rnonce = dict.r;
if (rnonce.startsWith('nonce')) {
  // TODO(NODE-3483)
  throw new MongoRuntimeError(`Server returned an invalid nonce: ${rnonce}`);
}
// Set up start of proof
const withoutProof = `c=biws,r=${rnonce}`;
```

RFC 5802 §3 (SCRAM) requires the client to verify that the nonce returned by the server in
the server-first-message **begins with the exact nonce the client generated and sent**,
and to abort the exchange if it doesn't. This code does not do that. The check it does
perform — `rnonce.startsWith('nonce')` — tests whether the server's nonce begins with the
*literal seven-character string* `"nonce"`. That's not a prefix check against the client's
own nonce (`authContext.nonce`, generated on line 35 and never referenced again after this
point in the function); it reads like a leftover/mistaken stand-in for the real check
(the `TODO(NODE-3483)` marker on the line right above suggests the author was already
aware something here needed revisiting). Whatever `r` value a hostile or MITM'd server
sends back, as long as it doesn't literally start with the word "nonce", this code accepts
it and builds the rest of the SCRAM exchange (`authMessage`, `clientProof`,
`serverSignature` check) on top of it unquestioned.

## This isn't a one-off oversight — the driver gets this right elsewhere, in the same file tree

`src/cmap/auth/mongodb_aws.ts:79-90`, the MONGODB-AWS mechanism's own nonce handling:

```ts
const serverNonce = serverResponse.s.buffer;
if (serverNonce.length !== 64) {
  ...
}
if (!ByteUtils.equals(serverNonce.subarray(0, nonce.byteLength), nonce)) {
  // throw because the serverNonce's leading 32 bytes must equal the client nonce's 32 bytes
  ...
  throw new MongoRuntimeError('Server nonce does not begin with client nonce');
}
```

This is the *exact same security check*, done correctly, with an explanatory comment
showing the author understood exactly why it's required. It's implemented for AWS auth
and simply missing for SCRAM auth — the mechanism that's the default for the overwhelming
majority of MongoDB username/password connections. This is strong evidence the omission is
an accidental gap, not an intentional design decision: the project's own code proves its
authors know this check matters.

## Cross-driver confirmation

Compared against `mongodb/mongo-go-driver`, which delegates SCRAM entirely to the
third-party `xdg-go/scram` library rather than hand-rolling it. Read that library directly
(`xdg-go/scram/client_conv.go:93-97`):

```go
// Check nonce prefix and update
if !strings.HasPrefix(msg.nonce, cc.nonce) {
    return "", errors.New("server nonce did not extend client nonce")
}
cc.nonce = msg.nonce
```

Confirms the Go driver's dependency performs the check the Node driver omits. Two
independent data points (an internal one and a cross-driver one), not a single
interpretation of the spec.

## Impact assessment — honest calibration, not oversold

Traced what this omission actually buys an attacker, rather than stopping at "spec
violation":

- MongoDB's SCRAM implementation does not support channel binding (`GS2` header is
  hardcoded to `n,,` — "no channel binding, no authzid" — confirmed by grep: no `PLUS`,
  `cbind`, or `tls-server-end-point` reference anywhere in `src/cmap/auth/`). The classes
  of attack the nonce-prefix check most directly defends against in the RFC (channel-binding
  downgrade, SASL session/authentication mechanism confusion in multiplexed contexts) are
  therefore not directly exploitable here today, because there's no channel binding to
  downgrade *from*.
- The core cryptographic guarantee — a party without the account password cannot forge a
  `ClientProof`/`ServerSignature` pair the real server will accept — is untouched by this
  bug; salting/iteration parameters aren't attacker-forgeable into something materially
  weaker in a way this omission alone unlocks (`iterations < 4096` is still checked, salt is
  still applied through the standard PBKDF2/HI step).
- What the missing check *does* remove: any guarantee that the SCRAM conversation the
  client is completing corresponds to the exchange it actually started. A network-position
  attacker (active MITM, e.g. on a non-TLS or TLS-misconfigured connection, or a
  malicious/compromised intermediate proxy speaking the wire protocol) can substitute an
  arbitrary `r=`/`s=`/`i=` triple from a different SCRAM exchange (their own, or a captured
  one) into the response the client processes, and the Node.js driver will not notice or
  abort — it'll just silently authenticate against attacker-supplied conversation state
  instead of refusing outright the way a spec-compliant client (and this driver's own AWS
  path) would.

Calibrated conclusion: this is a confirmed, real, fixable defect — not defense-in-depth
dismissible the way the mongosh log-redaction report was (that one required pre-existing
local log/filesystem access; this is a gap in the wire-level authentication handshake logic
itself, hit by every default password-auth login). But I'm not overselling it as a
demonstrated full credential-theft exploit either: absent channel binding, I don't have a
concrete chain from "accepts a substituted nonce" to "attacker without the password gets
authenticated." The strongest, cleanly defensible framing is: a required RFC 5802 integrity
check on the authentication handshake is missing, it's demonstrably not an intentional
omission (the same codebase implements the identical check correctly for a different
mechanism), and its absence removes a real barrier against SASL response-substitution in
exactly the connection classes (MITM'd/misconfigured TLS, hostile intermediary) that
SCRAM's nonce design exists to catch.

## Suggested fix

In `continueScramConversation`, after parsing `dict.r`, verify it starts with the base64
encoding of the client's own `nonce` (available as `authContext.nonce`, already in scope)
before using it in `withoutProof`/`authMessage`, mirroring exactly what
`mongodb_aws.ts:85-90` already does one file over.
