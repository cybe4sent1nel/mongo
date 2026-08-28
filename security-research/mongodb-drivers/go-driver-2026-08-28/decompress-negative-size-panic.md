# mongo-go-driver: unauthenticated remote crash via negative `UncompressedSize` in OP_COMPRESSED

**Status: real, directly reproduced against current HEAD (commit `d803fd5`, clone date 2026-08-28)
of `github.com/mongodb/mongo-go-driver`. Not previously seen/flagged anywhere in this
engagement — treating as a fresh candidate finding pending MongoDB's own triage. Confirmed by
running a standalone Go program against the actual driver source, not just static reasoning.**

## Summary

Any MongoDB server the Go driver connects to — including a malicious server, or an on-path
attacker who can inject/modify the first TCP response before TLS is negotiated or via a
plain-text deployment — can crash the connecting Go process by replying to the driver's very
first `hello` command with an `OP_COMPRESSED` message that declares a negative
`uncompressedSize`. No credentials, no prior negotiation, and no application-level access are
required: this fires on connection establishment, before the driver has authenticated the
server or the user has authenticated to it.

## Root cause

`x/mongo/driver/compression.go`, `DecompressPayload`:

```go
case wiremessage.CompressorZLib:
    r, err := zlib.NewReader(bytes.NewReader(in))
    ...
    out := make([]byte, opts.UncompressedSize)   // <-- opts.UncompressedSize is attacker-controlled int32, unchecked
    ...
case wiremessage.CompressorZstd:
    buf := make([]byte, 0, opts.UncompressedSize) // <-- same field, unchecked, used as capacity
    ...
```

`opts.UncompressedSize` comes straight from the wire with zero validation:

`x/mongo/driver/operation.go`, `decompressWireMessage`:
```go
uncompressedSize, rem, ok := wiremessage.ReadCompressedUncompressedSize(rem)
if !ok {
    return 0, nil, errors.New("malformed OP_COMPRESSED: missing uncompressed size")
}
...
opts := CompressionOpts{Compressor: compressorID, UncompressedSize: uncompressedSize}
uncompressed, err := DecompressPayload(rem, opts)
```

`ReadCompressedUncompressedSize` (`wiremessage.go`) only checks that 4 bytes are present — it
never checks the value is non-negative or bounded:
```go
func ReadCompressedUncompressedSize(src []byte) (size int32, rem []byte, ok bool) {
    return binaryutil.ReadI32(src)
}
```

A negative `int32` (e.g. `-1`) reaches `make([]byte, -1)` (zlib) or `make([]byte, 0, -1)`
(zstd), and Go's runtime unconditionally panics — `runtime error: makeslice: len out of range`
/ `cap out of range`. This is a genuine `panic`, not a returned `error`; nothing in the call
chain (`decompressWireMessage` → `readWireMessage` → `roundTrip` → `Operation.Execute`) has a
`recover()`. An unrecovered panic in Go terminates the entire process, not just the calling
goroutine — confirmed no `recover()` exists anywhere in `x/mongo/driver/operation.go` or the
read path (only unrelated `recover()`s exist in background topology-monitoring goroutines in
`topology/server.go` and `topology/topology.go`, nowhere near this call chain).

Notably, the **snappy branch already validates correctly** — it computes the real decoded
length from the compressed bytes via `snappy.DecodedLen(in)` and compares it against
`opts.UncompressedSize` *before* ever allocating, cleanly returning an error on mismatch. The
zlib and zstd branches skip this check and trust the wire-supplied field directly. This is an
inconsistency within the same function, not a design choice — the safe pattern already exists
two branches away.

## Reachability: this is the very first message, not just "pre-auth"

Traced the full call path to confirm this isn't gated behind any negotiation or auth state:

- `readWireMessage` (`operation.go`) is `Operation.roundTrip`'s generic reply reader, used for
  **every** command the driver executes — there is no compression-negotiated-yet check; it
  decompresses any incoming message whose header opcode is `OP_COMPRESSED`, unconditionally,
  using whatever compressor ID and size the bytes claim.
- The initial `hello` handshake itself goes through this exact path:
  `internal/handshake/operation/hello.go`'s `GetHandshakeInformation` builds a
  `driver.Operation{...}` and calls `op.Execute(ctx)` — the same `Operation` type whose
  `roundTrip`/`readWireMessage` contains the vulnerable code.
- `topology/connection.go` only decides the connection's *own outgoing* compressor **after**
  both the initial hello round-trip and `FinishHandshake` (the authentication step) complete
  (lines ~281-338) — but that state (`c.connection.compressor`) only governs what the client
  chooses to send. It plays no role in whether an *incoming* reply gets decompressed; that's
  driven purely by the opcode in the bytes the server (or attacker) sent.
- The SASL/SCRAM exchange (`x/mongo/driver/auth/sasl.go`'s `ConductSaslConversation`/
  `runCommand`) also builds a plain `driver.Operation{...}.Execute(ctx)` — same shared path.

Net: a malicious/MITM server can send `OP_COMPRESSED` with a negative size as its reply to
**literally the first bytes the client ever receives** (the `hello` reply), or at any later
point including mid-SASL-conversation. This is reachable before authentication in the
strictest sense (the very first server response), and remains reachable for the entire
connection lifetime afterward.

## Direct reproduction

Built a standalone Go program (`go.mod` with a `replace` directive to the local clone) calling
`driver.DecompressPayload` exactly as `decompressWireMessage` does, with a `recover()` wrapper
to observe rather than suppress the crash:

```
[zlib_negative_-1]           PANIC: runtime error: makeslice: len out of range
[zlib_negative_INT32_MIN]    PANIC: runtime error: makeslice: len out of range
[zstd_negative_-1]           PANIC: runtime error: makeslice: cap out of range
[huge_INT32_MAX]             no panic — allocated ~2GB successfully in this sandbox (15GB RAM);
                             on a memory-constrained host this class of value risks Go's
                             unconditional (non-recoverable) "fatal error: out of memory"
[snappy_negative_-1]         no panic — correctly rejected: "unexpected decompression size,
                             expected -1 but got 1" (the one branch that validates first)
```

The `len out of range`/`cap out of range` results are unconditional and 100% deterministic —
no timing, no memory pressure, no environment dependence. The `INT32_MAX` case is a real but
probabilistic amplification/DoS vector (attacker sends a tiny compressed blob, forces a ~2GB
allocation attempt) rather than a guaranteed crash, and is secondary to the negative-size
finding.

## Impact

Denial of service against any application using this driver: a malicious server (or path
attacker positioned before TLS, or before TLS is configured at all) can crash the connecting
process on first contact, with no credentials and no prior connection state. Repeatable against
every reconnect attempt, so an attacker controlling DNS/routing to a client's configured seed
list, or a rogue node in a replica set/sharded cluster the client is configured to trust, can
sustain the crash indefinitely.

## Suggested fix

Validate `uncompressedSize >= 0` (and arguably bound it to a sane maximum, e.g. the server's
own advertised `maxMessageSizeBytes`) in `decompressWireMessage` before constructing
`CompressionOpts`, matching the check-before-allocate discipline the snappy branch already
uses. This is a small, local, low-risk fix.

## Disclosure

Not filed with MongoDB yet. Per `docs/SECURITY.md` in the driver repo, MongoDB's disclosure
process is at https://www.mongodb.com/docs/manual/tutorial/create-a-vulnerability-report/ —
this write-up is prepared in that format/spirit but has not been submitted. Only a shallow
(`--depth 1`) clone was available in this sandbox, so full history for `compression.go` /
`operation.go` could not be searched for a pre-existing fix-in-flight; the bug was confirmed
present and triggerable against the current HEAD regardless.
