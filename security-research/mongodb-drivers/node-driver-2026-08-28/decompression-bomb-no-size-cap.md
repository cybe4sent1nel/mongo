# node-mongodb-native: unauthenticated decompression-bomb DoS via OP_COMPRESSED (no output-size cap)

**Status: real, directly reproduced (Node.js script calling the exact same `zlib.inflate`
invocation the driver uses, byte-for-byte). Different bug shape from the Go driver's crash
(no attacker-supplied allocation size here — Node's zlib determines output size from the
compressed stream itself), but the same practical outcome class: an unauthenticated,
malicious/MITM server can force unbounded memory growth in the connecting Node process using
a tiny reply.**

## Summary

`decompress()`/`zlibInflate()` in `src/cmap/wire_protocol/compression.ts` calls Node's
`zlib.inflate(buf, callback)` with **no options object** — in particular, no
`maxOutputLength`. Node's zlib API supports capping decompression output size via this option
specifically to defend against decompression bombs; the driver does not set it. A server
reply carrying a small, highly-compressible `OP_COMPRESSED` payload can therefore expand to
an arbitrarily large buffer in memory, bounded only by the compressed input's actual size
(and the wire protocol's ~48MB message-size ceiling on that *compressed* input, not the
*decompressed* output).

## Code

```ts
// src/cmap/wire_protocol/compression.ts
const zlibInflate = (buf: zlib.InputType) => {
  return new Promise<Uint8Array>((resolve, reject) => {
    zlib.inflate(buf, (error, result) => {   // <-- no options; no maxOutputLength
      if (error) return reject(error);
      resolve(result);
    });
  });
};
```

`decompressResponse` (same file) reads the header fields directly off the wire
(`readInt32LE`), pulls out `compressorID` and `compressedBuffer`, and passes
`compressedBuffer` straight to `decompress()` → `zlibInflate()`. The `header.length` field
(the claimed uncompressed size) is only compared **after** decompression already completed
(`if (messageBody.length !== header.length) throw ...`) — it's a post-hoc sanity check, not a
pre-allocation bound, so it does nothing to stop the expansion from happening.

## Reachability: same generic-reply-loop pattern as Go/Java, confirmed pre-auth

- `Connection.readMany` (`src/cmap/connection.ts:759-791`) is the single generic reply reader:
  `for await (const message of this.dataEvents) { const response = await
  decompressResponse(message); ... }` — every incoming message, regardless of what was sent,
  passes through this unconditionally if its opcode is `OP_COMPRESSED`.
- `readMany` backs `sendCommand`, which backs the connection's generic `command()` method —
  the same machinery used to send the initial `hello` handshake. There is no
  compression-already-negotiated gate before decompression is attempted; it is driven purely
  by the incoming message's own opcode, exactly like the Go and Java drivers.
- `uncompressibleCommands` (top of `compression.ts`: `saslStart`, `saslContinue`, `hello`,
  etc.) only affects what the *client* refuses to compress on the way *out* — it has no effect
  on whether an *incoming* reply gets decompressed.

Net: a malicious/MITM MongoDB server can send `OP_COMPRESSED` as its very first reply (to the
client's initial `hello`), or at any point during the SASL exchange, before authentication
completes.

## Direct reproduction

Reproduced the exact call the driver makes (`zlib.inflate(buf, callback)`, no options) against
a deliberately crafted small compressed blob:

```
Compressed 209715200 bytes down to 203848 bytes (ratio 1028.8x)
inflate SUCCEEDED after 2099ms, output length=209715200 bytes
  (RSS before=47.0MB after=483.0MB)
```

200MB of zeros compresses to ~200KB; `zlib.inflate` happily expands it back with no
resistance, growing process RSS by ~436MB in ~2 seconds for this one message. The wire
protocol's ~48MB cap (`StreamDescription.maxMessageSizeBytes = 48000000`,
`src/cmap/stream_description.ts:49`) bounds the *compressed* bytes an attacker can send in one
message, not the *decompressed* output — a ~48MB message built from more aggressively
repetitive/structured data than plain zeros could plausibly expand into tens of gigabytes,
well beyond what most application containers can absorb, causing the process to be OOM-killed
or to stall for an extended period under memory/GC pressure. This can be repeated on every
reconnect attempt.

Only the zlib path was directly reproduced. The `snappy`/`zstd` branches in the same
`decompress()` function were not independently tested for an equivalent output-size cap (or
lack thereof) in this round — noting this as an open thread rather than claiming it either
way.

## Contrast with the Go/Java drivers

This is a different bug shape from the Go driver's crash: the Node driver never allocates a
buffer *sized by* an attacker-supplied field before decompressing (unlike Go's `make([]byte,
opts.UncompressedSize)`), so there's no direct negative-size-triggers-a-panic equivalent here.
The size mismatch check happens only after zlib has already produced its output. The
practical effect is the same DoS family, though: a small malicious message forces a large,
attacker-controlled amount of work/memory in the client before authentication.

## Suggested fix

Pass a `maxOutputLength` in the `zlib.inflate` options, bounded to the negotiated/expected
`maxMessageSizeBytes` (the driver already tracks this value in `StreamDescription`), and treat
exceeding it as a decompression error. This mirrors the fix already needed on the allocation
side of the Go and Java drivers: never let a value derived from unauthenticated wire bytes
control an unbounded amount of client-side work before the peer is trusted.

## Disclosure

Not yet filed with MongoDB. Same responsible-disclosure channel as noted for the Go driver
(https://www.mongodb.com/docs/manual/tutorial/create-a-vulnerability-report/). Audited against
a shallow (`--depth 1`) clone of `github.com/mongodb/node-mongodb-native`, current HEAD as of
2026-08-28; full history was not available to check for an in-flight fix.
