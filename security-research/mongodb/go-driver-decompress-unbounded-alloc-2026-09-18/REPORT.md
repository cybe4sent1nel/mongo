# Title

Unbounded, server-declared `uncompressedSize` in `OP_COMPRESSED` drives a large `make()` allocation in `DecompressPayload` — sibling of the just-fixed GODRIVER-4135 negative-size panic, left open for the positive/oversized case (client-side memory-exhaustion DoS from a malicious or compromised server response)

## Summary

Commit `12a1588e` (GODRIVER-4135, landed on `master` 2026-09-17, not yet in a tagged release as of this audit) fixed a real bug: `DecompressPayload` (`x/mongo/driver/compression.go`) used a server-supplied, signed `int32` `UncompressedSize` field straight in `make([]byte, opts.UncompressedSize)` with no validation. A negative value (trivial for a malicious/compromised server, or a MITM on an unencrypted connection, to send) makes Go's runtime panic (`makeslice: cap out of range`), crashing the client process — a one-message, server-triggered DoS. The fix adds exactly one check:

```go
if opts.UncompressedSize < 0 {
    return nil, fmt.Errorf("invalid uncompressed size: %d", opts.UncompressedSize)
}
```

This closes the negative half of the input range. The **positive** half is still completely unbounded: `UncompressedSize` can be any value up to `math.MaxInt32` (2,147,483,647 ≈ 2 GiB), and every branch of `DecompressPayload` allocates a buffer of that exact size **before** doing any real decompression work or verifying the compressed payload is actually that large:

```go
// x/mongo/driver/compression.go (current, post-fix, on master)
func DecompressPayload(in []byte, opts CompressionOpts) ([]byte, error) {
	if opts.Compressor == wiremessage.CompressorNoOp {
		return in, nil
	}
	if opts.UncompressedSize < 0 {
		return nil, fmt.Errorf("invalid uncompressed size: %d", opts.UncompressedSize)
	}
	switch opts.Compressor {
	case wiremessage.CompressorSnappy:
		l, err := snappy.DecodedLen(in)
		if err != nil {
			return nil, fmt.Errorf("decoding compressed length %w", err)
		} else if int32(l) != opts.UncompressedSize {
			return nil, fmt.Errorf("unexpected decompression size, expected %v but got %v", opts.UncompressedSize, l)
		}
		out := make([]byte, opts.UncompressedSize)          // <-- unbounded allocation
		return snappy.Decode(out, in)
	case wiremessage.CompressorZLib:
		r, err := zlib.NewReader(bytes.NewReader(in))
		if err != nil {
			return nil, err
		}
		out := make([]byte, opts.UncompressedSize)          // <-- unbounded allocation, BEFORE any bytes are decompressed
		if _, err := io.ReadFull(r, out); err != nil {
			return nil, err
		}
		...
	case wiremessage.CompressorZstd:
		buf := make([]byte, 0, opts.UncompressedSize)        // <-- unbounded capacity reservation
		r := zstdReaderPool.Get().(*zstd.Decoder)
		out, err := r.DecodeAll(in, buf)
		...
```

None of the three branches caps `opts.UncompressedSize` against anything (not `math.MaxInt32`, not the server's own negotiated `maxMessageSizeBytes`, not even the size of `in`, the actual bytes received). The **zlib branch is the starkest case**: it allocates the full `out` buffer unconditionally, then tries to fill it via `io.ReadFull` — the allocation happens whether or not the compressed input can actually produce that much data.

## Why this is a real, reachable DoS — and not just theoretical

`UncompressedSize` is read directly off the wire, from a field the **server** controls, with no cross-check against the actual number of compressed bytes received in the same message:

`x/mongo/driver/operation.go`:
```go
func readWireMessage(...) {
    ...
    length, _, _, opcode, rem, ok := wiremessage.ReadHeader(wm)
    if !ok || len(wm) < int(length) {
        return nil, errors.New("malformed wire message: insufficient bytes")
    }
    if opcode == wiremessage.OpCompressed {
        rawsize := length - 16 // remove header size
        opcode, rem, err = op.decompressWireMessage(rem[:rawsize])
        ...
```
```go
func (Operation) decompressWireMessage(wm []byte) (wiremessage.OpCode, []byte, error) {
    opcode, rem, ok := wiremessage.ReadCompressedOriginalOpCode(wm)
    ...
    uncompressedSize, rem, ok := wiremessage.ReadCompressedUncompressedSize(rem)   // raw int32, no bound check
    ...
    opts := CompressionOpts{Compressor: compressorID, UncompressedSize: uncompressedSize}
    uncompressed, err := DecompressPayload(rem, opts)
```

The only check performed before `DecompressPayload` is called is that the message's own declared `length` matches the number of bytes actually read (`len(wm) < int(length)`) — that bounds the **physical, on-wire size of the compressed payload**, not the **declared uncompressed size** field, which is a completely separate 4-byte value inside the `OP_COMPRESSED` sub-header. A malicious or compromised server (or a MITM able to inject/modify traffic on a connection that isn't using TLS, which is still a supported and non-default-enforced driver configuration) can therefore send a **tiny** `OP_COMPRESSED` message — a few dozen bytes of actual compressed payload — while declaring `UncompressedSize = 2147483647` in the header field. The client will attempt to `make([]byte, 2147483647)` (zlib/snappy path) or reserve a matching-capacity buffer (zstd path) for essentially every such reply, well before it has verified the compressed bytes could plausibly decompress to that size.

At ~2 GiB per triggered response, a small number of such responses (or repeated ones across reused/pooled connections, since nothing throttles retrying this) is enough to exhaust the memory of a typical client process and crash it (Go's runtime will OOM-kill or panic on allocation failure) — the same client-crashing impact the driver's own maintainers judged worth an explicit, dedicated fix one field-range over, in the same function, the same week.

## Weakness

CWE-789 (Memory Allocation with Excessive Size Value) / CWE-400 (Uncontrolled Resource Consumption), reachable from an untrusted or compromised server response, no authentication or special server privilege required on the attacker's side beyond being able to answer a wire-protocol connection the client makes (rogue server, DNS/SRV hijack of a `mongodb+srv` URI, or a MITM on a non-TLS connection).

## Component / Version

- Repository: `mongodb/mongo-go-driver`
- The vulnerable, unbounded `make()` calls are present in every released version through `v2.9.1` (the latest tag) and remain present on `master` at commit `12a1588e` (the GODRIVER-4135 fix commit itself) and later — i.e. this is not a regression introduced by that fix, it's the fix's own blind spot.

## Suggested fix

Cap `UncompressedSize` to a sane maximum before any allocation — the natural bound is the connection's own negotiated `maxMessageSizeBytes` (default 48,000,000 bytes, `x/mongo/driver/topology/connection.go:43`, `defaultMaxMessageSize`), which the server itself advertises and which every other part of the driver already treats as the ceiling for a single wire message:

```go
if opts.UncompressedSize < 0 || opts.UncompressedSize > maxAllowedUncompressedSize {
    return nil, fmt.Errorf("invalid uncompressed size: %d", opts.UncompressedSize)
}
```
Additionally, for the zlib branch specifically, consider not pre-allocating the full declared size up front — reading via `io.LimitReader(r, opts.UncompressedSize)` into a growing buffer (or capping via `io.CopyN`) would avoid committing memory before any bytes are confirmed decompressible, independent of whatever upper bound is chosen.

## Suggested repro (static analysis only — not executed against a live server in this environment)

1. Stand up a rogue TCP listener speaking just enough of the MongoDB wire protocol to complete a handshake the client accepts (or MITM a non-TLS connection).
2. In response to any command, reply with an `OP_COMPRESSED` message: a valid original opcode, `compressorID = zlib (2)`, `uncompressedSize = 0x7FFFFFFF`, and a small valid zlib stream as the payload (e.g. compressing a handful of bytes).
3. Observe the driver call `DecompressPayload` → `make([]byte, 2147483647)` for that single reply — a ~2 GiB allocation attempt triggered by a message that was itself only a few dozen bytes on the wire.
4. Repeating step 2 a small number of times against a real client application is expected to exhaust available memory and crash the process (or be killed by the OS OOM killer), matching the same client-crash impact class GODRIVER-4135 was fixed to prevent for the negative-value case.

## Notes on scope

Found while sibling-hunting the Go driver's most recent security-relevant commit (GODRIVER-4135) for the "did the fix address the whole input range" pattern used throughout this audit — the same technique that found the GridFS `Drop`-cleanup gap in the Rust driver. This is a fresh, independent finding, not from the originally pasted CVE list, and not yet reported upstream.
