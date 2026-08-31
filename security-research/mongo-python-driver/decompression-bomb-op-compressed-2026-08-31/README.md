# mongo-python-driver: OP_COMPRESSED decompression-bomb DoS

Finding from the `mongo-python-driver` (PyMongo) audit pass, tag `4.17.0`, commit
`f2103a95870ab5c00b436f757cbaeb86a1047679`.

See `HACKERONE-REPORT.md` for the full write-up. Short version: `pymongo` reads
the `uncompressedSize` field out of every `OP_COMPRESSED` wire-protocol reply
and then **throws it away** (`pymongo/network_layer.py`), passing the
compressed payload straight to `zlib.decompress()` / `snappy.uncompress()` /
`zstd.decompress()` — all one-shot, unbounded-output calls
(`pymongo/compression_support.py`). A malicious or compromised server (or a
MITM without TLS) that gets a client to enable wire compression
(`compressors=zlib`) can reply to any ordinary operation with an
`OP_COMPRESSED` message wrapping a "zlib bomb": in this PoC, **1.9 MB** on the
wire forces the client to allocate **1.86 GiB** in memory (confirmed via a
direct call to the exact vulnerable function, and end-to-end through a real
socket against a minimal malicious server).

MongoDB's own C driver validates this exact field against the connection's
`maxMessageSizeBytes` *before* allocating anything (`mcd_rpc_message_decompress`
in `mongoc-cluster.c`) — `pymongo` has no equivalent check anywhere.

## Files

- `evil_server.py` — minimal malicious MongoDB server. Handles the client's
  legacy `OP_QUERY` hello handshake (replies advertising zlib compression),
  then replies to the client's next request with a hand-built `OP_COMPRESSED`
  message wrapping a precomputed zlib bomb.
- `victim_client.py` — connects with `pymongo.MongoClient(..., compressors=zlib)`
  and issues `client.admin.command("ping")`, tracking peak RSS via
  `resource.getrusage`.
- `bomb_2gb.zlib` — precomputed bomb: 1,943,919 bytes that decompress (via
  plain `zlib.decompress`) to exactly 2,000,000,000 bytes (~1.86 GiB), a
  ~1029:1 ratio. Regenerate with:
  ```python
  import zlib
  open('bomb_2gb.zlib','wb').write(zlib.compress(b'\x00' * 2_000_000_000, level=9))
  ```

## Running it

```
python3 evil_server.py <port> 2000000000 bomb_2gb.zlib &
python3 victim_client.py <port>
```

Or, to see the effect in complete isolation (no networking, no pymongo
connection machinery — just the exact vulnerable function):

```python
import resource, time
from pymongo.compression_support import decompress
data = open('bomb_2gb.zlib', 'rb').read()
before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
out = decompress(data, 2)  # 2 == zlib compressor_id
after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(len(data), '->', len(out), 'bytes;', (after-before)/1024/1024, 'GiB RSS growth')
```

## Also checked this pass (negative results, not written up)

- **Path traversal / Zip Slip**: confirmed absent. `gridfs/` never touches the
  local filesystem — `GridOut`/`GridIn` are pure buffer-to-buffer streams; the
  `open('myfile', 'wb')` occurrences in the source are docstring examples
  showing how the *calling application* might write a downloaded file, not
  driver-internal file I/O. No server-controlled filename ever reaches a
  local path-construction call anywhere in this driver.
- **Unbounded recursion in BSON decode** (the same bug class found in
  `mongo-php-driver`): NOT present here. `bson/_cbsonmodule.c`'s `get_value`/
  `elements_to_dict` wrap every recursive descent in
  `Py_EnterRecursiveCall`/`Py_LeaveRecursiveCall` (CPython's built-in
  C-recursion guard), converting what would otherwise be a stack overflow
  into a catchable `RecursionError`.
- **BSON decode bounds-checking** (`get_value`, `_element_to_dict`,
  `elements_to_dict`/`_elements_to_dict`, `_cbson_bson_to_dict`): reviewed in
  detail for the classic OOB-read patterns (unbounded `strlen` on embedded
  BSON key strings, integer-overflow in length-field arithmetic, size checks
  that run after a read instead of before). All of it is soundly bounded —
  every sub-document/array validates its own trailing EOO NUL byte before
  iterating, so even the `strlen`-based key-length scans are provably bounded
  within the currently-validated buffer region. One caveat worth naming
  honestly: `_cbson._element_to_dict` (the raw C entry point) does not itself
  validate `position`/`max` against the real buffer length — it trusts its
  caller. Every actual call site in this codebase (`RawBSONDocument`,
  `_bson_to_dict`, `_get_object`) pre-validates those values via
  `_get_object_size`/`len(data)` first, so this isn't independently
  reachable with attacker-controlled data through any documented path — it's
  a missing defense-in-depth check, not a demonstrated vulnerability, so it
  is not written up as a separate finding.
