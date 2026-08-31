import struct, sys

def nested_doc_bytes(depth):
    # innermost document: just {} (empty doc), 5 bytes: len(4) + 0x00
    inner = struct.pack('<i', 5) + b'\x00'
    for _ in range(depth):
        # wrap as {"a": <inner-subdocument>}
        # element: type 0x03 (document) + key "a\0" + subdoc bytes
        elem = b'\x03' + b'a\x00' + inner
        total_len = 4 + len(elem) + 1
        inner = struct.pack('<i', total_len) + elem + b'\x00'
    return inner

depth = int(sys.argv[1]) if len(sys.argv) > 1 else 200000
data = nested_doc_bytes(depth)
sys.stdout.buffer.write(data)
