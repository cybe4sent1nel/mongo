#!/usr/bin/env python3
"""Stands in for an internal-only service on 127.0.0.1:80."""
from http.server import BaseHTTPRequestHandler, HTTPServer

HITS = []

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        HITS.append((self.path, dict(self.headers)))
        print(f"INTERNAL SERVICE HIT: {self.path} host={self.headers.get('Host')}", flush=True)
        body = b"INTERNAL-SECRET-DATA"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass

HTTPServer(("127.0.0.1", 80), H).serve_forever()
