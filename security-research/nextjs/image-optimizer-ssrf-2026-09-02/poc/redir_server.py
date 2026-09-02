#!/usr/bin/env python3
"""
One server on :80 that routes by Host header, for the redirect-allowlist test.

  Host: allowed.test     -> 302 to http://notallowed.test/y.png
  Host: notallowed.test  -> record the hit (this host is NOT in remotePatterns)
"""
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        if host == "allowed.test":
            target = "http://notallowed.test/y.png"
            print(f"ALLOWED HOST hit {self.path} -> 302 {target}", flush=True)
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if host == "notallowed.test":
            print(f"NOT-ALLOWLISTED HOST REACHED: {self.path} host={host}", flush=True)
            body = b"REACHED-NON-ALLOWLISTED-HOST"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", 80), H).serve_forever()
