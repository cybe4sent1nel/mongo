#!/usr/bin/env python3
"""
Round 17: authorization-boundary check on create-block-theme/v1's REST
routes, done dynamically (real HTTP, three real sessions) rather than by
reading can_modify_theme() and trusting it. All ten routes require
'edit_themes' + wp_is_file_mod_allowed() per the source; verify that holds
for a Subscriber and an Editor (neither has edit_themes by default) against
an Administrator baseline.
"""
import json
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:8890"
SCRATCH = "/tmp/claude-0/-home-user-mongo/88417634-60f9-5bda-b080-646aad79e105/scratchpad"

USERS = {
    "admin": {"jar": f"{SCRATCH}/cookies_admin.txt", "nonce": "5077c95857"},
    "editor": {"jar": f"{SCRATCH}/cookies_editor.txt", "nonce": "1bc3b949ad"},
    "subscriber": {"jar": f"{SCRATCH}/cookies_subscriber.txt", "nonce": "c14b5b30dd"},
}

ROUTES = [
    ("POST", "/create-block-theme/v1/export", {}),
    ("POST", "/create-block-theme/v1/update", {}),
    ("POST", "/create-block-theme/v1/save", {"title": "pwn-test"}),
    ("POST", "/create-block-theme/v1/theme-settings", {}),
    ("POST", "/create-block-theme/v1/clone", {}),
    ("POST", "/create-block-theme/v1/create-variation", {"title": "pwn-variation"}),
    ("POST", "/create-block-theme/v1/create-blank", {"title": "pwn-blank", "slug": "pwn-blank-theme"}),
    ("POST", "/create-block-theme/v1/create-child", {"title": "pwn-child"}),
    ("GET", "/create-block-theme/v1/font-families", None),
    ("POST", "/create-block-theme/v1/reset-theme", {}),
]


def _cookie_header(jar_path):
    cookies = []
    with open(jar_path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#HttpOnly_"):
                line = line[len("#HttpOnly_"):]
            elif line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 7:
                cookies.append(f"{parts[5]}={parts[6]}")
    return "; ".join(cookies)


def call(role, method, path, body):
    u = USERS[role]
    url = f"{BASE}/?rest_route={urllib.parse.quote(path)}" if False else f"{BASE}{path.replace('/create-block-theme', '/index.php?rest_route=/create-block-theme')}"
    headers = {
        "Cookie": _cookie_header(u["jar"]),
        "X-WP-Nonce": u["nonce"],
        "User-Agent": "wp-authz-check",
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()[:400]
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:400]
    except Exception as e:
        return None, str(e).encode()


import urllib.parse

for method, path, body in ROUTES:
    print(f"\n== {method} {path} ==")
    for role in ("admin", "editor", "subscriber"):
        status, resp = call(role, method, path, body)
        snippet = resp.decode(errors="replace").replace("\n", " ")[:180]
        print(f"  {role:12s} -> {status}  {snippet}")
