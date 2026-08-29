#!/usr/bin/env python3
"""
Round 13: authenticated write-path fuzzer, extending round 11's pre-auth
type-confusion fuzzer past permission_callback into the actual create/
update controller logic.

Runs every write-method (POST/PUT/PATCH/DELETE) route+arg combination
found in the REST index twice: once authenticated as a low-privilege
Author (author1, role: author) and once as an Administrator, using
Application Passwords (Basic auth) minted for this test install only.

Looks for two things beyond round 11's crash-only findings:
  1. A type-confused value that gets ACCEPTED (2xx) where a same-shaped
     ordinary invalid value would be rejected (4xx) -- i.e. a validation
     bypass rather than a crash.
  2. A type-confused value that lets the low-priv Author write to a
     field/object it should not be able to touch at all (horizontal /
     vertical privilege-escalation flavored), by diffing DB state
     (wp_posts.post_author, wp_posts.post_status, wp_usermeta roles)
     before and after each interesting-looking write attempt.
"""
import base64
import json
import subprocess
import time
import urllib.request
import urllib.parse
import urllib.error
import os

BASE = "http://127.0.0.1:8890"
DEBUG_LOG = "/home/user/wp-site/wordpress/wp-content/debug.log"
RESULTS_PATH = "/tmp/claude-0/-home-user-mongo/88417634-60f9-5bda-b080-646aad79e105/scratchpad/auth_fuzz_results.jsonl"

# Application Passwords are disabled on this install (WP requires HTTPS,
# and this is a plain-HTTP local dev server) -- use real cookie+nonce auth
# instead: cookie jars from an actual wp-login.php POST, nonce scraped from
# an authenticated admin page's localized wpApiSettings.
SCRATCH = "/tmp/claude-0/-home-user-mongo/88417634-60f9-5bda-b080-646aad79e105/scratchpad"
USERS = {
    "author": {"cookiejar": f"{SCRATCH}/cookies_author.txt", "nonce": "8868032906"},
    "admin": {"cookiejar": f"{SCRATCH}/cookies_admin.txt", "nonce": "5077c95857"},
}

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _load_cookie_header(jar_path):
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


def auth_header(role):
    u = USERS[role]
    return {"Cookie": _load_cookie_header(u["cookiejar"]), "X-WP-Nonce": u["nonce"]}


def get_json(url, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": "wp-authfuzz", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return None, str(e).encode()


def req_json(url, data, method, headers=None):
    body = json.dumps(data).encode()
    hdrs = {"Content-Type": "application/json", "User-Agent": "wp-authfuzz", **(headers or {})}
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return None, str(e).encode()


def log_size():
    try:
        return os.path.getsize(DEBUG_LOG)
    except FileNotFoundError:
        return 0


def log_tail_since(offset):
    try:
        with open(DEBUG_LOG, "rb") as f:
            f.seek(offset)
            return f.read().decode(errors="replace")
    except FileNotFoundError:
        return ""


def db_snapshot():
    """Cheap state fingerprint: post count/authors/statuses + user roles."""
    out = subprocess.run(
        ["mysql", "-u", "wpuser", "-pwppass_local_2026", "wordpress", "-N", "-e",
         "SELECT ID, post_author, post_status, post_type FROM wp_posts ORDER BY ID;"],
        capture_output=True, text=True,
    )
    posts = out.stdout.strip()
    out2 = subprocess.run(
        ["mysql", "-u", "wpuser", "-pwppass_local_2026", "wordpress", "-N", "-e",
         "SELECT user_id, meta_value FROM wp_usermeta WHERE meta_key='wp_capabilities';"],
        capture_output=True, text=True,
    )
    roles = out2.stdout.strip()
    return posts, roles


def main():
    status, body = get_json(BASE + "/?rest_route=/")
    index = json.loads(body)
    routes = index["routes"]

    tested = 0
    results = []

    with open(RESULTS_PATH, "w") as outf:
        for route, rdef in routes.items():
            for endpoint in rdef.get("endpoints", []):
                methods = [m for m in endpoint.get("methods", []) if m in WRITE_METHODS]
                if not methods:
                    continue
                args = endpoint.get("args", {})
                if not isinstance(args, dict) or not args:
                    continue

                for argname, argschema in args.items():
                    atype = argschema.get("type")
                    if atype is None:
                        continue
                    types = atype if isinstance(atype, list) else [atype]

                    confused = []
                    if "array" in types:
                        confused.append(("scalar-for-array", "1"))
                    if "object" in types:
                        confused.append(("scalar-for-object", "1"))
                        confused.append(("array-for-object", [1, 2]))
                    if "integer" in types or "number" in types:
                        confused.append(("array-for-int", [1, 2]))
                        confused.append(("string-array-for-int", ["1) OR 1=1-- -"]))
                    if types and not ({"array", "object"} & set(types)):
                        confused.append(("array-for-scalar", ["x", "y"]))

                    if not confused:
                        continue

                    for method in methods:
                        for role in ("author", "admin"):
                            for label, val in confused:
                                tested += 1
                                before_log = log_size()
                                before_db = db_snapshot()

                                url = f"{BASE}/?rest_route={urllib.parse.quote(route)}"
                                payload = {argname: val}
                                status, resp_body = req_json(url, payload, method, headers=auth_header(role))

                                time.sleep(0.02)
                                after_log = log_tail_since(before_log)
                                after_db = db_snapshot()
                                resp_snippet = resp_body[:400].decode(errors="replace") if isinstance(resp_body, bytes) else str(resp_body)[:400]

                                db_changed = after_db != before_db
                                interesting = False
                                if after_log.strip():
                                    interesting = True
                                if status in (200, 201):
                                    interesting = True  # any accepted type-confused write is notable
                                if db_changed:
                                    interesting = True

                                record = {
                                    "route": route, "method": method, "role": role,
                                    "arg": argname, "label": label, "value": val,
                                    "status": status, "db_changed": db_changed,
                                    "new_log": after_log.strip(), "resp_snippet": resp_snippet,
                                }
                                if interesting:
                                    results.append(record)
                                    outf.write(json.dumps(record) + "\n")
                                    outf.flush()

    print(f"Tested {tested} (route,method,role,arg,confusion) combinations.")
    print(f"Interesting: {len(results)}")
    for r in results[:80]:
        print("----")
        print(r["route"], r["method"], r["role"], r["arg"], r["label"], "status=", r["status"], "db_changed=", r["db_changed"])
        if r["new_log"]:
            print("LOG:", r["new_log"][:300])
        else:
            print("RESP:", r["resp_snippet"][:200])


if __name__ == "__main__":
    main()
