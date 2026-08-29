#!/usr/bin/env python3
"""
Type-confusion fuzzer for the WordPress REST API, informed by the wp2shell
(CVE-2026-60137) bug shape: a query-var sanitizer that only runs inside an
is_array()-gated branch, bypassable by sending a scalar where an array-typed
REST arg is expected (or vice versa).

For every registered REST route + arg declared as type "array" (or "object",
or with enum/oneOf), send the arg as a scalar string instead of an array, and
vice versa for scalar-typed args (send an array). Diff wp-content/debug.log
before/after each request and flag any new PHP warning/notice/error, with
extra attention to SQL-error-shaped log lines (which would indicate a type
confusion reached raw SQL, the exact wp2shell shape).
"""
import json
import subprocess
import time
import urllib.request
import urllib.parse
import urllib.error
import os

BASE = "http://127.0.0.1:8890"
DEBUG_LOG = "/home/user/wp-site/wordpress/wp-content/debug.log"
RESULTS_PATH = "/tmp/claude-0/-home-user-mongo/88417634-60f9-5bda-b080-646aad79e105/scratchpad/fuzz_results.jsonl"

def get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "wp-fuzz"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read()
            return r.status, body
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return None, str(e).encode()

def post_json(url, data, method="POST"):
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, method=method,
                                  headers={"Content-Type": "application/json", "User-Agent": "wp-fuzz"})
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

def main():
    status, body = get_json(BASE + "/?rest_route=/")
    index = json.loads(body)
    routes = index["routes"]

    results = []
    tested = 0

    with open(RESULTS_PATH, "w") as outf:
        for route, rdef in routes.items():
            for endpoint in rdef.get("endpoints", []):
                methods = endpoint.get("methods", [])
                args = endpoint.get("args", {})
                if not args:
                    continue
                for argname, argschema in args.items():
                    atype = argschema.get("type")
                    if atype is None:
                        continue
                    # normalize type to list
                    types = atype if isinstance(atype, list) else [atype]

                    confused_values = []
                    if "array" in types:
                        confused_values.append(("scalar-for-array", "1) OR SLEEP(0)-- -"))
                        confused_values.append(("scalar-for-array-alt", "../../../../etc/passwd"))
                    if "object" in types:
                        confused_values.append(("scalar-for-object", "1"))
                    if types and "array" not in types and "object" not in types:
                        confused_values.append(("array-for-scalar", ["1) OR SLEEP(0)-- -", "2"]))

                    if not confused_values:
                        continue

                    for method in methods:
                        if method not in ("GET", "POST"):
                            continue
                        for label, val in confused_values:
                            tested += 1
                            before = log_size()
                            if method == "GET":
                                qs = urllib.parse.urlencode({argname: val if isinstance(val, str) else json.dumps(val)})
                                url = f"{BASE}/?rest_route={urllib.parse.quote(route)}&{qs}"
                                status, resp_body = get_json(url)
                            else:
                                url = f"{BASE}/?rest_route={urllib.parse.quote(route)}"
                                status, resp_body = post_json(url, {argname: val}, method=method)

                            time.sleep(0.02)
                            new_log = log_tail_since(before)
                            resp_snippet = resp_body[:300].decode(errors="replace") if isinstance(resp_body, bytes) else str(resp_body)[:300]

                            interesting = False
                            if new_log.strip():
                                interesting = True
                            if status not in (200, 201, 400, 401, 403, 404, 405, 500) and status is not None:
                                interesting = True
                            if status == 500:
                                interesting = True

                            record = {
                                "route": route, "method": method, "arg": argname,
                                "label": label, "value": val, "status": status,
                                "new_log": new_log.strip(), "resp_snippet": resp_snippet,
                            }
                            if interesting:
                                results.append(record)
                                outf.write(json.dumps(record) + "\n")
                                outf.flush()

    print(f"Tested {tested} (route,method,arg,confusion) combinations.")
    print(f"Interesting results: {len(results)}")
    for r in results[:50]:
        print("----")
        print(r["route"], r["method"], r["arg"], r["label"], "status=", r["status"])
        if r["new_log"]:
            print("LOG:", r["new_log"][:500])
        else:
            print("RESP:", r["resp_snippet"][:200])

if __name__ == "__main__":
    main()
