#!/usr/bin/env python3
"""Probe every registered REST route with each role (GET only) and report reachability."""
import re
import sys
import json
from wplab import sess, BASE
import requests

routes = [l.strip() for l in open(
    "/tmp/claude-0/-home-user-mongo/88417634-60f9-5bda-b080-646aad79e105/scratchpad/all_routes.txt")
    if l.strip()]

# Build a concrete path for each route pattern by substituting simple values.
SUBS = [
    (r"\(\?P<id>\[\\d\]\+\)", "1"),
    (r"\(\?P<id>[^)]+\)", "1"),
    (r"\(\?P<parent>[^)]+\)", "1"),
    (r"\(\?P<name>[^)]+\)", "core/get-user-info"),
    (r"\(\?P<slug>[^)]+\)", "core"),
    (r"\(\?P<collection>[^)]+\)", "core"),
    (r"\(\?P<type>[^)]+\)", "post"),
    (r"\(\?P<taxonomy>[^)]+\)", "category"),
    (r"\(\?P<font_family_id>[^)]+\)", "1"),
    (r"\(\?P<[a-z_]+>[^)]+\)", "1"),
]

sessions = {}
for role in ["subscriber", "contributor", "author", "editor", "admin"]:
    sessions[role] = sess(role)
anon = requests.Session()

results = {}
seen = set()
for line in routes:
    methods, rest = line.split(" ", 1)
    route, cb = rest.split(" -> ")
    if "GET" not in methods:
        continue
    path = route
    for pat, val in SUBS:
        path = re.sub(pat, val, path)
    if "(" in path or path in seen:
        continue
    seen.add(path)
    row = {}
    r = anon.get(BASE + "/index.php?rest_route=" + path, timeout=20)
    row["anon"] = r.status_code
    for role, s in sessions.items():
        rr = s.rest("GET", path, timeout=20)
        row[role] = rr.status_code
    results[path] = (row, cb)

for path, (row, cb) in results.items():
    line = " ".join(f"{k}={v}" for k, v in row.items())
    flag = ""
    if row["subscriber"] == 200 and row["admin"] == 200 and row["anon"] != 200:
        flag = "  <== subscriber-readable"
    print(f"{path:70s} {line}{flag}   [{cb}]")
