#!/usr/bin/env python3
"""Explore what WP_REST_Comments_Controller::update_item() fails to re-check."""
import json
from wplab import sess, BASE

admin = sess("admin")
editor = sess("editor")
contrib = sess("contributor")
sub = sess("subscriber")


def j(r):
    try:
        return r.json()
    except Exception:
        return r.text[:200]


# Targets owned by other people.
pub = editor.rest("POST", "/wp/v2/posts", json={
    "title": "editor published", "content": "x", "status": "publish"}).json()["id"]
closed = editor.rest("POST", "/wp/v2/posts", json={
    "title": "comments closed", "content": "x", "status": "publish",
    "comment_status": "closed"}).json()["id"]
priv = editor.rest("POST", "/wp/v2/posts", json={
    "title": "editor PRIVATE", "content": "x", "status": "private"}).json()["id"]
draft = editor.rest("POST", "/wp/v2/posts", json={
    "title": "editor draft", "content": "x", "status": "draft"}).json()["id"]
page = admin.rest("POST", "/wp/v2/pages", json={
    "title": "admin page", "content": "x", "status": "publish"}).json()["id"]
print(f"targets: pub={pub} closed={closed} private={priv} draft={draft} page={page}")

# Contributor's own draft is the staging ground.
own = contrib.rest("POST", "/wp/v2/posts", json={"title": "contrib own", "content": "x"}).json()["id"]
print("contributor own draft:", own)


def new_note(content="staging note"):
    r = contrib.rest("POST", "/wp/v2/comments",
                     json={"post": own, "type": "note", "content": content})
    return r.json().get("id"), r.status_code


print("\n== direct create on each target (baseline, expect 403) ==")
for label, tid in [("published", pub), ("closed", closed), ("private", priv),
                   ("draft", draft), ("page", page)]:
    r = contrib.rest("POST", "/wp/v2/comments",
                     json={"post": tid, "type": "note", "content": "direct"})
    print(f"  create note on {label:10s} -> {r.status_code} {json.dumps(j(r))[:110]}")

print("\n== move an existing note onto each target ==")
for label, tid in [("published", pub), ("closed", closed), ("private", priv),
                   ("draft", draft), ("page", page)]:
    nid, sc = new_note(f"MOVED-NOTE-{label}")
    r = contrib.rest("POST", f"/wp/v2/comments/{nid}", json={"post": tid})
    ok = r.status_code == 200 and j(r).get("post") == tid
    print(f"  move note -> {label:10s} : {r.status_code} landed={ok} {json.dumps(j(r))[:100]}")

print("\n== field-level re-checks on update (own note, still on own post) ==")
nid, _ = new_note("field probe")
for field, value in [("author", 1), ("author_name", "administrator"),
                     ("author_email", "admin@example.test"),
                     ("author_ip", "1.2.3.4"), ("status", "approved"),
                     ("type", "comment"), ("date", "2000-01-01T00:00:00")]:
    r = contrib.rest("POST", f"/wp/v2/comments/{nid}", json={field: value})
    got = j(r).get(field) if isinstance(j(r), dict) else None
    print(f"  set {field:14s}={str(value):22s} -> {r.status_code} now={got!r}")

print("\n== same trick with a plain comment ==")
c = contrib.rest("POST", "/wp/v2/comments",
                 json={"post": own, "content": "PLAIN-COMMENT-CANARY"})
print("  create comment on own draft:", c.status_code, json.dumps(j(c))[:160])
if c.status_code in (200, 201):
    cid = c.json()["id"]
    for label, tid in [("published", pub), ("closed", closed), ("private", priv)]:
        r = contrib.rest("POST", f"/wp/v2/comments/{cid}", json={"post": tid})
        print(f"  move comment -> {label:10s}: {r.status_code} post={j(r).get('post') if isinstance(j(r),dict) else ''} status={j(r).get('status') if isinstance(j(r),dict) else ''}")
