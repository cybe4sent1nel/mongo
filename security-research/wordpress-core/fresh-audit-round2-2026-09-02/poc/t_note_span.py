import re, json, subprocess, requests
from wplab import sess, BASE
WP="/home/user/wpaudit/wordpress"
def wpcli(*a): return subprocess.run(["wp","--allow-root","--path="+WP,*a],capture_output=True,text=True).stdout.strip()

admin=sess("admin"); sub=sess("subscriber")
# a post with comments open
pid=admin.rest("POST","/wp/v2/posts",json={"title":"note span test","content":"x","status":"publish","comment_status":"open"}).json()["id"]

PAYLOADS = [
 ("plain span class",          '<span class="wp-note-mention user-1">@a</span>'),
 ("extra class",               '<span class="wp-note-mention user-1 evil">x</span>'),
 ("onmouseover on span",       '<span class="user-1" onmouseover="alert(1)">x</span>'),
 ("class value breakout",      '<span class="a&quot; onmouseover=&quot;alert(1)">x</span>'),
 ("style on span",             '<span class="user-1" style="position:fixed;inset:0">x</span>'),
 ("uppercase SPAN",            '<SPAN CLASS="user-1" OnMouseOver="alert(1)">x</SPAN>'),
 ("malformed no-quote class",  '<span class=user-1 onmouseover=alert(1)>x</span>'),
 ("class then slash",          '<span class="user-1"/onmouseover="alert(1)">x</span>'),
 ("nested lt in class",        '<span class="x><img src=x onerror=alert(1)>">y</span>'),
 ("data attr",                 '<span class="user-1" data-x="y">x</span>'),
 ("backtick/weird ws",         '<span\tclass="user-1"\nonmouseover="alert(1)">x</span>'),
 ("two spans",                 '<span class="evil1">a</span><span class="user-2">b</span>'),
 ("span in comment node",      '<!-- --><span class="a" onclick="alert(1)">x</span>'),
 ("class with html entity",    '<span class="user-1&#x20;evil">x</span>'),
 ("bogus comment breakout",    '<span class="user-1"><!--><img src=x onerror=alert(1)>--></span>'),
]

for label,p in PAYLOADS:
    r=sub.rest("POST","/wp/v2/comments",json={"post":pid,"content":p})
    if r.status_code not in (200,201):
        print(f"{label:26s} HTTP {r.status_code} {r.text[:80]}"); continue
    cid=r.json()["id"]
    raw=wpcli("db","query",f"SELECT comment_content FROM wp_comments WHERE comment_ID={cid}").split("\n")[-1]
    # flag anything dangerous surviving
    danger = bool(re.search(r'on\w+\s*=|<img|<script|style=|onerror|onmouseover|onclick', raw, re.I))
    print(f"{label:26s} -> {raw[:120]}")
    if danger: print(f"{'':26s}    *** DANGEROUS TOKEN SURVIVED ***")
