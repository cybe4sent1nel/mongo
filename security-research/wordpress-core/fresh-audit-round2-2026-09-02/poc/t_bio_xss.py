import subprocess, json, requests
from wplab import sess, BASE
WP="/home/user/wpaudit/wordpress"
def wpcli(*a): return subprocess.run(["wp","--allow-root","--path="+WP,*a],capture_output=True,text=True).stdout.strip()
contrib=sess("contributor")

PAYLOADS = [
 '<script>alert(1)</script>',
 '<img src=x onerror=alert(1)>',
 '<a href="javascript:alert(1)">x</a>',
 '<svg/onload=alert(1)>',
 '<b onmouseover=alert(1)>x</b>',
 'plain <b>bold</b> text',
 '<iframe src=javascript:alert(1)>',
 '<style>*{x:expression(alert(1))}</style>',
 '<a href="#" onclick="alert(1)">y</a>',
 '<details open ontoggle=alert(1)>',
]
cid = int(wpcli("user","get","contributor","--field=ID"))
for p in PAYLOADS:
    r=contrib.rest("POST","/wp/v2/users/me",json={"description":p})
    stored=wpcli("user","meta","get",str(cid),"description")
    danger = any(t in stored.lower() for t in ('<script','onerror','onload','onmouseover','onclick','ontoggle','javascript:','expression('))
    flag = "  *** DANGEROUS STORED ***" if danger else ""
    print(f"in : {p[:45]:45s}\n  stored: {stored[:80]}{flag}")
