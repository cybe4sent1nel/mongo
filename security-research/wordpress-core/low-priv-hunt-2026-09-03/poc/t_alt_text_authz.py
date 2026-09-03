#!/usr/bin/env python3
"""
Author-level attachment alt_text: confirm sanitize_text_field() strips tags
but NOT quotes, then confirm every render path re-escapes anyway.
Recorded as a negative result - see README.
"""
from wplab import sess, BASE
import subprocess, struct, zlib

WP = "/home/user/wpaudit/wordpress"


def png(w=10, h=10):
    def chunk(t, d):
        c = t + d
        return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
    raw = b''.join(b'\x00' + b'\xff' * (w * 3) for _ in range(h))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b''))


s = sess('author')
n = s.fetch_rest_nonce()
r = s.s.post(BASE + '/index.php?rest_route=/wp/v2/media', headers={
    'X-WP-Nonce': n, 'Content-Disposition': 'attachment; filename="a.png"',
    'Content-Type': 'image/png'}, data=png())
aid = r.json()['id']
print('attachment', aid)

payload = '<script>alert(1)</script>" onmouseover=alert(2) x="'
r2 = s.s.post(BASE + f'/index.php?rest_route=/wp/v2/media/{aid}',
              headers={'X-WP-Nonce': n}, json={'alt_text': payload})
print('REST update status', r2.status_code, 'stored (via REST):', repr(r2.json().get('alt_text')))

stored = subprocess.run(['wp', '--allow-root', '--path=' + WP, 'post', 'meta', 'get',
                          str(aid), '_wp_attachment_image_alt'],
                         capture_output=True, text=True).stdout
print('stored in DB                 :', repr(stored))

# Render through wp_get_attachment_image() the way a theme/the_content would.
html = subprocess.run(['wp', '--allow-root', '--path=' + WP, 'eval',
                        f"echo wp_get_attachment_image({aid}, 'thumbnail');"],
                       capture_output=True, text=True).stdout
print('wp_get_attachment_image() out:', html)
assert 'alt="&quot;' in html and 'x=&quot;"' in html, 'unexpected escaping shape'
assert 'x="' + '"' not in html.replace('&quot;', ''), 'sanity check failed'
print('\n-> the literal quote was converted to &quot; by esc_attr(); the payload is')
print('   inert text inside the alt="..." attribute, not a breakout. Not exploitable.')
