#!/usr/bin/env python3
"""
Contributor-level Group/Columns block `layout.contentSize` CSS-injection
attempt. Negative result - see README (Block-Supports layout section).
"""
from wplab import sess, BASE

s = sess('contributor')
n = s.fetch_rest_nonce()

payload_content = (
    '<!-- wp:group {"layout":{"type":"constrained",'
    '"contentSize":"10px} .injectedMARK{background:url(https://evil.example/x)}/*",'
    '"wideSize":"10px"}} -->\n'
    '<div class="wp-block-group"><!-- wp:paragraph --><p>hi</p><!-- /wp:paragraph --></div>\n'
    '<!-- /wp:group -->'
)
r = s.s.post(BASE + '/index.php?rest_route=/wp/v2/posts', headers={'X-WP-Nonce': n},
             json={'title': 'csstest', 'content': payload_content, 'status': 'pending'})
pid = r.json()['id']
print('contributor saved post', pid, r.status_code)
print('stored raw content contains marker:', 'injectedMARK' in r.json()['content']['raw'])

admin = sess('admin')
an = admin.fetch_rest_nonce()
r2 = admin.s.post(BASE + f'/index.php?rest_route=/wp/v2/posts/{pid}',
                   headers={'X-WP-Nonce': an}, json={'status': 'publish'})
link = r2.json()['link']
print('published at', link)

r3 = admin.s.get(link)
print('page status', r3.status_code)
if 'injectedMARK' in r3.text:
    idx = r3.text.find('injectedMARK')
    print('*** FOUND in rendered page ***', repr(r3.text[max(0, idx - 150):idx + 150]))
else:
    print('injectedMARK NOT found anywhere in the rendered page - safecss_filter_attr() dropped it.')
