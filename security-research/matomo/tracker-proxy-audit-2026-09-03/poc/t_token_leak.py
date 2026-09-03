import urllib.request, urllib.error, itertools
TOKEN='dvfp78u17jxk5w6j1fppoi308490o7t5'
op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def g(url, data=None, headers=None):
    h=dict(headers or {})
    if data is not None: h['Content-Type']='application/x-www-form-urlencoded'
    r=urllib.request.Request(url, data=data, headers=h)
    try:
        with op.open(r,timeout=25) as f: return f.status, str(f.getheaders()), f.read()
    except urllib.error.HTTPError as e: return e.code, str(e.getheaders()), e.read()
    except Exception as e: return -1,'', str(e).encode()

B='http://127.0.0.1:8500'
urls=[]
# tracker with params designed to make Matomo echo / error
for extra in ['','&debug=1','&send_image=1','&idsite=0','&idsite=abc','&bots=1','&rec=0',
              '&url=%3Cscript%3E','&action_name=%3Cscript%3E','&_cvar=notjson','&cvar=[[',
              '&ping=1','&idgoal=0&revenue=abc','&ua=x','&lang=x','&res=x','&h=99','&e_c=a&e_a=b',
              '&search=x','&link=http://x','&download=http://x','&pf_net=abc','&gt_ms=abc']:
    urls.append((B+'/matomo.php?idsite=1&rec=1'+extra, None))
    urls.append((B+'/piwik.php?idsite=1&rec=1'+extra, None))
# opt-out variants
for extra in ['','&applyStyling=0','&showIntro=0','&language=xx','&divId=a','&setCookieInNewWindow=1',
              '&nonce=abc','&showConfirmOnly=1','&cookiePath=/a','&cookieDomain=.a','&useSecureCookies=0',
              '&fontFamily=aaa','&fontSize=10px','&fontColor=fff','&backgroundColor=000']:
    urls.append((B+'/matomo-proxy.php?module=CoreAdminHome&action=optOut'+extra, None))
    urls.append((B+'/matomo-proxy.php?module=CoreAdminHome&action=optOutJS'+extra, None))
urls.append((B+'/matomo-proxy.php?file=plugins/CoreAdminHome/javascripts/optOut.js', None))
urls.append((B+'/matomo.php', None))
urls.append((B+'/piwik.php', None))
urls.append((B+'/plugins/HeatmapSessionRecording/configs.php?idsite=1', None))
urls.append((B+'/plugins/HeatmapSessionRecording/configs.php', None))
urls.append((B+'/proxy.php', None))
urls.append((B+'/config.php', None))
# bypass
urls.append((B+'/matomo-proxy.php?module=&action=', b'module=CoreAdminHome&action=optOut'))

leaks=[]; html=[]
for u,d in urls:
    st,hd,b=g(u,d)
    body=b.decode('utf8','replace')
    if TOKEN in body or TOKEN in hd: leaks.append((u,'TOKEN'))
    if '8400' in body or '8400' in hd: leaks.append((u,'MATOMO_URL/host'))
    ct = 'text/html' in hd
    if ct and len(b)>0: html.append((u,st,len(b)))
print("total requests:", len(urls))
print("\n== token / upstream-URL leaks ==")
for x in leaks: print("  ", x)
if not leaks: print("   none")
print("\n== text/html responses with a body ==")
for x in html: print("  ", x)
