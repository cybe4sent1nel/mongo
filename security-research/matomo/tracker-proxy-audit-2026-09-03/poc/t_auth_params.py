import urllib.request, urllib.parse, json, subprocess, time, sys
P='http://127.0.0.1:8500'
op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def send(qs, body=None, headers=None, ctype='application/x-www-form-urlencoded'):
    h=dict(headers or {})
    if body is not None: h['Content-Type']=ctype
    r=urllib.request.Request(P+'/matomo.php?'+qs, data=body, headers=h)
    try:
        with op.open(r, timeout=25) as f: return f.status, f.read()[:300]
    except urllib.error.HTTPError as e: return e.code, e.read()[:300]
    except Exception as e: return -1, str(e).encode()[:300]

def db(q):
    return subprocess.run(['mysql','-h127.0.0.1','-umatomo','-pmatomo','matomo513','-N','-B','-e',q],
                          capture_output=True,text=True).stdout.strip()

OLD = int(time.time()) - 40*86400   # 40 days ago -> requires auth
base = "idsite=1&rec=1&apiv=1&send_image=0"
tests = []
def T(name, qs="", body=None, headers=None, ctype='application/x-www-form-urlencoded', bulk=False):
    tests.append((name,qs,body,headers,ctype,bulk))

vid = lambda n: ('%016x' % (0xA0000000000000 + n))

T("01 baseline",                 f"{base}&_id={vid(1)}&action_name=t01")
T("02 cip param (GET)",          f"{base}&_id={vid(2)}&action_name=t02&cip=9.9.9.9")
T("03 XFF header",               f"{base}&_id={vid(3)}&action_name=t03", None, {'X-Forwarded-For':'9.9.9.3'})
T("04 Client-IP header",         f"{base}&_id={vid(4)}&action_name=t04", None, {'Client-IP':'9.9.9.4'})
T("05 CF-Connecting-IP",         f"{base}&_id={vid(5)}&action_name=t05", None, {'CF-Connecting-IP':'9.9.9.5'})
T("06 cdt old (GET)",            f"{base}&_id={vid(6)}&action_name=t06&cdt={OLD}")
T("07 country=zz",               f"{base}&_id={vid(7)}&action_name=t07&country=zz")
T("08 cip[] array",              f"{base}&_id={vid(8)}&action_name=t08&cip[]=9.9.9.8")
T("09 cip empty",                f"{base}&_id={vid(9)}&action_name=t09&cip=")
T("10 cdt in POST body",         f"{base}&_id={vid(10)}&action_name=t10", f"cdt={OLD}".encode())
T("11 cdt via dot-name c.dt",    f"{base}&_id={vid(11)}&action_name=t11&c.dt="+str(OLD))
T("12 leading-space cdt",        f"{base}&_id={vid(12)}&action_name=t12&%20cdt="+str(OLD))
T("13 cdt[]=x array",            f"{base}&_id={vid(13)}&action_name=t13&cdt[]="+str(OLD))
T("14 XFF + cip param",          f"{base}&_id={vid(14)}&action_name=t14&cip=9.9.9.14", None, {'X-Forwarded-For':'9.9.9.44'})

# bulk cases
def bulkbody(reqs, extra=None):
    d = {"requests": reqs}
    if extra: d.update(extra)
    return json.dumps(d).encode()

T("20 bulk clean",  "", bulkbody([f"?{base}&_id={vid(20)}&action_name=t20"]), bulk=True)
T("21 bulk mixed (cdt entry + clean entry)", "",
  bulkbody([f"?{base}&_id={vid(21)}&action_name=t21&cdt={OLD}", f"?{base}&_id={vid(210)}&action_name=t21b"]), bulk=True)
T("22 bulk array entries clean", "", bulkbody([{ "idsite":"1","rec":"1","_id":vid(22),"action_name":"t22"}]), bulk=True)
T("23 bulk array entry with cdt", "",
  bulkbody([{"idsite":"1","rec":"1","_id":vid(23),"action_name":"t23","cdt":str(OLD)},
            {"idsite":"1","rec":"1","_id":vid(230),"action_name":"t23b"}]), bulk=True)
T("24 bulk clean + XFF", "", bulkbody([f"?{base}&_id={vid(24)}&action_name=t24"]), None, bulk=True)
T("25 bulk entry cdt nested array", "",
  bulkbody([{"idsite":"1","rec":"1","_id":vid(25),"action_name":"t25","cdt":[str(OLD)]}]), bulk=True)
T("26 bulk top-level token empty", "",
  bulkbody([f"?{base}&_id={vid(26)}&action_name=t26"], {"token_auth":""}), bulk=True)
T("27 bulk token array", "",
  bulkbody([f"?{base}&_id={vid(27)}&action_name=t27"], {"token_auth":["x"]}), bulk=True)

before = db("select max(idvisit) from matomo_log_visit") or "0"
for name,qs,body,headers,ctype,bulk in tests:
    hh = dict(headers or {})
    if name.endswith("XFF") or "XFF" in name: hh.setdefault('X-Forwarded-For','9.9.9.24')
    st,bd = send(qs, body, hh, ctype)
    print(f"{name:38s} http={st} resp={bd[:110]!r}")
time.sleep(1)
print("\n--- recorded visits ---")
print(db(f"select v.idvisit, hex(v.idvisitor), INET6_NTOA(v.location_ip), v.location_country, from_unixtime(v.visit_first_action_time) from matomo_log_visit v where v.idvisit > {before} order by v.idvisit"))
