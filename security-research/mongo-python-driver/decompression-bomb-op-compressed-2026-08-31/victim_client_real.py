import sys
import time
import threading
import resource

from pymongo import MongoClient

PROXY_PORT = int(sys.argv[1])

peak = [0]
stop = [False]

def watch_rss():
    while not stop[0]:
        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # KB on Linux
        if usage > peak[0]:
            peak[0] = usage
        time.sleep(0.1)

t = threading.Thread(target=watch_rss, daemon=True)
t.start()

uri = (
    f"mongodb://127.0.0.1:{PROXY_PORT}/?directConnection=true&compressors=zlib"
    f"&serverSelectionTimeoutMS=5000&socketTimeoutMS=120000&heartbeatFrequencyMS=60000"
)
print(f"[client] connecting through proxy at {uri}")
client = MongoClient(uri)

t0 = time.time()
try:
    print("[client] issuing ping command against REAL mongod 8.3.8 (via MITM proxy)...")
    result = client.admin.command("ping")
    dt = time.time() - t0
    print(f"[client] got result in {dt:.2f}s: {result}")
except Exception as e:
    dt = time.time() - t0
    print(f"[client] EXCEPTION after ~{dt:.2f}s: {type(e).__name__}: {e}")
finally:
    stop[0] = True
    t.join()
    print(f"[client] peak RSS observed: {peak[0]/1024/1024:.2f} GiB ({peak[0]} KB)")
