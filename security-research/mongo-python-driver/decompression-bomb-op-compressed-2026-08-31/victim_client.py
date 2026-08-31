import sys
import time
import threading
import resource

from pymongo import MongoClient

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 27750

peak = [0]
stop = [False]

def watch_rss():
    while not stop[0]:
        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # KB on Linux
        if usage > peak[0]:
            peak[0] = usage
        time.sleep(0.2)

t = threading.Thread(target=watch_rss, daemon=True)
t.start()

uri = f"mongodb://127.0.0.1:{PORT}/?directConnection=true&compressors=zlib&serverSelectionTimeoutMS=3000&socketTimeoutMS=120000"
print(f"[client] connecting to {uri}")
client = MongoClient(uri)

try:
    print("[client] issuing ping command (will trigger the malicious compressed reply)...")
    t0 = time.time()
    result = client.admin.command("ping")
    dt = time.time() - t0
    print(f"[client] got result in {dt:.2f}s: {result}")
except Exception as e:
    dt = time.time() - t0 if 't0' in dir() else -1
    print(f"[client] EXCEPTION after ~{dt if isinstance(dt,float) else '?'}s: {type(e).__name__}: {e}")
finally:
    stop[0] = True
    t.join()
    print(f"[client] peak RSS observed: {peak[0]/1024/1024:.2f} GiB ({peak[0]} KB)")
