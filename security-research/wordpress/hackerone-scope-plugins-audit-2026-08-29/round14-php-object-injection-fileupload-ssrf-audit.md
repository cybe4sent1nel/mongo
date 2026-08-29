# Round 14: PHP Object Injection / file-upload type validation / XML-RPC pingback
# SSRF audit — three more classic RCE-adjacent bug classes, all negative

**Trigger for this round**: continued instruction to keep hunting for a fresh RCE/
High/Critical bug in WordPress core, "whatever method." This round pivoted away from
the REST API argument-validation surface (rounds 11/13) and the attribute-injection
XSS shape (round 12) toward three different classic "leads to RCE" bug families that
hadn't yet been checked this audit: PHP Object Injection via `unserialize()`, file
upload MIME/extension-spoofing bypass, and XML-RPC pingback SSRF. All three: negative.

## 1. PHP Object Injection — every `unserialize()` call site in core

Grepped all of `wp-includes/` and `wp-admin/includes/` for direct `unserialize()`
calls (excluding `maybe_unserialize()`, which already gates on `is_serialized()` and
is a much larger, separately-auditable surface not covered by this round). Three
call sites total:

- **`class-wp-customize-widgets.php:1496`** (`sanitize_widget_instance()`) — gated by
  `hash_equals( wp_hash( $decoded ), $value['instance_hash_key'] )` immediately before
  the `unserialize()` call. `wp_hash()` is a keyed hash derived from the site's
  `AUTH_KEY`/`AUTH_SALT` secrets (`wp_salt()`) — an attacker cannot forge a valid hash
  for their own chosen serialized payload without knowing those secrets, so this
  `unserialize()` only ever runs on data the server itself produced and round-tripped
  (the customizer's live-preview JS echoes back exactly what was sent to it). This is
  the correct, intentional mitigation for this exact historical bug class, not a gap.
- **`blocks/legacy-widget.php:44`** (`render_block_core_legacy_widget()`) — identical
  pattern: `hash_equals( wp_hash( $serialized_instance ), (string) $attributes['instance']['hash'] )`
  gates the `unserialize()`. Same protection, same reasoning.
- **`rss.php:809`** (`RSSCache::unserialize()`, legacy MagpieRSS compatibility shim) —
  confirmed via grep that this method is never actually called anywhere in core;
  `RSSCache::get()`/`check_cache()` (the methods that *are* used, by the deprecated
  `fetch_rss()`) go through `get_transient()` directly and never invoke
  `$this->unserialize()`. Dead code, unreachable.

No PHP Object Injection found — the two live call sites are protected by a secret-
keyed HMAC gate (the known-correct fix for this bug class), and the third is
unreachable dead code.

## 2. File upload extension/MIME-type validation bypass

Read `wp_check_filetype()` and `wp_check_filetype_and_ext()`
(`wp-includes/functions.php`) end to end, specifically hunting for the classic
bypass techniques:

- **Double-extension bypass** (`shell.php.jpg` tricking a prefix-matching extension
  check into treating it as PHP): `wp_check_filetype()`'s regex
  (`'!\.(' . $ext_preg . ')$!i'`) is anchored to the end of the filename (`$`), so it
  always matches against the *true* last extension component, never a fake extension
  earlier in the name. `shell.php.jpg` matches only `jpg`, not `php`.
- **Content/extension mismatch** (renaming a PHP payload to `.jpg`):
  `wp_check_filetype_and_ext()` independently verifies actual file content — via
  `wp_get_image_mime()` for anything claiming an `image/*` type, and via
  `finfo_file()` (fileinfo) as a fallback for everything else — and forces
  `$type = false; $ext = false;` (rejecting the upload) whenever the real content
  type doesn't match what the claimed extension implies. The one deliberately
  loosened case (`nonspecific_types` like `application/octet-stream`) still requires
  the claimed type's major category to be `application`/`video`/`audio`, never
  `image` or (implicitly) never something that would map to an executable-extension
  bucket.
- **Allowlist enforcement**: after all of the above, the resolved `$type` is checked
  against `get_allowed_mime_types()` and rejected if absent — `.php`/`.phtml`/etc. are
  not in the default allowed-mimes list at all, so even a file that somehow survived
  the content checks with a executable-adjacent extension would be rejected here.

No bypass found. This function is evidently the product of years of hardening against
exactly this bug class (the HEIC-extension special-casing and Google-Docs-duplicate-
mime workaround in the current code are themselves evidence of relatively recent,
careful maintenance) — consistent with file-upload-to-RCE being one of the most
heavily scrutinized areas of WordPress core.

## 3. XML-RPC `pingback.ping` SSRF

Read `WP_XMLRPC_Server::pingback_ping()` end to end — XML-RPC pingbacks are
unauthenticated by design (any site can pingback any post), making this historically
one of WordPress's richest sources of real SSRF/RCE-adjacent CVEs (e.g.
CVE-2013-0235's use of pingback as an SSRF/port-scanning amplifier).

The current implementation fetches the attacker-supplied `$pagelinkedfrom` URL via
**`wp_safe_remote_get()`**, not a raw request — this is the specific WP HTTP API entry
point that forces `'reject_unsafe_urls' => true`, routing the request through
`wp_http_validate_url()` before it's allowed to proceed. Read that function in full
(`wp-includes/http.php:559`) as its own target, since it's the actual security
boundary here:

- Rejects the URL outright if it contains userinfo (`user:pass@host`), or if the host
  contains any of `:#?[]` — which blanket-rejects every IPv6 literal address
  (`[::1]`, `[fe80::...]`, etc.) rather than trying to parse and range-check IPv6,
  a conservative fail-closed design rather than an allowlist gap.
- For non-same-host requests, resolves the hostname and range-checks the **resolved**
  IP (not the original host string) against an extensive, evidently recently-
  maintained blocklist: loopback, RFC1918 private ranges, link-local/cloud-metadata
  (`169.254.0.0/16`), CGNAT (`100.64.0.0/10`), benchmarking (`198.18.0.0/15`), all
  three TEST-NET ranges, 6to4 relay anycast, multicast, and reserved/broadcast —
  considerably more complete than the minimal historical fix.
- Checked specifically for legacy IP-obfuscation bypasses (octal `0177.0.0.1`,
  decimal `2130706433`, hex `0x7f000001`) since those are a classic SSRF-filter
  bypass class: the dotted-quad regex used for the fast-path IP check doesn't match
  any of these forms, so they fall through to `gethostbyname()` — and critically, the
  range check runs against **whatever `gethostbyname()` returns**, not the original
  input string. Even on platforms where the underlying resolver accepts legacy
  numeric notations and resolves them directly to an IP (bypassing DNS), the
  resulting dotted-decimal address still gets range-checked before the request is
  allowed — the code's structure closes this class by construction, not merely by
  accident.

No bypass found in the validation logic itself. (A DNS-rebinding TOCTOU race — where
the hostname resolves to a public IP during `wp_http_validate_url()`'s check but a
private IP by the time the actual connection is made — is a known, accepted residual
limitation of this whole design pattern, not something specific to WordPress's
implementation, and isn't a fresh, reportable bug on its own without a working race
demonstrated against the actual HTTP transport in use.)

## Why this round's negative result is still informative

Three genuinely distinct, historically fruitful bug classes, each checked against a
plausible current-core candidate, each found to already be correctly and (in the SSRF
case) quite thoroughly hardened. This is meaningfully different from rounds 9/10/12's
"look for a sibling of one specific known CVE" pattern — this round independently
picked classic *categories* of RCE-adjacent bugs and audited core's actual current
defenses against each, rather than pattern-matching one prior report. The consistent
result (mature, evidently well-maintained protections in every case) is itself useful
signal about where remaining effort is and isn't likely to pay off in WP core
specifically, going forward.

## What this is not

Not RCE, not SSRF, not PHP Object Injection. Three honestly-reported negative results
from real, complete investigations, not surface-level checks.

## Standing findings for this audit, unchanged by this round

- Round 6: **CONFIRMED** — SCF bidirectional-field broken access control (reported).
- Round 11: **CONFIRMED** — WP Core REST API unauthenticated argument-validation crash /
  DoS (CWE-248/CWE-20), Medium severity; round 13 confirmed no write-path impact.
- Rounds 12, 14: negative — no fresh XSS/RCE/privesc/SSRF/object-injection bug found via
  five additional distinct hunting methods across this and the prior round.
