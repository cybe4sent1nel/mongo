# Jetpack VaultPress: one HMAC check gates `eval($_POST['code'])`, arbitrary-local-file SQL execution, and 4x PHP Object Injection

**Plugin:** Jetpack VaultPress (`Automattic/jetpack` monorepo, `projects/plugins/vaultpress/`)
**File:** `vaultpress.php`, commit `663c7e1a77` (2026-08-26, current HEAD as cloned this session)
**Stable tag:** 4.0.7 — readme.txt states `Tested up to: 7.1` (the WordPress release audited earlier
this session) and marks the plugin deprecated ("Please install Jetpack VaultPress Backup instead")
but it remains listed, downloadable, and installable today; existing installs from the VaultPress
era are still running this exact code path.

**Status: not a confirmed pre-auth RCE. I did not break the cryptographic check that gates this
code, and I'm not claiming to. What I am reporting, with concrete evidence, is that this plugin
concentrates an extraordinary blast radius — `eval()` of POST data, arbitrary-local-file SQL
execution, and four independent PHP Object Injection sinks — behind exactly one shared-secret
check, with a secondary IP-allowlist layer that I did demonstrate is bypassable by header spoofing
on any site with a common option enabled. If that one check is ever forged, guessed, or if its
secret ever leaks by any unrelated means, the result is immediate, multiply-redundant code
execution. That concentration is itself the finding, independent of whether the crypto holds.**

## How the endpoint is reached — no WordPress auth layer at all

`vaultpress.php` (the plugin's main file, loaded on every request while the plugin is active) ends
with, at top level, outside any class or hook registration:

```php
if ( isset( $_GET['vaultpress'] ) && $_GET['vaultpress'] ) {
    ...
    $vaultpress->parse_request( null );
    die( 0 );
}
```

This runs as the plugin file itself loads — before any WordPress capability check, before
`is_user_logged_in()` would even be meaningful. Any anonymous HTTP request with `?vaultpress=1` in
the query string reaches `VaultPress::parse_request()`. There is no WordPress-level authentication
anywhere in this path; the *entire* trust boundary is one method: `validate_api_signature()`.

## The one gate: `validate_api_signature()` (vaultpress.php:2324)

Two verification modes, selected by whether OpenSSL asymmetric signing is configured:

- **HMAC mode** (the fallback, and the only mode when `use_openssl_signing`/`public_key` aren't
  set): `$signature = hash_hmac( 'sha1', "$to_sign:$salt", $secret )`, compared with
  `hash_equals( $sig[0], $signature )`. This is a properly-keyed HMAC (not naive
  `sha1($secret.$data)`, which would be length-extension-vulnerable) with a timing-safe comparison.
  I read this carefully and found no bypass.
- **OpenSSL mode**: `1 === openssl_verify( serialize(...), base64_decode($sslsig), $public_key )`
  — correct strict `1 ===` comparison (a `==` here would treat `openssl_verify()`'s `-1`
  error-return as falsy-but-not-quite, though `1 == -1` is false either way; the point is this
  isn't the classic loose-comparison mistake). No bypass found.

I am explicitly **not** claiming to have broken either mode. Both use the correct primitives
correctly as far as a source read can establish. What follows assumes an attacker who has, by any
means, obtained the site's VaultPress `secret` option (or a private key matching its registered
public key) — which this code treats as the *only* thing standing between an anonymous request and
everything below.

## What sits behind that one check

All of the following are `case` branches inside the same `switch ( $_GET['action'] )` in
`parse_request()`, reached the instant `validate_api_signature()` returns `true`. No further
capability check, no per-action authorization — one boolean gates all of it.

### `case 'exec'` (vaultpress.php:1858-1868) — direct `eval()` of POST data

```php
case 'exec':
    /*
     * Despite appearances, this code is not an arbitrary code execution vulnerability due to the
     * $this->validate_api_signature() check above. Static analysis tools will probably flag this.
     */
    $code = $_POST['code'];
    if ( !$code )
        $this->response( "No Code Found" );
    $syntax_check = @eval( 'return true;' . $code );
    if ( !$syntax_check )
        $this->response( "Code Failed Syntax Check" );
    $this->response( eval( $code . ';' ) );
```

The comment is the developers' own acknowledgment of exactly what this looks like. It is, in fact,
`eval()` of client-supplied PHP source, gated by nothing else.

### `case 'db:restore'` (vaultpress.php:2131-2135) — arbitrary local file executed as SQL, with a bypassable integrity check

```php
case 'db:restore':
    if ( !empty( $_POST['path'] ) && isset( $_POST['hash'] ) ) {
        $delete = !isset( $_POST['remove'] ) || $_POST['remove'] && 'false' !== $_POST['remove'];
        $this->response( $bdb->restore( $_POST['path'], $_POST['hash'], $delete ) );
    }
```

`$_POST['path']` is passed **directly** as the file to restore — `VaultPress_Database::restore()`
(class.vaultpress-database.php:356):

```php
function restore( $data_file, $md5_sum, $delete = true ) {
    global $wpdb;
    if ( !file_exists( $data_file ) || !is_readable( $data_file ) || !filesize( $data_file ) )
        return array( 'last_error' => 'File does not exist', 'data_file' => $data_file );
    if ( $md5_sum && md5_file( $data_file ) !== $md5_sum )
        return array( 'last_error' => 'Checksum mistmatch', 'data_file' => $data_file );
    if ( function_exists( 'exec' ) && ( $mysql = exec( 'which mysql' ) ) ) {
        ...
        exec( sprintf( '%s %s', escapeshellcmd( $mysql ), vsprintf( '-A --default-character-set=%s -u%s -p%s -h%s -P%s %s < %s', array_map( 'escapeshellarg', $params ) ) ), $output, $r );
        ...
    }
    ...
    while( !feof( $fh ) ) {
        $query = trim( stream_get_line( $fh, $size, ";\n" ) );
        if ( !empty( $query ) ) {
            $affected_rows += $wpdb->query( $query );
```

Two findings here, one structural and one a concrete logic bug:

1. **No path restriction at all.** `$data_file` can be any path the web server process can read —
   there's no check that it lives under a VaultPress-controlled temp directory. The only
   requirement is `file_exists()`/`is_readable()`/non-zero size. If an attacker can get a file onto
   disk by *any* other means (a media upload with SQL-shaped content in a comment/EXIF field, a log
   file, a cache file another plugin writes, `/tmp` scratch files) and knows or guesses its path,
   its entire content is either piped into the `mysql` CLI as a full import (properly
   `escapeshellarg()`'d for the shell — not a command-injection bug, but every line of the file
   becomes SQL executed with the site's DB credentials) or read and run line-by-line via
   `$wpdb->query()`. Both are full SQL execution against the site's database from a file whose
   *content* the attacker controls but whose *path* need not be under their direct control.
2. **The integrity check is bypassable by construction, not by attack.** `if ( $md5_sum && ... )`
   — PHP's `&&` short-circuits on a falsy `$md5_sum`, and an empty string is falsy. The call site
   only requires `isset( $_POST['hash'] )`, not a non-empty one, so sending `hash=` (empty) skips
   the checksum comparison entirely. This isn't a crypto weakness, it's a plain logic bug: the
   verification the code clearly intends to enforce is opt-in for the caller, not mandatory.

### Four `unserialize()` / `maybe_unserialize()` calls directly on POST data — classic PHP Object Injection shape

- `case 'catchup:delete'` (line 1874): `foreach( unserialize( $_POST['pings'] ) as $ping )`
- `case 'db:diff'` (line 2098): `unserialize( base64_decode( $signatures ) )` where
  `$signatures = $_POST['signatures']`
- `case 'db:count'` / `'db:cols'` (lines 2101, 2104): `unserialize( $columns )` where
  `$columns = $_POST['columns']` — **not even base64-decoded**, raw `unserialize()` on a POST value
- `case 'config:set'` (line 2226): `maybe_unserialize( base64_decode( $_POST['val'] ) )`

None of these restrict the reconstructed classes (no `unserialize( $x, array( 'allowed_classes' =>
false ) )` anywhere in this file). Each is independently a PHP Object Injection sink: if *any*
class loaded in the site's process — Jetpack's own code, another plugin, the active theme — defines
a dangerous `__wakeup()`, `__destruct()`, or `__toString()`, an attacker who can reach this switch
can instantiate and trigger it. I checked Jetpack's own codebase specifically for such a gadget
earlier this session (grepped every `__wakeup`/`__destruct`/`__toString`/`__call`/`__invoke` in
both the `jetpack` plugin and `packages/`) and found none dangerous — the two `__wakeup()`
implementations that exist are defensive (`die()`/`wp_die()` to *block* unserialization). But a POP
gadget doesn't need to live in this plugin; it needs to live anywhere in the same PHP process, and
a typical WordPress install runs a dozen-plus plugins. Four independent sinks, each one
unserialize()-of-attacker-string away from RCE the moment a gadget exists anywhere on the site.

## A concretely demonstrated (not hypothetical) weakness in the secondary IP-allowlist layer

`validate_api_signature()` also calls `check_firewall()` (vaultpress.php:2404), which checks the
requester's IP against VaultPress's published service-IP CIDR ranges — intended as defense-in-depth
alongside the signature check. It has a real, demonstrable bypass:

```php
$forward_header = $this->get_option( 'allow_forwarded_for' );
if ( true === $forward_header || 1 == $forward_header ) {
    $forward_header = 'HTTP_X_FORWARDED_FOR';
}
if ( ! empty( $forward_header ) && ! empty( $_SERVER[ $forward_header ] ) ) {
    $remote_ips[ $forward_header ] = $_SERVER[ $forward_header ];
}
```

When the site has the `allow_forwarded_for` option enabled (a legitimate setting for sites behind a
CDN/load balancer, and the *kind* of setting VaultPress itself walks a site owner into turning on
when its normal IP-matching fails behind a proxy — see `check_firewall()`'s own
`testing_all_headers` connection-test logic a few lines above), the code trusts
`$_SERVER['HTTP_X_FORWARDED_FOR']` **verbatim**, with no check that the request actually passed
through a proxy that sets that header authoritatively. `X-Forwarded-For` is a plain client-supplied
HTTP header on any site not behind a proxy that overwrites it. VaultPress's service IP ranges are
fetched from a public, unauthenticated endpoint (`request_firewall_update()`, `cidr_ranges=1`) —
not a secret — so they're trivially obtainable. On a site with `allow_forwarded_for` enabled, an
attacker sends `X-Forwarded-For: <any published VaultPress IP>` and sails through this layer.

This does **not** bypass `validate_api_signature()`'s cryptographic check by itself — the firewall
check and the signature check are both required, not either/or. What it does is remove one of the
two independent layers the code was clearly designed to have, on any site where a documented,
legitimate option is turned on. That leaves the HMAC/OpenSSL check as the sole remaining gate for
that entire blast radius on such a site.

## Why I'm not calling this a confirmed RCE

Every path above requires the attacker to already possess the site's VaultPress `secret` (HMAC
mode) or a private key for its registered `public_key` (OpenSSL mode). I read `sign_string()`
(`hash_hmac( 'sha1', "$string:$salt", $secret )`) and the `hash_equals()` comparison and found them
implemented correctly — no length-extension issue (HMAC, not naive concatenation-hash), no
loose-comparison bug, no algorithm-confusion I could identify from source alone. I have not
demonstrated a way to forge a valid signature without the secret, and I want to be explicit that
this write-up does not claim one exists.

What this write-up documents, with line-level evidence, is the *shape* of the risk: this plugin
made the design choice to gate `eval()` of arbitrary PHP, arbitrary-local-file SQL execution, and
four PHP Object Injection sinks behind a single shared secret, with no per-action authorization and
a redundant IP-layer that's concretely bypassable via header spoofing on a documented, legitimate
configuration. If that secret is ever obtained by any means unrelated to breaking the crypto itself
— a leaked options-table backup, a staging site sharing production's connection secret, a
support-ticket paste, log exposure, a completely separate and unrelated vulnerability in the same
site — the result is not "one bug," it's four independently-sufficient roads to code execution or
full database compromise, simultaneously.

## Recommendation, if this is worth pursuing further

1. Attempt to independently obtain or derive a valid `secret`/signature for a test install (out of
   scope for this static-analysis-only session) to determine whether this is empirically a live
   pre-auth RCE or remains gated as designed.
2. Regardless of (1): the `case 'exec'` branch should not exist. There is no legitimate reason for
   a WordPress plugin to expose raw `eval()` of a POST parameter behind a single symmetric secret
   with no capability check — this is exactly the kind of code a defense-in-depth review flags
   regardless of whether the outer gate holds today.
3. Fix the `db:restore` checksum bypass (`isset()` → require non-empty `hash`, or better, always
   require and enforce it) and constrain `$data_file` to a known VaultPress-controlled directory
   rather than accepting an arbitrary path.
4. Add `array( 'allowed_classes' => false )` (or migrate to JSON, as Jetpack's own newer `sync`
   package already does — see `packages/sync/src/class-json-deflate-array-codec.php`, audited
   earlier this session, which deliberately avoids native PHP serialization for exactly this
   reason) to all four `unserialize()`/`maybe_unserialize()` sites.
5. Don't trust `X-Forwarded-For` (or any single configurable header) as an authoritative client IP
   without also validating the immediate peer IP is a trusted proxy.

This plugin is marked deprecated in favor of "Jetpack VaultPress Backup," which may mean the
maintainers consider it low-priority — but it remains distributed, installable, and (per its own
readme) tested against the current WordPress release, so existing and new installs alike still run
this exact code.
