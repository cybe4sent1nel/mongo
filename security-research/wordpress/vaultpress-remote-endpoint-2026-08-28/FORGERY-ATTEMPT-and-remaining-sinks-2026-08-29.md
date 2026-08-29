# Signature forgery attempt, the remaining 3 unserialize() sinks, and a genuine finding: no replay protection

Direct follow-up to `EMPIRICAL-confirmation-2026-08-29.md`. Two asks: (1) actually attempt to
forge `validate_api_signature()` without knowing the secret, and find a proper path to pre-auth
RCE if one exists; (2) individually confirm the three `unserialize()`/`maybe_unserialize()` sinks
not yet tested one-by-one (`db:diff`, `db:count`, `db:cols`, `config:set`).

**Result up front, stated plainly: no signature forgery was found, and I did not find a way to
make this pre-auth from nothing. What I did find is real and distinct from both of those — a
replay weakness that turns "capture one valid request, by any means" into "replay it forever,"
without ever needing the secret.**

## 1. The other unserialize() sinks — all four independently confirmed live

Repeated the same marker-gadget technique from the prior round (a class with a harmless
`__wakeup()` that writes a timestamped file) against each remaining sink individually, each with
its own marker path so there's no ambiguity about which call fired:

| Sink | Payload field | Encoding | Result |
|---|---|---|---|
| `db:diff` | `signatures` | base64 → `unserialize()` | `GADGET_WAKEUP_FIRED_...` written; request returned `HTTP 200`, `response: false` (handled gracefully downstream, no crash) |
| `db:count` | `columns` | raw → `unserialize()` (no base64 at all) | `GADGET_WAKEUP_FIRED_...` written |
| `db:cols` | `columns` | raw → `unserialize()` | `GADGET_WAKEUP_FIRED_...` written |
| `config:set` | `val` | base64 → `maybe_unserialize()` | `GADGET_WAKEUP_FIRED_...` written |

Combined with `catchup:delete` from the prior round, that's **five** independent
`unserialize()`/`maybe_unserialize()` call sites in this one file, all confirmed to genuinely
reconstruct and trigger magic methods on attacker-controlled POST data, given a valid signature.

## 2. The forgery attempt — what was actually tried, and why none of it worked

Went back through `validate_api_signature()`, `sign_string()`, and the only place a secret is ever
set (`register()` / the `ui_load()` `action=register` handler), specifically looking for a way to
either (a) trick the check into passing without the real secret, or (b) get the real secret or an
attacker-chosen one into the site without needing it already.

**(a) Trying to trick the check itself:**
- Missing/empty `signature` → `no_signature`, rejected (sanity-checked, matches source).
- `signature` sent as an array instead of a string → blocked by the explicit `is_string( $_POST['signature'] )`
  check before anything else runs.
- Malformed `sig:salt` (no colon, or more than one) → `invalid_signature_format`, rejected.
- The comparison itself (`hash_equals( $sig[0], $signature )`) is PHP's own constant-time
  comparator — not the historical `==`-loose-comparison mistake, and not vulnerable to the classic
  "magic hash" trick that affects loose comparison of hex-numeric-looking strings, because
  `hash_equals()` never performs type juggling.
- HMAC-SHA1 keyed correctly via `hash_hmac('sha1', "$string:$salt", $secret)` — the secret is the
  HMAC *key*, not concatenated into the message, so this isn't susceptible to a length-extension
  attack (that class of attack applies to naive `hash($secret . $message)` constructions, which
  this deliberately isn't).
- The OpenSSL path (`openssl_verify(..., $public_key)` with a strict `1 === `) wasn't reachable to
  test here at all, since it requires the site to have `use_openssl_signing` enabled and a
  registered `public_key` — neither of which this test install has (this plugin defaults to the
  HMAC path). Not tested, not claimed either way.

None of this is a crypto break. It's confirmation that the obvious implementation-level mistakes
(loose comparison, non-constant-time compare, naive concatenation hash, missing type checks)
aren't present. A genuine break of correctly-keyed HMAC-SHA1 itself is not something source review
can produce, and I'm not going to pretend otherwise.

**(b) Trying to get a secret without already having one:**
- The only two places `secret` is ever written are `VaultPress::register()` (static) and the
  `ui_load()` handler for `$_POST['action'] === 'register'`. The latter requires
  `current_user_can( 'manage_options' )` (admin) *and* `check_admin_referer( 'vaultpress_register' )`
  (CSRF nonce) before it runs at all.
- Critically, even an admin's request **does not supply the secret value directly** — it supplies
  a `registration_key`, and the actual `secret` comes back from `contact_service( 'register', ... )`,
  which is an XML-RPC call to `vaultpress.com` (hardcoded hostname, HTTPS enforced via
  `$client->ssl()` when the hostname is exactly `vaultpress.com`). The response is validated
  (`$nonce != $response['nonce']` check, a fault-code check) before the secret from that response
  is trusted. There's no code path where a value the *client's own request* supplied ends up
  directly in the `secret` option.
- The outbound `contact_service()` method (used for the site talking *to* VaultPress) uses the
  secret to *sign* outbound requests but never returns or echoes it back to the caller in any
  response this plugin sends to a browser.
- No hardcoded/default/example secret exists anywhere in the file — the default is `''`, and an
  empty secret makes `validate_api_signature()` fail closed (`missing_secret`), not open.

I did not find an unauthenticated or admin-CSRF path to set an attacker-chosen secret, nor a way to
read the real one back out. Both of the obvious "make this pre-auth" routes are, as far as I could
establish from source and from testing what's testable, closed.

## 3. What I did find: no freshness/replay protection on the signature itself

This is the part worth taking seriously. `validate_api_signature()`'s `$salt` — the second half of
the client-supplied `signature` field (`$sig[1]`) — is entirely client-chosen and **never tracked,
consumed, or expired anywhere** in the verification path. Grepped the whole file for anything that
would enforce single-use or a freshness window on this specific check (a used-nonces table, a
transient, a timestamp comparison) — the only nonce/timestamp machinery in the file
(`get_login_tokens()`, `nonce_life`) is for a completely unrelated feature (VaultPress dashboard
SSO login tokens), not the API request signature.

Demonstrated directly: replayed the *exact* `case 'exec'` request (verbatim `code` and `signature`)
from the very first empirical test in the prior round, with no changes whatsoever.

```
HTTP 200, response: 'VP_EXEC_TEST_OK_4'
```

Identical output, second time, no new signing, no freshness check rejected it. A signed request,
once valid, is valid forever (or at least until the site's secret is rotated) — nothing about time
elapsed or prior use invalidates it.

## Why this matters even without a crypto break or a secret leak

This turns the threat model from "you need the secret" into "you need to have seen one valid
signed request, ever, by any means" — a meaningfully lower bar in the real world:

- Any full-request access/debug logging anywhere in the request path (a WAF, a CDN, a
  reverse-proxy access log configured to capture POST bodies, PHP error/debug logs that dump
  `$_POST` on an unrelated warning) that ever captured one legitimate VaultPress↔site exchange
  would hand an attacker a permanently-replayable credential for whatever that one action was —
  no cryptanalysis, no leaked secret required.
- If VaultPress's own normal operation legitimately uses `action=exec` for any maintenance/
  diagnostic purpose (not confirmed either way from this codebase — the *client* side that sends
  these requests lives on vaultpress.com's infrastructure, not in this plugin), a single exposure
  of that traffic would hand an attacker repeatable arbitrary code execution on the site, forever,
  without ever touching the HMAC.
- Even absent that specific scenario, it's a real, fixable gap: binding a timestamp into
  `$to_sign` and rejecting requests outside a short window, or tracking `$salt` values as
  single-use with a short TTL, are both standard, cheap mitigations that aren't present.

## Honest final verdict

**No pre-auth RCE found.** The two paths that would produce one — breaking the HMAC/OpenSSL check
itself, or finding a way to set/leak the secret without already having it — were both genuinely
attempted and both came back closed, for reasons documented above rather than asserted. What *is*
real, newly found, and demonstrated this round is the replay gap, which is a legitimate secondary
finding worth reporting alongside the others, but it is not the same claim as pre-auth RCE and I'm
not presenting it as one: it still requires a valid signed request to have existed and been
observed at some point, by whatever means.
