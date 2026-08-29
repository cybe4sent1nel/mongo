# Second forgery-bypass pass on `validate_api_signature()` — result unchanged: no bypass found; severity verdict for the current (unbroken-crypto) state

Direct follow-up to `FORGERY-ATTEMPT-and-remaining-sinks-2026-08-29.md`, at explicit request to go back
and audit deeper for (a) any way to bypass or forge the signature gate that's standing between
anonymous access and the `case 'exec'` `eval()`, and (b) whether the finding, as it stands today
(gate unbroken), should be considered High severity.

**Result up front: still no bypass found.** This pass re-read every function in the trust chain from
scratch against the current clone (`/home/user/drivers/jetpack/projects/plugins/vaultpress/vaultpress.php`,
same commit as the original write-up) looking specifically for angles the first two rounds didn't cover,
found one genuinely new and previously-undocumented behavior (`ge`/`pe` request re-encoding happens
*after* signature validation), traced it all the way through, and confirmed it does not enable forgery
either. No new bypass to report. The severity verdict is below.

## New angle 1: `ge`/`pe` — action/POST are re-decoded *after* `validate_api_signature()` already ran

`parse_request()` (vaultpress.php:1762), order of operations:

```php
if ( !$this->validate_api_signature() ) {                    // line 1784 — the ONE gate
    die( 'invalid api call signature [...]' );
}

if ( !empty( $_GET['ge'] ) ) {                                // line 1789 — runs AFTER the gate
    if ( '1' === $_GET['ge'] ) $_GET['action'] = base64_decode( $_GET['action'] );
    if ( '2' === $_GET['ge'] ) $_GET['action'] = str_rot13( $_GET['action'] );
}
if ( !empty( $_GET['pe'] ) ) {                                // line 1797 — runs AFTER the gate
    if ( '1' === $_GET['pe'] ) {
        foreach( $_POST as $idx => $val ) {
            if ( $idx === 'signature' ) continue;
            $_POST[ base64_decode( $idx ) ] = base64_decode( $val );
            unset( $_POST[$idx] );
        }
    }
    // '2' === $_GET['pe'] does the same with str_rot13() instead of base64_decode()
}

switch ( $_GET['action'] ) { ... }                            // acts on the DECODED value
```

This is a real structural pattern worth flagging on its own terms: the value that gets *signed*
(the raw `$_GET['action']` and raw `$_POST` as literally received, via `$_SERVER['REQUEST_URI']` and
`$_POST` before this block runs) is not the same value that gets *acted on* (the post-decode result).
That is exactly the shape of a classic "verify one representation, act on a different one" bug (the
same family as TOCTOU/canonicalization mismatches, request smuggling, and signature-wrapping attacks
in other systems).

**Why it doesn't work as a bypass here, traced through concretely:**

- `$uri` (part of what's signed) is taken from the raw, literal query string
  (`preg_replace('/^[^?]+\?/', '?', $_SERVER['REQUEST_URI'])`) — this necessarily *includes* `ge=1`,
  `pe=1`, and the still-encoded `action=<base64>` exactly as sent, because it's extracted before any
  decoding happens.
- `$post` (the other half of what's signed) is `$_POST` minus `signature`, ksorted — also captured
  before the `pe` decode loop runs, so it's the raw, still-encoded POST values.
- So `$to_sign` (and therefore the HMAC/OpenSSL signature the attacker must produce) is always computed
  over the *wire-literal* bytes, including whatever `ge`/`pe` flags and encoded payloads are present.
  An attacker cannot add `ge=1`/`pe=1` to a request after the fact, or change what an existing encoded
  `action`/POST field decodes to, without changing the literal bytes that get signed — which requires
  the secret to re-sign, exactly like changing `action=exec` to `action=general:ping` directly would.
- I specifically checked for a decode/verify *order-of-operations* trick — e.g., whether the signature
  could be computed over one canonical form while two different raw byte-strings decode to the same
  meaning (a classic signature-malleability shape) — but there's no parsing ambiguity to exploit here:
  base64 and ROT13 are both deterministic, injective-enough for this purpose, and the *whole* raw string
  is what's hashed, not some semantically-normalized version of it. There's no daylight between "what
  was signed" and "what will eventually run" that an attacker controls without the secret.

Conclusion on this angle: it's a genuine, previously-undocumented implementation detail (most likely
existing to help VaultPress's own legitimate traffic dodge WAFs/mod_security rules that pattern-match
on literal strings like `action=db:restore` or `eval` in a POST body), and it's worth a line in the
writeup for completeness, but it is not a signature bypass. Confirmed by inspection, not just asserted.

## New angle 2: the registration nonce check (`$nonce != $response['nonce']`) — loose comparison, but not attacker-reachable

`ui_load()`'s `action=register` handler (line 738-756) does:
```php
$nonce = wp_create_nonce( 'vp_register_' . $registration_key );
...
if ( empty(...) || $nonce != $response['nonce'] ) { /* reject */ }
```
Loose `!=` on two hash-shaped strings is the classic PHP "magic hash" comparison shape (`"0e123..." ==
"0e456..."` both cast to `0` and compare equal). I checked whether this could be leveraged into a
forgery path and it can't, for two independent reasons: (1) this whole handler requires
`current_user_can('manage_options')` plus `check_admin_referer('vaultpress_register')` before it's
reachable at all — an attacker without an admin session can't hit this code; (2) `$response` here is
the deserialized reply from `contact_service('register', ...)`, an outbound HTTPS/XML-RPC call this
plugin itself makes to the hardcoded hostname `vaultpress.com` — it is not attacker-suppliable input
at all unless vaultpress.com's own infrastructure is compromised or the outbound TLS connection is
MITM'd, both outside this plugin's (or this audit's) attack surface. Noted for completeness; not a
finding.

## New angle 3: the login-token side channel (`get_login_tokens()` / `add_js_token()`) — real information exposure, but doesn't touch the `exec` gate

`get_login_tokens()` (line 1658) computes an anti-automation token for `wp-login.php`:
```php
$salt = wp_salt( 'nonce' ) . md5( $this->get_option( 'secret' ) );
'current' => substr( hash_hmac( 'md5', 'vp-login' . ceil( time() / $nonce_life ), $salt ), -12, 10 ),
```
and `add_js_token()` (hooked on `login_form`, i.e. rendered into the **public, unauthenticated**
`wp-login.php` page) writes this `current` token value into the page via obfuscated inline JS. This
token is a keyed HMAC over a fully attacker-*computable* message (`'vp-login'` concatenated with
`ceil(time()/900)` — a value only dependent on wall-clock time, and the site's own login page response
time discloses that clock precisely enough to compute it), keyed by `wp_salt('nonce') . md5(secret)`.

This is a real, previously-undocumented data point: **any anonymous visitor to `wp-login.php` can read
a value that is a keyed-HMAC output over a fully known message, keyed by a value derived from the
VaultPress secret.** That is not nothing — it's the shape of an oracle. I checked seriously whether it
gives an attacker anything usable against `validate_api_signature()`'s HMAC-SHA1 check and concluded no,
for concrete reasons: (1) it's a different hash function (MD5-HMAC vs. SHA1-HMAC) and a different key
material (`wp_salt('nonce') . md5(secret)`, not the raw `secret` itself) — there is no algebraic
relationship between an MD5-HMAC output keyed by `md5(secret)` and a SHA1-HMAC keyed by `secret`
directly that recovers `secret` from the former; (2) even treating this purely as a MAC oracle, HMAC
(keyed, not naive concatenation) is not vulnerable to length-extension, so an oracle over one message
doesn't let you forge over a different one; (3) recovering `secret` from `md5(secret)` requires
inverting MD5 (a preimage attack) or brute-forcing the underlying secret's keyspace offline — feasible
only if the secret is weak/short/dictionary-guessable, which is a property of the *specific* installed
secret, not a flaw in this code. This is a real, reportable secondary observation (a public,
unauthenticated page leaking a keyed hash of secret-derived material is worse practice than leaking
nothing) but it does not provide a forgery path into `case 'exec'` or any other switch branch.

## New angle 4: option-write side doors — checked and closed, same as before but re-verified against the current clone

Re-confirmed by direct re-read (not assumed from memory) that `secret`/`key`/`public_key`/
`use_openssl_signing` are written in exactly two places in the whole file (`register()` static helper
and the `ui_load()` `action=register` branch), both gated by `manage_options` + a WordPress core nonce,
and both only ever *receive* their value from `contact_service()`'s XML-RPC round-trip to
`vaultpress.com` — never from a value the requesting browser supplies directly. `sync_jetpack_options()`
(line 2810) can push the VaultPress option blob (including `secret`) *up* to WordPress.com via legacy
Jetpack Sync, but only for Jetpack versions `< 4.1` (essentially unreachable on any current install) and
even then this is the intended architecture (the vendor's own backend is supposed to know the shared
secret — that's what makes it *shared*), not a third-party attacker disclosure. No new option-write or
option-read side door found.

## Overall forgery verdict (unchanged from the prior round, now checked from four additional angles)

No way was found — across the original HMAC/OpenSSL/comparison read, the registration-nonce
loose-comparison check, the post-validation `ge`/`pe` decode-order question, the login-token side
channel, and the option-write surface — to make `validate_api_signature()` return `true` without
already possessing the site's real `secret` (or, for the untested OpenSSL branch, a private key
matching a registered `public_key`, which no test install here has configured). I looked for a genuine
bypass, in good faith, from several independent angles, and did not find one. I'm not going to claim
one exists.

## Severity verdict for the current, actually-demonstrated state

Applying the same CVSS discipline used on the SCF nav-menu finding (component-by-component, not a gut
call): to score *this* codebase's `case 'exec'` `eval()` as a standalone vulnerability at all, there has
to be a `PR` (Privileges Required) / precondition value that reflects what an attacker can actually
bring to the request. As things stand:

- **No demonstrated pre-auth path exists.** Every route to the `secret` (or a usable captured signed
  request) that this audit checked — breaking the HMAC, breaking OpenSSL verification, a loose-compare
  bug in an admin-gated registration flow, an option-write side door, a decode-order confusion — is
  closed. There is no CVSS `AV`/`AC`/`PR` combination this audit can honestly write down for "anonymous
  attacker reaches `eval()`", because no such path was found. Writing `PR:N` here would misrepresent
  what was actually shown.
- The only way to give this a score at all is to score it **conditional on the secret already being
  compromised by some other, unspecified means** — but that precondition is not a vulnerability *in this
  plugin*; it's the same precondition that makes "if you already have the admin password, you can do
  admin things" trivially true of any authentication secret anywhere. A secret-gated remote-management
  API being powerful *if the secret leaks* is the expected shape of that design pattern (comparable to
  a Stripe/GitHub webhook signing secret), not by itself a distinct, scoreable bug — unless the
  verification itself is broken (it isn't, as re-confirmed above) or there's a demonstrated way to lower
  the bar to get that secret (the replay gap and the `X-Forwarded-For` bypass are exactly that: real,
  demonstrated, but each still requires a *separate* precondition — "you've observed one valid signed
  request" or "the site has `allow_forwarded_for` enabled" respectively — that this audit did not find
  a way to satisfy from a bare anonymous starting point either).
- Applying the user's own standing rule from the SCF review verbatim: **don't reach for an escalation
  argument that's evidentially interesting but doesn't move the actual math.** "It's `eval()`, that's
  scary" is the same shape of reasoning as "it can reach a WooCommerce object" was for the SCF finding
  — true, vivid, and not a substitute for a demonstrated path from an unauthenticated request to that
  `eval()`.

**Honest answer to "is this considerable as High in its current state": no.** Not because the impact
described isn't severe — full `eval()`, arbitrary-file-as-SQL execution, four PHP Object Injection sinks
are about as severe an impact ceiling as exists — but because CVSS (and any triager) scores a
demonstrated path, and this audit, across three rounds now, has not produced one that starts from
"anonymous request" and ends at that impact. What's actually confirmed and scoreable on its own are the
two narrower, real bugs that don't need the primary secret at all:

1. **`X-Forwarded-For` bypass of `check_firewall()`** (confirmed empirically) — this alone doesn't reach
   `eval()`; it only removes one of two required independent gates (signature still required). By
   itself this is a weak access-control bug on a defense-in-depth layer, not a standalone high-impact
   finding.
2. **No replay/freshness protection on `$salt`** (confirmed empirically via literal request replay) —
   real, but requires "a previously-valid signed request was captured by some means" as its own
   precondition, which this audit also did not find a way to satisfy independently.

Neither, alone or combined, produces a demonstrated pre-auth chain, so neither reaches Medium or High as
an independently-scored CVSS finding by the same standard this audit is holding SCF findings to. What
this remains — accurately, and this is the correct way to characterize it — is a **well-evidenced
defense-in-depth / secure-design writeup**: if the plugin's shared secret is ever compromised by any
means, the blast radius is catastrophic and concentrated in one file behind one check, with a bypassable
secondary layer and no replay protection making "briefly observed" nearly as dangerous as "fully
possessed." That's a legitimate, valuable finding to hand to a plugin maintainer as a hardening report.
It is not, on the evidence actually produced across three rounds of trying, a scoreable RCE.

## Scope reminder (unchanged, restated for completeness)

VaultPress is Automattic's plugin (`Automattic/jetpack` monorepo), not one of the four WordPress.org-
maintained plugins in the actual audit scope for the HackerOne program this work targets (Classic
Editor, Create Block Theme, Secure Custom Fields, SQLite Database Integration). This entire line of
research — including this round — stays out of the submission queue for that program regardless of the
severity conclusion above; it's retained here as legitimate completed research, at explicit request, not
as a redirection of the in-scope hunting effort.
