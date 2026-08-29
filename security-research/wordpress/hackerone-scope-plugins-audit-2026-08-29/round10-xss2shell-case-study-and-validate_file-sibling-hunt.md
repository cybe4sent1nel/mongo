# Round 10: XSS2Shell (CVE-2026-64638) case study + validate_file() trust-boundary sibling hunt

Continuing the WordPress Core RCE/XSS push per direct instruction to keep going and to study the
second recent real-world chain, XSS2Shell. Same constraint as round 9: the secondary-source blogs
(Patchstack, pwn.ai, Brandefense, coffsec, hackread, etc.) are all egress-blocked from this
environment, so — as with wp2shell — went straight to the `wordpress-develop` git history for the
actual fix commits, which is authoritative anyway.

## XSS2Shell (CVE-2026-64638), read from the real fix commits

WordPress 7.0.3 (and backports to every branch from 4.7 through 6.9) shipped 2026-08-06/07. Found
the full security-fix bundle via the branch-merge commits (e.g. `44363f5110` on the 6.9 branch,
which lists all 11 fixes in that release in its commit message) and read the two commits that
correspond to the publicly-reported chain stages:

**Stage 1 — pre-auth reflected XSS on the login page** (`d46d1011b1`, "Users: Prevent usernames
from mangling HTML.", `src/wp-includes/user.php` + `src/wp-login.php`):

`wp_authenticate_username_password()` built its "username not registered" / "incorrect password"
error messages by splicing the raw, attacker-supplied `$username` (the login form's `log` POST
field) directly into an HTML string:

```php
// pre-fix
sprintf( __( '<strong>Error:</strong> The username <strong>%s</strong> is not registered...' ), $username )
// and
'<strong>' . $username . '</strong>'
```

No `esc_html()`. This is reachable by anyone, unauthenticated, by submitting any login attempt to
`wp-login.php` — the classic reflected-XSS-in-an-error-message shape, except on the one page every
WordPress site exposes by default with zero preconditions. Fix: wrap `$username` (and, in sibling
functions, `$email`) in `esc_html()` at each of the four sites the commit touches. Traced every other
`$user_login`/`$username` use in `wp-login.php` and `wp-includes/user.php` afterward (see below) —
this was the only unescaped one; the form re-population inputs (`value="<?php echo ...
$user_login"`) were already correctly `esc_attr()`-wrapped before this fix, so the bug was narrowly
this one message-text sink, not a wholesale missing-escaping problem across the file.

**Stage 3 — DOM clobbering of the inline emoji-settings config** (part of the same bundle, "EmojI:
Ensure that the emoji settings come from a script element.", `src/js/_enqueues/lib/emoji-loader.js`):

```js
// pre-fix
const settings = JSON.parse( document.getElementById( 'wp-emoji-settings' ).textContent );
// post-fix
const script = document.querySelector( 'script#wp-emoji-settings' );
if ( ! ( script instanceof HTMLScriptElement ) ) { throw new Error(...); }
const settings = JSON.parse( script.text );
```

`document.getElementById()` returns the first element in the DOM with a matching `id` **regardless
of tag name** — the textbook DOM-clobbering primitive: if attacker-controlled markup (supplied via
Stage 1's reflected XSS, which — per the article's summary — first achieves limited HTML injection
before this stage escalates it) can place *any* element bearing `id="wp-emoji-settings"` earlier in
the DOM than, or in place of, the legitimate `<script>` tag, `getElementById` can return the
attacker's element instead. Reading `.textContent` off a clobbered element and `JSON.parse()`-ing it
lets the attacker control `window._wpemojiSettings`, from which downstream emoji-loading code
derives a CDN URL it uses to inject a real `<script src="...">` tag — turning a constrained HTML
injection into a fully attacker-controlled script load in the page's own origin. Fix: a
tag-qualified `querySelector('script#wp-emoji-settings')` plus a runtime `instanceof
HTMLScriptElement` check, neither of which fall prey to clobbering the way bare `getElementById` +
any-element access does.

**Stages 2/4/5** (JS interaction / REST JSONP execution via the Same-Origin-Method-Execution
technique / forcing Application Password approval) are the weaponization phase once genuine script
execution is achieved in the wp-login/wp-admin origin during a victim admin's authenticated
session — not separate WordPress *bugs* so much as abuse of the (functioning-as-designed)
Application Passwords approval flow (`wp-admin/authorize-application.php`) once the attacker has
arbitrary JS execution to drive it. Confirmed the one core-side artifact of this stage visible in
`wp-login.php` — the `authorize-application.php` redirect messaging block (`str_contains(
$_GET['redirect_to'], 'wp-admin/authorize-application.php' )`) — already correctly `esc_html()`s the
`app_name` query parameter it displays; this is legitimate, pre-existing, correctly-escaped core
functionality that the exploit chain *drives via* automated script interaction once it has script
execution, not a fresh bug in its own right.

## Sibling check: DOM clobbering elsewhere in first-party WP core JS

Searched every non-vendor, non-minified JS file under `src/js/_enqueues/` for the
`getElementById`-reads-config pattern that made the emoji-settings bug possible (a fixed-string ID
lookup whose result is read as trusted data — `.textContent`/`.text`/`.value` — and JSON-parsed or
otherwise treated as authoritative settings). Zero matches: every other `getElementById()` call in
first-party core JS is ordinary UI-element manipulation (buttons, containers, form fields), not a
config-reading pattern. The DOM-clobbering shape was unique to the emoji loader; not reproduced
elsewhere in bundled core JS.

## Sibling check: the unescaped-username sink, checked for a missed spot

Grepped `wp-login.php` and `wp-includes/user.php` for every remaining `$username`/`$user_login` use
in a message/output context. Found one more `sprintf()` use (`wp-includes/user.php:3384`, inside
`retrieve_password()`'s reset-password email body: `sprintf( __( 'Username: %s' ), $user_login )`)
— traced it and ruled it out: by this point `$user_login` has been reassigned from the actual DB
record (`$user_login = $user_data->user_login;`), not the raw request value, the message is a
plain-text (not HTML) email body sent to the account's own registered address, and it's the account
owner's own real username being echoed back to them, not attacker-injectable text. Every
`value="<?php echo ... $user_login"` form-repopulation site in `wp-login.php` (lines 894, 1164,
1517) was already correctly `esc_attr()`-wrapped pre-fix. No missed sibling.

## A genuinely fresh thread: `validate_file()`'s documented absolute-POSIX-path gap (fixed 2026-08-16, ~2 weeks old)

Widened the search to the most recent trunk commits (through 2026-08-28, i.e. up to "today") for
anything security-flavored newer than the 7.0.3 bundle, since a fix this recent is as close to
"still fresh" as this method can get. Found `1ae6d6965e`, "Filesystem API: Reject UNC and device
paths in `validate_file()`." (merged 2026-08-16, Trac #51368) — a hardening fix to `validate_file()`,
core's central path-traversal-defense primitive, used by roughly 20 call sites across
`wp-admin/`/`wp-includes/` (theme/plugin file editor, template hierarchy resolution, plugin
activation, block template-part rendering, the REST plugins controller, and more).

The fix itself closes a narrow platform-specific gap (Windows UNC/device paths weren't recognized as
"absolute Windows path"). But its commit message states something structurally more interesting and
explicitly documents an intentional, permanent limitation:

> Absolute POSIX paths such as `/etc/passwd` are *not* rejected, and never have been. Callers that
> must reject them are responsible for their own check. The convention in core is to concatenate the
> validated value onto a trusted base directory and then confirm the result exists, rather than to
> treat this function as an absolute-path guard.

That is a real, load-bearing trust-boundary contract: `validate_file() === 0` only guarantees "no
`../` traversal, no Windows-absolute-path prefix" — it does **not** guarantee "not an absolute path"
on POSIX, by design. A caller that treats a `0` return as sufficient on its own, without also
concatenating the value onto a trusted directory before touching the filesystem, would have a real
absolute-path-traversal bug (attacker-controlled data reaching `/etc/passwd`, or worse, an arbitrary
writable/includable absolute path) — this is exactly the kind of "documented gap, now go find the
caller that doesn't know about it" lead that's worth chasing hard, and structurally similar in spirit
to the wp2shell/XSS2Shell pattern of "the fix closed one door; check whether every caller actually
needed that door closed at all, or was relying on a guarantee the function never made."

**Audited every meaningful `validate_file()` call site for this specific misuse pattern**:

- `get_page_template()` / `get_single_template()` (`wp-includes/template.php`): the `validate_file()`-
  passed candidate feeds into `locate_template()`, which does
  `file_exists( $wp_stylesheet_path . '/' . $template_name )` — string concatenation onto a trusted,
  known theme directory, not a path-join that would let a leading `/` reset to filesystem root (PHP
  string concatenation isn't `path_join()`; `"/theme/dir" . "/" . "/etc/passwd"` collapses to
  `/theme/dir/etc/passwd` on POSIX, not `/etc/passwd`). Combined with `validate_file()`'s own
  `../`-traversal rejection (return code `1`, unaffected by this fix), this closes both the
  absolute-path and traversal angles. Safe.
- `render_block_core_template_part()` (`wp-includes/blocks/template-part.php`), reachable via a
  Gutenberg `core/template-part` block's `slug` attribute (author-level content, not admin-only):
  feeds into `_get_block_template_file()`, which builds `$theme_dir . '/' . $template_base_paths[...]
  . '/' . $slug . '.html'` — concatenation onto *two* nested trusted prefixes plus a fixed `.html`
  suffix, then `file_exists()`. Same safe shape, with the added defense that even a full bypass here
  would only reach a filesystem **read** of an `.html`-suffixed path (via `file_get_contents`-style
  loading, never `include()`), not code execution.
- `wp_edit_theme_plugin_file()` (`wp-admin/includes/file.php`), the actual theme/plugin file editor —
  the highest-value target for RCE via arbitrary write: builds `$real_file = WP_PLUGIN_DIR . '/' .
  $file` / `$theme->get_stylesheet_directory() . '/' . $file`, but *additionally* re-validates via
  `validate_file( $file, $allowed_files )` against an explicit allowlist built from
  `get_plugin_files( $plugin )` / `$theme->get_files(...)` — i.e. code `3` (not-in-allowed-list), a
  second, independent containment mechanism on top of the trusted-prefix concatenation. Also gated
  behind `edit_plugins`/`edit_themes` regardless, which is already file-write-equivalent capability.
  Safe, and even a hypothetical bypass wouldn't be a privilege escalation for this caller specifically.
- `WP_REST_Plugins_Controller::validate_plugin_param()`
  (`wp-includes/rest-api/endpoints/class-wp-rest-plugins-controller.php`): runs the value through
  `plugin_basename()` *and* a dedicated regex (`self::PATTERN`) before `validate_file()` ever sees
  it — `plugin_basename()` strips any prefix matching the real plugin directory constants, which
  neutralizes an absolute-path value long before the `validate_file()` check even runs. Safe.

**Conclusion: no misuse found.** Every caller that matters follows the documented convention the
`validate_file()` commit message describes (concatenate onto a trusted base, or apply an independent
allowlist) rather than trusting the return value as a self-sufficient absolute-path guard. This is a
genuinely fresh, still-recent (12 days old at the time of this check) core hardening commit, and it
was worth the depth given how directly its own commit message names the exact caller mistake to look
for — but WordPress core's callers, on this pass, don't make that mistake anywhere reachable.

## Honest assessment after three structured sibling hunts

This is now the third distinct, recent, real-CVE-informed sibling hunt this audit has run against
WordPress Core (wp2shell's two bug shapes in round 9; XSS2Shell's two bug shapes plus the
`validate_file()` trust-boundary gap in this round) — six named bug shapes in total, each checked
against every structurally-similar location the method could find. All six came back negative. That
consistency is itself the most honest signal available from this method: WordPress Core's own
recent, real vulnerabilities were each narrow, one-off mistakes (a missing array push in one
error-handling branch; a sanitizer gated behind the wrong conditional in one query-var handler; one
unescaped `sprintf()` call in one login error message; one `getElementById` without a tag check in
one settings loader) rather than instances of a systemically-repeated pattern — which is exactly what
you'd expect from a codebase under continuous, serious security review, and exactly why re-applying
the same "find the pattern, grep for it elsewhere" method a fourth time has correspondingly low
expected value.

No fresh RCE or XSS found in WordPress Core across rounds 9-10 despite genuinely deep, structured
effort informed by the two most recent real core RCE chains. The confirmed finding for this entire
audit remains round 6's Secure Custom Fields bidirectional-field broken access control.
