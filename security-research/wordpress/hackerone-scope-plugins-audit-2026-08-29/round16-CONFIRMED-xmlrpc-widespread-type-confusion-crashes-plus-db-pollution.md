# Round 16: CONFIRMED, fresh, currently-unpatched — type-confusion crashes across
# essentially the entire authenticated XML-RPC content-editing surface, plus a
# confirmed database-pollution side effect via `wp.newPost`

**This is a real, fresh, empirically-confirmed bug in WordPress Core's current
`wordpress-develop` trunk, live-tested via HTTP against the same throwaway WP install
used throughout this audit.** Same underlying bug *class* as round 11 (CWE-248 Uncaught
Exception / CWE-20 Improper Input Validation — an authenticated Denial of Service), but
found in a completely different subsystem (XML-RPC, not REST), at dramatically larger
breadth (8 distinct methods, ~15 distinct crash sites), and with one confirmed
consequence beyond round 11's: **a crashing `wp.newPost` call permanently litters the
`wp_posts` table with an orphaned "Auto Draft" row on every single attempt.** As with
round 11: **this is not RCE.** No code execution, no data disclosure, no auth bypass —
reporting it as exactly what it is.

## How this was found: fuzzing informed by two fixes the WP core team shipped this month

Reading `wordpress-develop`'s own recent commit history (the same technique round 15
used successfully on the `secure-custom-fields` plugin, applied here to WP core itself)
turned up two very recent, security-titled commits to `class-wp-xmlrpc-server.php`:

- `67c01d5705` (2026-08-28, **yesterday** relative to this audit) — "Require the
  `$fields` argument to be an array," fixing ten `wp.get*` methods that crashed with an
  uncaught `TypeError` when a client sent a non-array `$fields` argument.
- `1ef9d70aea` (2026-08-04) — "Validate the attachment data in `mw_newMediaObject()`,"
  fixing an *unauthenticated* crash (struct read before login) in the media-upload
  method, with the fix explicitly noting a struct member reaching `fwrite()` via
  `wp_upload_bits()` and throwing a `TypeError`.

Both were read in full and independently confirmed complete within their own stated
scope (checked every other caller of the same helper functions/sanitizers — no sibling
gap inside what each commit set out to fix). That in turn showed the WP core team is
actively, currently sweeping this exact bug class through XML-RPC. Given two instances
surfaced and got fixed in the last month, the reasonable next step was to check whether
more instances exist that haven't been found yet — this time by dynamic fuzzing (the
same method that produced round 11's finding) rather than manual reading, since the
surface (~89 methods, ~7,500 lines) is too large to review by hand exhaustively.

## Method

Built `xmlrpc_typeconfusion_fuzz.py`: for every XML-RPC method that accepts a
content-struct-shaped argument (`wp.newPost`, `wp.editPost`, `wp.editProfile`,
`wp.setOptions`, `wp.newTerm`, `wp.editTerm`, `wp.newComment`, `wp.editComment`,
`wp.newCategory`, `wp.suggestCategories`, `metaWeblog.newPost`, `metaWeblog.editPost`,
`blogger.newPost`, `blogger.editPost`, `mt.setPostCategories`, `wp.uploadFile`), sent
(a) the whole struct replaced with a non-struct scalar/array, and (b) each individual
struct member replaced with a nested array/struct where a scalar was expected —
authenticated with a real admin account's login/password (XML-RPC uses ordinary
username+password, not application passwords), diffing `wp-content/debug.log`
before/after each of 174 (method, mutation) combinations for a new uncaught error.

## Results: 15 distinct fatal-crash sites across 8 methods

All independently reproduced with a direct, minimal follow-up request (not just
observed once during the fuzz sweep) and traced to root cause in the current
`wordpress-develop` source:

| Method | Crashing member | Root cause |
|---|---|---|
| `wp.newPost` | `post_title` | `trim()` on an array, `class-wp-xmlrpc-server.php` (`_insert_post()`) |
| `wp.newPost` | `post_content` | `str_contains()` on an array (a content filter hooked to `content_save_pre`) |
| `wp.newPost` | `post_date` | `date_create()` on an array (`_convert_date()`) |
| `wp.newPost` | `custom_fields` | array-offset-of-array in `set_custom_fields()`, `class-wp-xmlrpc-server.php:461` |
| `wp.newPost` | whole struct (string/int) | `Cannot unset string offsets` / `Cannot unset offset in a non-array variable` (`unset( $content_struct['ID'] )`) |
| `wp.editPost` | whole struct (string/int) | `array_merge(): Argument #2 must be of type array` |
| `wp.editPost` | `post_title`, `post_content`, `custom_fields` | same three sinks as `wp.newPost` (shared `_insert_post()`) |
| `wp.editProfile` | `bio` | `stripslashes()` on an array |
| `wp.newTerm` | whole struct (string) | `Cannot access offset of type string on string` |
| `wp.newTerm` | `name` | `trim()` on an array |
| `wp.newComment` | whole struct (string) | `Cannot access offset of type string on string` |
| `wp.newComment` | `content` | `trim()` on an array, `class-wp-xmlrpc-server.php:3983` |
| `wp.editComment` | `content` | `str_contains()` on an array, `formatting.php:2548` (`convert_invalid_entities` filter) |
| `wp.newCategory` | whole struct (string/int) | `Cannot access offset of type string on string` / `Cannot use a scalar value as an array` |
| `wp.newCategory` | `name` | `trim()` on an array, `wp-admin/includes/taxonomy.php:132` (`wp_insert_category()`) |
| `wp.newCategory` | `slug` | `preg_match()` on an array, `formatting.php:1612` (`remove_accents()`, called from `sanitize_title()`) |
| `metaWeblog.newPost` | `title` | `trim()` on an array (a `title_save_pre` filter callback) |
| `metaWeblog.newPost` | `description` | `str_contains()` on an array (`attach_uploads()`) |
| `metaWeblog.newPost` | `wp_slug` | `strip_tags()` on an array (`sanitize_title_with_dashes()`) |
| `metaWeblog.newPost` | `custom_fields` | same as `wp.newPost` |

Every one of these is a **different sink function** (`trim()`, `str_contains()`,
`date_create()`, `array_merge()`, `stripslashes()`, `preg_match()`, `strip_tags()`, plus
two `Cannot access/unset offset` engine errors) reachable from a **different struct
member on a different public method** — this is not one bug with many call sites, it's
the same *systemic gap* (no type validation on optional struct members before they
reach PHP 8's strict-typed internal functions) recurring independently across the
XML-RPC content-editing API, exactly mirroring the shape of the two commits that
prompted this search, just not yet caught by either of them.

## Empirical confirmation, with a negative control

```
POST /xmlrpc.php   wp.newTerm(0, 'admin', '<admin password>', {name: ['x'], taxonomy: 'category'})
→ HTTP 500, IXR fault, debug.log: "Uncaught TypeError: trim(): Argument #1 ($string)
  must be of type string, array given ... class-wp-xmlrpc-server.php:2128"

Negative control — same call, an ordinary (non-array) string name instead:
POST /xmlrpc.php   wp.newTerm(0, 'admin', '<admin password>', {name: 'ordinary-term', taxonomy: 'category'})
→ HTTP 200, a normal successful <struct> response, term created correctly.
```

All requests used real, valid admin credentials obtained via the standard XML-RPC
username/password login (`$this->login()`) — these are **authenticated** crashes, same
tier as round 11, not unauthenticated (unlike the already-fixed `mw_newMediaObject`
instance, every method checked here calls `login()` before touching the struct).
Capability requirements are consistent with each method's own ordinary requirements —
for `wp.newPost` specifically, only `create_posts`/`edit_posts` on the target post type
is needed (Contributor role and above by default), not an elevated capability.

## New consequence beyond a bare crash: confirmed database pollution via `wp.newPost`

Traced `wp_newPost()` → `_insert_post()` in full and found something round 11's REST API
crashes didn't have: at `class-wp-xmlrpc-server.php:1552`,
`$post_data['ID'] = get_default_post_to_edit( $post_data['post_type'], true )->ID;` runs
**unconditionally** for every new-post request, immediately after the capability check
and well *before* the later `post_title`/`post_content`/`custom_fields` processing where
the actual crash occurs. `get_default_post_to_edit( $post_type, true )` — the `true`
being `$create_in_db` — **inserts a real `post_status = 'auto-draft'` row into
`wp_posts` as a side effect**, and returns its ID. Since the crash happens *after* this
insert, the auto-draft row is never cleaned up: the overall XML-RPC call still fails
(HTTP 500 / IXR fault), but the junk row persists permanently.

Verified this is exact and deterministic, not incidental: recorded
`wp_posts` auto-draft row count immediately before and after three consecutive crashing
`wp.newPost` calls (malformed `post_title`) with nothing else running —

```
Auto-draft count before: 26
[3x crashing wp.newPost requests, each returning HTTP 500]
Auto-draft count after:  29
```

— exactly 3 new rows for exactly 3 crashing requests. This gives the bug an angle round
11 didn't have: it's not just "the request fails harmlessly," it's "the request fails
*and* leaves permanent junk behind," repeatable without limit by any user holding
ordinary post-creation rights (Contributor and above by default) — a storage/ID-space
pollution primitive, not merely a transient DoS.

Checked `wp.editPost` for the same class of side effect (it shares `_insert_post()`)
and confirmed it does **not** have one: `get_default_post_to_edit()` is only called
`if ( ! isset( $post_data['ID'] ) )`, which is false for an edit (the target post's ID
is always set), so no auto-draft creation happens on that path. Also directly verified
no partial write occurs on the *target* post when an edit crashes — recorded a real
post's `post_title`/`post_modified` immediately before and after a crashing
`wp.editPost` call targeting it, and both were byte-identical afterward: the crash
happens while still assembling `$post_data`, strictly before `wp_update_post()` is ever
called, so an edit-path crash is a clean no-op on existing content, unlike the new-post
path's confirmed pollution.

## Checked for escalation beyond a crash — two non-fatal near-misses, neither a bypass

- `wp.newCategory`/`wp.newTerm` with an array `description` member: produces a
  non-fatal `Array to string conversion` warning (`taxonomy.php:2505`) rather than a
  crash, and the term/category **is** created — but with its description silently
  coerced to the literal string `"Array"`, not the attacker's actual array content, and
  not any other object's data. A content-integrity nuisance (same shape as round 11's
  `check_comment_author_email()` near-miss), not a bypass of anything.
- `metaWeblog.newPost` with an array `wp_password` member: produces a `wpdb::prepare`
  usage notice ("Unsupported value type (array)") and the request still succeeds
  (HTTP 200) — traced this to `$wpdb->prepare()` refusing to interpolate an array
  placeholder value, which resolves to an empty/unset password being stored rather than
  the attacker's array or any escape/injection artifact. No SQL injection, no bypass.

## Honest severity assessment

Same classification as round 11: CWE-248 (Uncaught Exception) / CWE-20 (Improper Input
Validation) → **authenticated** Denial of Service (any user with ordinary content-editing
rights — Contributor and above for `wp.newPost`, similarly modest requirements for the
others), each crash taking down only the single PHP worker handling that request. This
round's severity sits at least at round 11's tier and arguably somewhat above it on
pure breadth-and-impact grounds: 8 distinct methods rather than 1 controller's shared
validator, ~15 independently-reachable crash sites, and a *confirmed*, deterministic,
unlimited storage-pollution side effect for the most commonly used of them
(`wp.newPost`) that round 11's REST findings did not have. Rough CVSS 3.1 reasoning:
`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L` — network-reachable, low complexity, **low**
privileges required (this round's crashes need valid low-tier credentials, unlike round
11's unauthenticated ones — the one respect in which this round rates lower), no
confidentiality impact, a small integrity impact from the confirmed junk-row pollution,
low availability impact per request. A program might reasonably weigh the breadth
(8 methods) and the confirmed persistent side effect upward, or the authentication
requirement downward, relative to round 11.

## What this is not

Not RCE, not SQLi, not an authentication bypass, not privilege escalation. Every crash
occurs deep inside a data-sanitization/filter call, before any privileged operation the
crash could otherwise short-circuit past. The two non-fatal near-misses were traced to
confirmed-safe outcomes, not bypasses.

## Relationship to the two upstream fixes that motivated this search

Recorded for completeness, not as something being claimed as prior art: both
`67c01d5705` and `1ef9d70aea` carry public Trac tickets (#65983, #65600/#65611) and
GitHub PRs credited to other researchers (`josephscott`, `westonruter`, `mukesh27`) —
they are WordPress's own already-fixed, already-disclosed work, read here purely as
methodology context (what bug shape is currently under active scrutiny, and where it's
already been found), not as this round's contribution. This round's contribution is the
~15 **not-yet-fixed** sibling crash sites found by extending that same scrutiny with
fuzzing rather than manual reading, plus the newly-identified `wp.newPost`
database-pollution consequence, which neither upstream commit's description mentions.

## Scope note

Reachable via WordPress Core's own XML-RPC server (`wp-includes/class-wp-xmlrpc-server.php`)
— no plugin involved, same as round 11's REST API finding.
