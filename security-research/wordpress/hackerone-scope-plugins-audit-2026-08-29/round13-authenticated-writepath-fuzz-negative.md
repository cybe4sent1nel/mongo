# Round 13: authenticated write-path fuzzing (Author + Administrator) —
# negative result for privilege-escalation/validation-bypass; confirms round 11's
# crash bugs have zero write-path side effects even when authenticated

**Trigger for this round**: direct instruction to extend round 11's pre-auth type-
confusion fuzzer past `permission_callback` into real write/save logic, specifically
hunting for the more valuable variant of that bug class — a type confusion that doesn't
just crash but *bypasses* a check (privilege escalation, unauthorized field write), the
open question round 11 flagged but hadn't yet tested with real authentication.

**Bottom line: no validation bypass, no privilege escalation, no new bug.** 3,072
(route, method, role, arg, confusion) combinations tested against every write-method
(POST/PUT/PATCH/DELETE) REST route, authenticated as both a low-privilege Author
(`author1`) and an Administrator (`admin`) on the same throwaway WP 7.1 install used
throughout this audit. 43 flagged as "interesting" by the fuzzer's heuristics; all 43
were individually triaged and none represents a new vulnerability. This round's genuine
positive contribution is proving — not just arguing — that round 11's two crash bugs
have no write-path impact under real authentication either.

## Method

Built `rest_auth_writepath_fuzz.py`. Two changes from round 11's pre-auth fuzzer:

1. **Real authentication.** Application Passwords are unavailable on this install
   (`wp_is_application_passwords_available()` returns `false` — WP requires HTTPS for
   them, and this is a plain-HTTP local dev server), so used real cookie + REST-nonce
   auth instead: logged in both test accounts via an actual `wp-login.php` POST to get
   session cookies, then scraped each account's live `X-WP-Nonce` value from an
   authenticated admin-side page's localized `wpApiSettings` (rather than trying to
   precompute a nonce out-of-band, which failed — WP's nonce hash incorporates the
   session token created at login time, so a nonce computed in a separate PHP process
   without that exact token doesn't validate). Confirmed working end-to-end against
   `/wp/v2/users/me` and a real post creation before running the sweep.
2. **DB-state diffing, not just log diffing.** Every request snapshots `wp_posts`
   (ID/author/status/type) and `wp_usermeta` role capabilities before and after, in
   addition to round 11's `debug.log` diff — so a type-confused value that gets silently
   *accepted and written* (rather than crashing or being rejected) would show up even
   with no log output.

Confused-value shapes sent per declared arg type: scalar for `array`/`object`-typed args,
array for `integer`/`number`-typed args (including an array containing a SQLi-shaped
string, in case an array slipped past a scalar cast reaches raw SQL somewhere), and array
for any other scalar-typed arg — run against both roles, on every write-method endpoint.

## Triage of all 43 flagged results

They fall into four groups, all accounted for:

**1. `template` (13 route patterns) and `url`/`sanitize_url` (`menu-items`) — round 11's
already-reported crash bugs, reproducing identically under real authentication.** Same
stack traces, same line numbers (`class-wp-rest-posts-controller.php:1663`,
`formatting.php:4558`), for *both* the Author and the Administrator session. This is the
useful new data point: **`db_changed` was `false` for every single one of these**, for
both roles — confirming empirically, not just by code-reading as round 11 did, that the
crash happens strictly during argument validation, before any post/page/media/block/
navigation object is created, updated, or partially written, regardless of whether the
requester is authenticated or what role they hold. No escalation, no partial-write
corruption, under real auth either.

**2. `title` / `content` / `excerpt` "scalar-for-object" and "array-for-object" — false
positives from the fuzzer's own type labeling, not a bug.** These fields are declared
`type: object` in the REST schema but their registered `sanitize_callback` deliberately
accepts *either* a plain string *or* an object with a `raw` key — sending a bare scalar
(e.g. `{"title": "1"}`) is normal, documented, everyday REST API usage (it's literally how
every simple REST client sets a post title), not a type confusion at all. Verified
directly against the database: post 24's `wp_posts.post_title` is cleanly `1`, no
malformed data, no injection artifact. My fuzzer over-flagged these because it labels
purely off the declared JSON-Schema `type`, without knowing individual endpoints'
`arg_options` intentionally widen accepted input. Correctly excluding this class going
forward would need per-arg schema awareness the fuzzer doesn't have; noting it here rather
than re-running to filter it out, since manual triage was cheap once the pattern was clear
(all ~20 instances are the same shape across posts/pages/blocks/navigation).

**3. `meta` "array-for-object" (`{"meta": [1, 2]}`) accepted with 201, `db_changed=true`.**
The one result that looked most like it could be new. Checked directly: the created page
(ID 36) has **zero rows** in `wp_postmeta` — the malformed meta value was silently
discarded, and `db_changed=true` fired only because *creating the page itself* changes
`wp_posts` (true of every successful POST regardless of the `meta` payload — not evidence
the meta write did anything). No data corruption, no silently-stored malformed value, no
bypass of a registered meta field's type/sanitize/auth callback — WordPress's meta-schema
validation for the REST API rejects the malformed shape internally and just doesn't apply
it, without surfacing an error. Same behavior for both roles.

**4. `/wp/v2/comments POST author_email array-for-scalar` → 400.** The exact near-miss
already documented in round 11's "Checked for escalation beyond a crash" section
(`check_comment_author_email()`'s `(string) $value` cast producing `"Array"`, then
correctly rejected by email-format validation). Reproduces identically authenticated;
still correctly rejected, still no bypass.

## What this round specifically ruled out

- **No horizontal or vertical privilege escalation**: the low-privilege Author account
  never got a type-confused request accepted where an ordinary Author-role request would
  have been rejected — every 2xx result was accepted *because it was legitimate input in
  a slightly unusual shape* (group 2 above), not because a check was bypassed. `wp_posts`
  was checked after every write attempt; no post was ever created with an unexpected
  `post_author` or elevated `post_status` (e.g. `publish` from the Author account, who
  lacks `publish_posts` for others' content) as a side effect of a type-confused field.
- **No write-path impact from either round-11 crash bug.** This was the open question
  round 11 left explicit (its "Checked for escalation" section was necessarily pre-auth
  only) — now closed empirically: authenticating as Author or Admin changes nothing about
  where the crash occurs (argument validation, before controller dispatch) or its
  consequences (none beyond the single request's own 500).
- **No SQLi reached via an array where an integer/number arg was expected** — the
  SQLi-shaped string-in-array payloads produced no new log output and no unexpected DB
  state in any of the 3,072 combinations.

## Scope / cleanup note

Test objects created during this run (pages/posts/blocks/navigation items with IDs
24-46, titles like "1", "authfuzz smoke test") were left in place on the throwaway local
install — harmless test data on a non-production instance used solely for this audit, not
cleaned up because doing so has no security relevance and the install is discarded with
the container.

## What this is not

Not RCE, not a privilege-escalation bug, not a validation bypass. A genuine, thoroughly-
executed negative result that also strengthens round 11's finding by empirically closing
its one open question (write-path impact under real auth) rather than leaving it as an
inference from code reading alone.

## Standing findings for this audit, unchanged by this round

- Round 6: **CONFIRMED** — SCF bidirectional-field broken access control (reported).
- Round 11: **CONFIRMED** — WP Core REST API unauthenticated argument-validation crash /
  DoS (CWE-248/CWE-20), Medium severity. This round confirms, with real authenticated
  testing, that it has no write-path or privilege-escalation impact under any tested role.
- Round 12: negative — no fresh XSS/RCE/privesc sibling of the CVE-2019-16773 attribute-
  injection shape.
- Round 13 (this round): negative — no validation bypass or privilege escalation found via
  authenticated write-path type-confusion fuzzing, 3,072 combinations, two roles.
