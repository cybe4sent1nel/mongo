# Round 11: CONFIRMED, fresh — unauthenticated PHP Fatal Error via REST API argument
# type confusion, found by fuzzing rather than pattern-matching a known CVE

> **STATUS CORRECTION (see README's "Scope correction #2"): this is a DoS/crash finding.
> The program's own exclusion list rules out "Brute force, DoS, memory exhaustion,
> phishing, text injection, or social engineering attacks" outright. This write-up
> classifies itself as a Denial of Service throughout — meaning it is Not Applicable /
> Informative, not a reportable finding, regardless of the technical detail below.
> Kept as-is for the historical record of what was actually verified; not being
> submitted, and not a confirmed in-scope bug.**

**This round switched method, per direct instruction, from manual code reading to actual
fuzzing against a live WordPress 7.1 install** (the same throwaway install used throughout this
audit), informed by the wp2shell/XSS2Shell case studies (rounds 9-10) but not a rediscovery of
either — this is a new bug, found by testing rather than reading.

**Bottom line up front, stated plainly: this is a real, fresh, unauthenticated, reproducible bug in
WordPress Core, confirmed by live HTTP testing with a negative control and traced to root cause in
the current `wordpress-develop` source. It is NOT remote code execution. It is an unauthenticated
Denial of Service via uncaught PHP exception (CWE-248 / CWE-20) — every confirmed instance crashes
the single request that triggers it (HTTP 500) before any data is read or written, with no code
execution, data disclosure, or persistence achieved.** Reporting it exactly as what it is, not
inflating it to match what was asked for.

## Method: type-confusion fuzzing of the REST API argument-validation pipeline

Built `scratchpad/rest_typeconfusion_fuzz.py`: enumerated all 144 routes from the live install's
`/?rest_route=/` index, and for every registered arg on every route+method, sent a type-confused
value — a JSON array where the schema declares `type: string` (and vice versa) — while diffing
`wp-content/debug.log` before/after each request for new PHP warnings/errors. 1,147
(route, method, arg, confusion) combinations tested in one pass. This is the differential/fuzzing
approach suggested as the next step after rounds 9-10's manual sibling hunts hit diminishing
returns — same case-study-informed hypothesis (wp2shell's `author__not_in` was exactly a
scalar-vs-array type-confusion bug), applied by testing instead of reading.

## Root cause

`WP_REST_Request::has_valid_params()` (`wp-includes/rest-api/class-wp-rest-request.php:942-958`)
and `::sanitize_params()` (same file, `:851-868`) both invoke a route's registered
`validate_callback` / `sanitize_callback` **directly** on the raw request parameter:

```php
$valid_check = call_user_func( $arg['validate_callback'], $param, $this, $key );
// and, separately:
$sanitized_value = call_user_func( $param_args['sanitize_callback'], $value, $this, $key );
```

Neither performs the arg's declared JSON-Schema `type` check first. That automatic type
enforcement only happens via `rest_validate_request_arg()` — the **default** validate_callback WP
core substitutes in *when no custom one is registered*. Once a route overrides `validate_callback`
or `sanitize_callback` with its own function (as most non-trivial REST args do, to run real
business-logic validation), the schema's `'type' => 'string'` declaration becomes documentation
only — nothing in the framework enforces it before that custom function runs. If the custom
function doesn't itself guard against the value being the wrong PHP type (many don't, since much of
this code predates PHP 8's stricter internal-function typing), a JSON array submitted where a
string is expected reaches string-only PHP operations and throws an uncaught `TypeError`.

Critically, **both `has_valid_params()` and `sanitize_params()` run inside `WP_REST_Server::dispatch()`
before `respond_to_request()`** (`class-wp-rest-server.php:1114-1126`), which is where a route's
`permission_callback` is actually checked and the controller method is invoked. So this fires for
*any* request that reaches argument validation — regardless of whether the requester could ever
pass that route's own authorization check. Confirmed via the crash stack traces themselves (below):
no `current_user_can()` frame appears anywhere in either trace.

## Confirmed instance 1: `WP_REST_Posts_Controller::check_template()` — array `template` crashes 13 route patterns

`wp-includes/rest-api/endpoints/class-wp-rest-posts-controller.php:2753-2760` registers `template`
with `'type' => 'string'` but overrides `validate_callback` with `check_template`, which does:

```php
// class-wp-rest-posts-controller.php:1663
if ( isset( $allowed_templates[ $template ] ) ) {
```

`isset()` on an array offset requires the offset to be a scalar (int/string); PHP 8 throws
`TypeError: Cannot access offset of type array in isset or empty` if `$template` is itself an
array — which it is, since nothing checked `is_string( $template )` first.

Affects every route this controller (or its `_Autosaves`/`_Revisions` subclasses which inherit the
same arg registration) serves: `/wp/v2/posts`, `/wp/v2/pages`, `/wp/v2/media`, `/wp/v2/blocks`,
`/wp/v2/navigation`, and each of their `/(?P<id>[\d]+)` and `/(?P<id>[\d]+)/autosaves` variants —
13 distinct route patterns confirmed via the live install's own `/?rest_route=/` schema index.

## Confirmed instance 2: `esc_url()` / `sanitize_url()` — array `url`-type args crash at least 4 more routes

`wp-includes/rest-api/endpoints/class-wp-rest-menu-items-controller.php:877` registers `url` with
`sanitize_callback => 'sanitize_url'`, which is a thin wrapper around `esc_url()`
(`wp-includes/formatting.php:4551`):

```php
// formatting.php:4558
$url = str_replace( ' ', '%20', ltrim( $url ) );
```

`ltrim()` is a PHP internal function with a strict `string` parameter type since PHP 8.0; passing
an array throws `TypeError: ltrim(): Argument #1 ($string) must be of type string, array given`.
`esc_url()`/`sanitize_url()` are among the most-used functions in all of WordPress (core, every
theme, every plugin) and were written under PHP 7-and-earlier's looser coercion rules (an array
passed to `ltrim()` used to just emit a notice and coerce to `"Array"`, not throw) — this is a
PHP-8-strictness regression in decades-old code, not a new logic bug, but it's live and reachable
today regardless. Confirmed reachable via `/wp/v2/menu-items` (collection, item, and item
`/autosaves`), and the same `url`-typed, `sanitize_url`-sanitized arg shape is registered on
`/wp/v2/media`'s `POST` route as well (not independently re-verified live this round, but the same
schema/sanitize_callback pairing, so almost certainly the same crash).

## Empirical confirmation (real HTTP, unauthenticated, with negative control)

```
POST /?rest_route=/wp/v2/posts   Content-Type: application/json   Body: {"template":["x"]}
→ HTTP 500  {"code":"internal_server_error", ... "data":{"status":500}}

POST /?rest_route=/wp/v2/menu-items   Content-Type: application/json   Body: {"url":["x"]}
→ HTTP 500  {"code":"internal_server_error", ... "data":{"status":500}}

Negative control — same route, a normal (non-array) invalid string instead:
POST /?rest_route=/wp/v2/posts   Body: {"template":"not-a-real-template"}
→ HTTP 400  {"code":"rest_invalid_param", "message":"Invalid parameter(s): template", ...}
```

No cookies, no `Authorization` header, no nonce — genuinely unauthenticated requests. The negative
control shows the *intended* behavior (a clean 400 rejection) for ordinary invalid input, making the
500-vs-400 contrast the actual defect, not an artifact of the test harness. `wp-content/debug.log`
captured both full stack traces (see round file for complete traces); both terminate inside
argument-validation, several frames before any permission or capability check, confirmed by the
complete absence of `current_user_can()`/`WP_REST_Server::respond_to_request()` frames in either
trace.

Root cause reconfirmed against the current `wordpress-develop` trunk clone (not just the live
install): identical code at identical line numbers
(`class-wp-rest-posts-controller.php:1663`, `formatting.php:4558`), same declared WP version
(`7.1`/`7.1-src`) — this is present in the actual current release, not a stale/patched-elsewhere
issue.

## Checked for escalation beyond a crash — none found

Deliberately looked for the more valuable variant of this bug class: a type confusion that
*doesn't* crash but instead silently misbehaves in a way that weakens a check (a functional bypass,
not just a fatal error). One promising-looking lead: `WP_REST_Comments_Controller::
check_comment_author_email()` does `$email = (string) $value;` (an explicit cast, not a
type-hinted function call) — an array here produces a `Warning: Array to string conversion` and the
literal string `"Array"` rather than a crash, and execution *continues*. Traced it through: the
resulting `"Array"` string still gets passed to `rest_validate_request_arg()` for email-format
validation immediately afterward, which correctly rejects it (not a valid email) — HTTP 400, no
bypass. No other non-fatal type-confusion warning found across the full fuzz sweep that resulted in
a 200/201 (i.e., a successful write) rather than a 400/500. The two confirmed instances above are
both crash-only.

Also considered: does anything about *how* the request fails leak information, corrupt state, or
have a side effect beyond the crash itself? No — both crashes occur during argument validation,
strictly before `sanitize_params()`'s data is used for any read or write, so no post/menu-item/
setting is created, modified, or exposed as a result of triggering either crash.

## Honest severity assessment

CWE-248 (Uncaught Exception) / CWE-20 (Improper Input Validation) → unauthenticated, single-request
Denial of Service. Each triggering request crashes only the PHP worker handling that one request
(returns a 500 and the standard WP "critical error" page); it does not crash the whole server
process, corrupt data, or persist across requests. Rough CVSS 3.1 reasoning:
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` ≈ 5.3 (Medium) — network-reachable, low complexity (single
crafted JSON body), no privileges or user interaction required, no confidentiality/integrity
impact, low/limited availability impact (this request fails; the site as a whole keeps serving
other requests normally). A program that scores availability impact by "can this be used to degrade
the site at volume with trivial attacker cost" might reasonably score it a bit higher given the
breadth (13+ route patterns, zero-cost single request, no rate-limit-relevant state); a program that
requires demonstrated sustained resource exhaustion beyond a single request's normal cost might
score it lower. Reporting it as a genuine Medium-severity, not inflating it, and not diminishing it
either.

## What this is not

This is not RCE, not SQLi, not an authentication or authorization bypass, and does not itself
enable any of those — it is a clean, isolated crash-on-malformed-input bug. Recording that plainly
because the standing instruction for this round was explicitly to keep hunting for RCE/Critical
specifically; this is what the fuzzing method actually surfaced, reported honestly rather than
reframed to fit the ask.

## Scope note

Reachable via WordPress Core's own REST API (`wp-includes/rest-api/`) — no plugin involved. In
scope for the WordPress.org HackerOne program's Core coverage, separate from the four-plugin scope
the earlier rounds of this audit focused on.
