# Matomo Tracker Proxy — security audit

**Target** `https://github.com/matomo-org/tracker-proxy` at `ecbc1a33f9e45cb6822b663782c65997d8e55c10` (2026‑08‑17, `master` tip)
**Backend used for validation** Matomo 5.13.0, PHP 8.4.19, MariaDB
**Date** 2026‑09‑03
**Method** live lab, not code reading. Proxy deployed at `http://127.0.0.1:8500` against a working Matomo at `http://127.0.0.1:8400` with a real write-scoped `token_auth`. Every claim below was executed against that lab; every negative result was executed too, not assumed.

---

## Summary

| # | Finding | Auth required | Verified | Assessment |
|---|---------|---------------|----------|------------|
| 1 | `matomo-proxy.php` endpoint allowlist bypass — parameter-precedence mismatch between the proxy and Matomo | none | live | **valid, Low–Medium** |
| A | Client-controlled IP headers are trusted unconditionally and authorised with the proxy's write token | none | live | out of scope by policy (analytics pollution) — reported as FYI only |
| B | Whole `Cookie` header of the tracked site is forwarded to Matomo by default | none | live | already addressed in code (`$COOKIE_ALLOWLIST`), documented default — hardening note only |
| C | Upstream redirects are followed cross-host on the `allow_url_fopen` backend | none | live | latent; **no exploitable chain exists in stock Matomo** — hardening note only |

Everything else audited came back clean. The negative results are in §5, because on this program they are the point: the token-lending logic in `proxy.php` — which is where a serious bug would live — is correct, and I could not break it.

---

## 1. Finding: `matomo-proxy.php` endpoint allowlist bypass

**Component** `matomo-proxy.php` (lines 15–41), interacting with `proxy.php`
**Authentication required** none (unauthenticated, remote)
**Class** CWE‑863 improper authorization / access-control bypass through parsing inconsistency (CWE‑436)

### What the control is supposed to do

`matomo-proxy.php` is the only entry point that proxies Matomo's `index.php`, and it deliberately restricts what may be reached:

```php
$SUPPORTED_METHODS = ['CoreAdminHome.optOut', 'CoreAdminHome.optOutJS'];
$VALID_FILES       = ['plugins/CoreAdminHome/javascripts/optOut.js'];
...
$hasSupportedMethod = !empty($module) && !empty($action)
                    && in_array("$module.$action", $SUPPORTED_METHODS, true);
if ($hasFileRequest) {
    if (!in_array($filerequest, $VALID_FILES, true)) { http_response_code(404); exit; }
} elseif (!$hasSupportedMethod) { http_response_code(404); exit; }
```

This is an intentional security control, added in commit `23ead76` / PR #100 ("Fixes entry condition in matomo proxy", 2026‑03‑30) and covered by dedicated tests (`test_indexphp_blocked_requests_are_not_proxied`, `test_indexphp_blocked_post_requests_are_not_proxied`, and the two `..._with_invalid_file_...` tests).

### The bug

The proxy and Matomo disagree about which of `$_GET` / `$_POST` supplies `module` and `action`.

*Proxy* — "GET value if it is **truthy**, otherwise the POST value":

```php
$module = isset($_GET['module']) ? $_GET['module'] : null;
if (empty($module)) { $module = isset($_POST['module']) ? $_POST['module'] : null; }
// identically for $action
```

*Matomo* — `Common::getRequestVar()` resolves against `$_GET + $_POST`, so the GET entry wins whenever the **key is present**, even with an empty value; an empty string then falls back to the parameter's *default* (`FrontController::DEFAULT_MODULE`, i.e. `CoreHome`), not to the POST value.

So an empty `module`/`action` in the query string is *skipped* by the proxy (`empty('')` is true, so it uses the POST value and validates `CoreAdminHome.optOut`) but is *honoured* by Matomo (which sees an empty module and dispatches its default). The pair the proxy validates is never the pair Matomo dispatches.

Note that `empty()` also treats the string `'0'` as empty, giving a second spelling of the same bypass.

### Reproduction

```bash
# blocked, as designed
curl -i 'https://tracked-site.example/matomo-proxy.php?module=Login&action=index'
#  -> HTTP 404, 0 bytes

# intended endpoint: the small opt-out iframe document
curl -i 'https://tracked-site.example/matomo-proxy.php?module=CoreAdminHome&action=optOut'
#  -> HTTP 200, ~2.7 KB

# BYPASS
curl -i -X POST 'https://tracked-site.example/matomo-proxy.php?module=&action=' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     --data 'module=CoreAdminHome&action=optOut'
#  -> HTTP 200, 235145 bytes, Content-Type: text/html
#  -> <title>Sign in - Matomo</title>, form_login / form_nonce / form_redirect
#  -> Set-Cookie: MATOMO_SESSID=...; path=/; HttpOnly; SameSite=Lax
```

A second variant reaches `CoreAdminHome`'s *default* action (the admin landing page) rather than `optOut`:

```bash
curl -X POST 'https://tracked-site.example/matomo-proxy.php?module=CoreAdminHome&action=' \
     -H 'Content-Type: application/x-www-form-urlencoded' --data 'action=optOut'
```

`poc/poc_allowlist_bypass.sh` runs all of the above plus the controls; `poc/poc_output.txt` is its recorded output from the lab.

### Impact

The proxy is installed in the public web root of the tracked website precisely so the Matomo server can stay hidden — in many deployments network-restricted so that only the proxy can reach it. The bypass turns the tracked website's own origin into an unauthenticated pass-through to Matomo's `index.php` for endpoints the allowlist exists to block. Concretely, and verified in the lab:

* Matomo application HTML that the allowlist blocks (235 KB — the Sign in page, including the login form, its `form_nonce`, and Matomo's markup/asset fingerprint) is returned with `Content-Type: text/html` **on the tracked website's origin**.
* Matomo's `MATOMO_SESSID` session cookie is set on the tracked website's origin, and the proxy forwards the client's `Cookie` header upstream on every request, so a Matomo session can be driven through the proxy for whichever modules are reachable.
* Matomo's login surface becomes reachable from the internet on an installation the operator believes is unreachable.

### What this is *not* — limits I verified rather than assumed

I want to be precise about the ceiling, because the difference matters for triage:

* **`module` is not freely attacker-controlled.** Because Matomo also honours the *present* GET key, an attacker can only force `module` into `CoreAdminHome` or empty (`→ CoreHome`). `Login`, `API`, `Widgetize`, `Proxy` etc. are **not** reachable — I tested them.
* **It is not an authentication bypass.** Matomo's own authorization still runs: admin-gated actions return the login page, not content. Submitting the login form through the proxy is not possible, because that would require reaching `module=Login`.
* **No XSS, no RCE, no data extraction** follows from it on stock Matomo 5.13.0 — see §5.

So: a real bypass of a real control with real consequences, but bounded. I would put it at **Low–Medium**; final severity is yours.

### Suggested fix

Make the proxy's view of `module`/`action` identical to Matomo's — resolve from `$_GET` first *by key presence*, not by truthiness, and only fall back to `$_POST` when the GET key is absent:

```php
$module = array_key_exists('module', $_GET) ? $_GET['module']
        : (isset($_POST['module']) ? $_POST['module'] : null);
$action = array_key_exists('action', $_GET) ? $_GET['action']
        : (isset($_POST['action']) ? $_POST['action'] : null);
```

Belt and braces: the proxy already rebuilds the forwarded query from `$_GET` for the tracker path; doing the same here — forwarding only the validated `module`/`action` pair — would remove the class of bug rather than this instance of it.

---

## 2. FYI (out of scope by policy): client-controlled IP headers authorised with the proxy's token

`getVisitIp()` (`proxy.php:263`) accepts `X-Forwarded-For`, `Client-IP` and `CF-Connecting-IP` from **any** client with no trusted-proxy check, and the result is forwarded as `cip` authorised by the proxy's write/admin `$TOKEN_AUTH`.

Verified live: `X-Forwarded-For: 9.9.9.3`, `Client-IP: 9.9.9.4` and `CF-Connecting-IP: 9.9.9.5` on an ordinary unauthenticated tracking request each produced a visit recorded with that IP (`matomo_log_visit.location_ip` = `9.9.0.0` after Matomo's own anonymisation), while the equivalent `&cip=9.9.9.9` parameter was correctly rejected with HTTP 400.

I am **not** claiming this as a vulnerability: the effect is spoofing your own recorded visitor IP, i.e. analytics pollution through the public tracking endpoint, which your policy excludes explicitly. It is written down only because it is the mechanism that makes the `clientProvidesAuthParams()` control — which exists to stop a client having its own `cip` honoured under the proxy's token — reachable by another route. If the maintainers consider that control worth having, the header path deserves the same gate (e.g. only trust these headers when the proxy is configured to sit behind a known reverse proxy).

## 3. Hardening note: default cookie forwarding crosses a trust boundary

With `$COOKIE_ALLOWLIST` unset — the shipped default — the proxy forwards the visitor's entire `Cookie` header to the Matomo server. Because the proxy is installed on the tracked website's own origin, that is the tracked site's cookie jar. Verified live against an instrumented upstream:

```
Cookie: PHPSESSID=SITE-SESSION-SECRET; wordpress_logged_in_9a=admin%7Cabcdef; _pk_id.1.1fff=aaa; csrftoken=CSRF123
```

— all four reached the upstream, on an ordinary tracking hit.

Not claimed as a finding: `$COOKIE_ALLOWLIST` was added for exactly this in PR #105 (2026‑07), the default is documented as backward compatibility, and the README calls it out. Worth reconsidering whether the safe configuration should become the default, particularly for Matomo Cloud where the upstream is a third party.

## 4. Hardening note: cross-host redirect following

On the `allow_url_fopen` backend, `file_get_contents()` follows `Location` responses (up to 20 hops) with no host restriction, and the proxy then serves the final hop's body — with the final hop's `Content-Type` — on the tracked website's origin. Demonstrated in the lab by pointing `$MATOMO_URL` at an upstream that 302s to a different host: the foreign host's body came back through the proxy verbatim (the status line forwarded is the *first* hop's 302, since `$http_response_header[0]` is the first status line).

The curl backend behaves differently — `CURLOPT_FOLLOWLOCATION` is never set, so it does not follow — which is itself an inconsistency worth knowing about.

I am **not** claiming this as a vulnerability, because I could not find a chain: I checked every Matomo endpoint the proxy can reach (`matomo.php`/`piwik.php` tracker, `index.php` for the opt-out actions and the modules reachable via §1, `plugins/HeatmapSessionRecording/configs.php`) and none of them emit an attacker-influenced `Location` — `grep` for `Location:`/`redirectToUrl` across `core/Tracker*` and `plugins/BulkTracking` is empty, and the reachable `index.php` responses were 200s. Setting `follow_location => 0` (or an explicit `max_redirects` of 1 with a host check) would close it pre-emptively and make the two backends agree.

---

## 5. Negative results — what I tried and could not break

These are recorded in full because "we tested this and it holds" is worth as much as a finding.

### 5.1 Token lending / auth-gated tracking parameters — holds

The proxy's core security property is that it must never lend `$TOKEN_AUTH` to a request carrying a parameter Matomo only honours for authenticated callers. I first established the authoritative list from Matomo 5.13.0 source rather than from the proxy's comments:

* `cip` — `Tracker\Request::getIpString()` (`core/Tracker/Request.php:934`)
* `cdt`, and `cdo` as its modifier — `Tracker\Request::getCurrentTimestamp()` (`:555`)
* `city`, `region`, `country`, `lat`, `long` — `RequestHandlerTrait::$fieldsThatRequireAuth`, enforced via `UserCountry\Columns\Base::getValueFromUrlParamsIfAllowed()`

Those eight, plus the bulk gate in `BulkTracking\Tracker\Requests::authenticateRequests()`, are the only `isAuthenticated()` consumers in the whole tree. `clientProvidesAuthParams()` covers **exactly** that set — no gap.

Attempts to get an override honoured under the proxy's token, all executed live (result = Matomo's HTTP status; 400 = correctly rejected):

| attempt | result |
|---|---|
| `&cip=9.9.9.9` in the query | 400 |
| `cdt=<40 days ago>` in the query | 400 |
| `cdt` in the **POST body** instead | 400 |
| `&country=zz` | 400 |
| `&cip[]=9.9.9.8` (array, to dodge the `is_string` test) | proxy drops it, sends its own `cip` |
| `&cip=` (empty, to dodge the emptiness test) | proxy drops it, sends its own `cip` |
| `&%20cdt=…` (PHP strips leading spaces from parameter names) | 400 |
| `&c.dt=…` (PHP maps `.`→`_`) | ignored — becomes `c_dt`, which Matomo does not read |
| `&cdt[]=…` (array) | 400 |
| `X-Forwarded-For` **plus** an explicit `cip` parameter | 400 |
| bulk: clean batch | tracked, top-level proxy token — correct |
| bulk: mixed batch with a `cdt` string entry | `{"tracked":1,"invalid":1}` — offending entry rejected |
| bulk: object entry carrying `cdt` | `{"tracked":1,"invalid":1}` |
| bulk: object entry with `cdt` as a nested array | tracked, but with **no** override applied |
| bulk: `"token_auth":""` at top level | proxy's own token used — correct |
| bulk: `"token_auth":["x"]` at top level | proxy's own token used — correct |

Structural reason it holds, which is the part worth stating: **the proxy re-serialises what it inspected.** The query is rebuilt with `http_build_query($_GET)`, the form body with `http_build_query($_POST)`, and each bulk entry with `'?' . http_build_query($params)` after `parse_url`+`parse_str` — the same functions Matomo uses. Parameter smuggling would need the proxy and Matomo to parse the *same bytes* differently, and after the rewrite Matomo never sees the original bytes. I specifically probed the ways that could still diverge and each is safe:

* **`max_input_vars` truncation** — a `cip` pushed past the 1000-parameter limit is invisible to the proxy *and* stripped from the rewritten output, so Matomo never sees it either.
* **`Common::sanitizeLineBreaks()` also strips `\0`, the proxy's pre-decode `str_replace` does not** — a real divergence, but fail-safe: a NUL makes the proxy's `json_decode` fail, so it forwards the body unchanged **with no token**, and Matomo then rejects it.
* **`json_encode` failure** falls back to the untouched raw body — again with no token attached.
* **`isUsingBulkRequest`** — the proxy replicates Matomo's truthy-`strpos` quirk verbatim, including the "marker at offset 0 is not bulk" case, so the two never disagree about whether a body is a batch.
* **Per-entry `token_auth` in a mixed batch** is inert on Matomo's side anyway: `RequestSet::setRequests()` constructs every `Tracker\Request` with the *top-level* token, and `Request::getTokenAuth()` returns that constructor argument without consulting the entry's own parameters. Not a security problem (it fails closed), but it means the `$includeProxyTokenPerEntry` branch is dead weight and mixed batches silently lose their clean entries.

### 5.2 Token / upstream-URL disclosure — none found

84 requests across every reachable endpoint (tracker with malformed `idsite`, `debug=1`, `ping`, `_cvar`, goal/ecommerce/search/link/download parameters; both opt-out actions with all 15 documented parameters; the allowlisted `.js` file; direct hits on `proxy.php` and `config.php`; the bypass itself), scanning **both response bodies and response headers** for the literal `$TOKEN_AUTH` and for the upstream host:port. **Zero hits.** `sanitizeContent()`'s scrubbing of the raw, `rawurlencode`d and `urlencode`d token forms is effective, and no reachable Matomo endpoint echoes the query string back.

Also checked and clean: `proxy.php` requested directly exits on the `MATOMO_PROXY_FROM_ENDPOINT` guard; the `.js` branch (which skips `sanitizeContent()` entirely) never carries the token in its upstream URL, and the static files it serves contain no upstream URL.

### 5.3 Reflected XSS on the tracked site's origin — none found

This was the highest-value hypothesis: any reflection in a proxied endpoint executes on the *tracked website's* origin rather than on Matomo's, which is a severity uplift the proxy uniquely creates. Tested:

* **Tracker error paths** — malformed `idsite`, missing `idsite`, unauthenticated `cip`, bad `_cvar`, bad revenue: all return `Content-Type: image/gif` with a zero-length body. No reflection, no HTML.
* **`CoreAdminHome.optOut`** — `optOutStyling()` reads `fontSize`, `fontColor`, `fontFamily`, `backgroundColor` through `Piwik\Request::getStringParameter()`, which does **not** HTML-encode, and embeds the raw value in an exception message. That looked like a live reflected XSS; it is not. Matomo's error page escapes the message (`&lt;script&gt;…`), verified with four payloads. The values that pass validation are constrained by `ctype_xdigit` (colours), an anchored `^[0-9]+\.?[0-9]*(px|pt|em|rem|%)$` (size) and `^[a-zA-Z0-9-\ ,\'"]+$` (family). The family class does permit `'` and `"` and therefore does break out of the `optOutDiv.style.cssText += '…'` string literal in `getOptOutJS()` — but with no `(`, `)`, `=`, `.`, `[` or backtick available there is no way to reach a call or an assignment, so it yields a syntax error at worst, not execution. Reported as neither.
* **`optOut.twig`** — every `|raw` there is a server-generated value (stylesheet/script paths, `queryParameters|url_encode`); `reloadUrl` and `nonce` are auto-escaped and URL-encoded. Confirmed by injecting `"><script>` through arbitrary extra query parameters, which come back percent-encoded inside the `meta refresh`.
* **`optOutJS`** — served as `application/javascript`; the settings blob goes through `json_encode` of values already HTML-encoded by `Common::getRequestVar`.
* **The proxy's own output** — `sanitizeContent()` only performs literal `str_replace` of config-controlled strings and one `preg_replace` whose pattern and replacement both come from the hardcoded `$VALID_FILES`; nothing attacker-influenced reaches either.

### 5.4 Path traversal — none found

`$filerequest` is the only file-ish input. It is compared with `in_array($filerequest, $VALID_FILES, true)` — strict, exact, single-entry — before `proxy.php` builds `$MATOMO_URL . $filerequest`. Array values fail the strict comparison; `''` and `'0'` fall through to the method check; `$path` is a per-entry-point constant in all four entry files; and the query is appended with `http_build_query()`, which percent-encodes `/`, `?` and `&` in both keys and values, so no request-supplied byte can ever alter the upstream path. Traversal attempts through `file=`, and attempts to relocate the upstream path via crafted `$_GET` keys, all returned 404 or an unchanged upstream path.

### 5.5 RCE — no primitives

No `eval`, no `include`/`require` of a variable, no `unserialize`, no `preg_replace` with `/e`, no `system`/`exec`/`popen`/`passthru`, no dynamic callables anywhere in the 687 lines of `proxy.php` or the four entry points. The single `include` in each entry file is a hardcoded `__DIR__` path.

### 5.6 Response-header handling — no injection

`forwardHeaders()` forwards only `content-type`, `access-control-allow-origin`, `access-control-allow-methods` and `set-cookie`, all sourced from the upstream Matomo response, and PHP's `header()` refuses CRLF regardless. `Accept-Language` is explicitly stripped of `\n`, `\r`, `\t` before being sent upstream. `User-Agent` and `Cookie` are *not* CRLF-sanitised on the outbound side, which is worth noting as defence in depth, but I could not produce a delivery vector: no compliant HTTP server admits a raw CR or LF into a request header value, so `$_SERVER['HTTP_USER_AGENT']`/`HTTP_COOKIE` cannot carry one. Not reported as a finding for that reason.

One behavioural bug, non-security: `sendHeader()` passes `$replace = true`, so when Matomo emits more than one `Set-Cookie` only the last survives the hop back to the visitor.

### 5.7 Out of scope, not tested further

Per program policy: the `tests/` directory (development-only, `export-ignore`d from release archives since `ecbc1a3`, and the README now warns against serving a clone); anything requiring a non-default `$DEBUG_PROXY`/`$NO_VERIFY_SSL`; `secure;` stripping when the proxy is served without HTTPS; and CLI paths.

---

## Reproducing the lab

```
matomo 5.13.0            -> http://127.0.0.1:8400   (PHP 8.4, MariaDB, db matomo513)
tracker-proxy ecbc1a3    -> http://127.0.0.1:8500   config.php: $MATOMO_URL=…:8400/,
                                                    $PROXY_URL=…:8500/, write-scoped $TOKEN_AUTH
```

`poc/poc_allowlist_bypass.sh <proxy-url>` reproduces finding 1 together with its controls.
`poc/poc_output.txt` is the recorded run against the lab above.
