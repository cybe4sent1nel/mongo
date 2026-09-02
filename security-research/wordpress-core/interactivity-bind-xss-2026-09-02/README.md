# WordPress Core 7.1 — Interactivity API `bind` client/server disagreement

**Finding:** kses allows Interactivity API directives in ordinary post content (`data-*` is a
global attribute and `/^data-[a-z0-9_-]+$/` admits the double-dash form). The server refuses to
turn a bound value into a URL attribute — `WP_HTML_Tag_Processor::set_attribute()` runs
`esc_url()` over everything in `wp_kses_uri_attributes()` — but the client runtime applies the
same binding with `el.setAttribute()` and no scheme check at all, and applies `data-wp-style`
with `el.style.cssText` and no `safecss_filter_attr()` equivalent.

Confirmed by execution on **WordPress 7.1** and **7.0.4**:

* A **Contributor** (no `unfiltered_html`) submits a post; every directive survives kses.
* An Editor publishes it through the normal review workflow.
* The server emits the anchor with **no** `href` and **no** `style`.
* The browser writes `href="javascript:…"` and
  `style="position:fixed;inset:0;z-index:2147483647"` — a transparent full-viewport overlay.
* **One click anywhere on the page**, in an administrator's session, creates a new
  **administrator** account.

Severity claimed: **CVSS 3.1 9.0** (`AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H`), or **7.9** with
`S:U`. CWE-79 / CWE-1289.

`HACKERONE-REPORT.md` is the submission.

## Lab

| | version | port | database |
|---|---|---|---|
| primary | 7.1 (released `wordpress-7.1.zip`) | 8371 | `wp71` |
| control | 7.0.4 (git tag `7.0.4`) | 8372 | `wp704` |

PHP 8.4.19 CLI server, MariaDB 10.11.14, Chromium 1194 via Playwright 1.62. Stock
Twenty Twenty-Five, no plugins. Users `admin`, `editor`, `author`, `contributor`,
`subscriber`, each with its stock role.

Both installs must be reached on `localhost`, not `127.0.0.1` — the `siteurl` is
`localhost:<port>`, and browsing the other host makes the script module fail CORS, which looks
exactly like "not vulnerable". That mistake cost one false negative during this audit (see
below).

## Files

| file | what it is |
|---|---|
| `poc/evidence_iapi.py` | the report's evidence run against 7.1, including the negative control |
| `poc/evidence_iapi.txt` | its literal output (quoted in the report) |
| `poc/t_iapi_704.py`, `poc/evidence_iapi_704.txt` | the same chain against 7.0.4 |
| `poc/t_iapi_takeover.py` | minimal administrator-account-creation PoC |
| `poc/t_iapi_exploit.py` | narrated Contributor → Editor → admin-click chain |
| `poc/t_iapi_browser.py` | the first, minimal `href` proof (server refuses / client applies) |
| `poc/t_iapi.py`, `poc/t_iapi2.py` | survey of which directives survive kses and which the server acts on, across four block wrappers |
| `poc/iapi_isolate.php` | isolates directive processing per directive and per nesting depth |
| `poc/iapi_url_schemes.php` | the twelve URL-scheme variants the server refuses vs. accepts |
| `poc/wplab.py`, `poc/wplab704.py` | HTTP harness (cookie login, REST nonce, request helpers) |

## Negative results from this pass

Recorded so the work is not repeated.

* **The server-side `bind` guard is sound.** Twelve scheme-smuggling variants
  (`JaVaScRiPt:`, embedded tab/newline, leading space, `data:text/html`, `vbscript:`,
  `&#106;avascript:`, `javascript&colon;`) are all refused by `esc_url()`; benign
  `https:`/`mailto:`/relative values pass. The defect is the client's silence, not a
  server-side filter bypass.
* **Server-side event-handler binding is blocked.** `data_wp_bind_processor()` skips any
  `on*` suffix (added 6.9.2). The client does not apply them either: `el.onclick = "string"`
  is null per WebIDL, and Preact's `on*` prop branch throws on a string rather than executing
  it. No XSS there.
* **`data-wp-text` is safe.** It sets escaped text, verified with an
  `<img src=x onerror=…>` context value that came back entity-encoded.
* **No camelCase directive suffix is reachable.** The client `bind` has branches for
  `tabIndex`, `rowSpan`, `colSpan` and would forward `dangerouslySetInnerHTML` to Preact's
  `innerHTML` sink, but suffixes come from `element.attributes`, which the HTML parser
  lowercases, so `dangerouslysetinnerhtml` never matches. Checked rather than assumed.
* **No zero-interaction variant found.** Of the tags in `$allowedposttags`, none pairs a
  dangerous all-lowercase IDL property with the client's `el[attribute] = result` branch:
  `iframe`/`script` are not allowed, `object.data` and `video.poster` do not execute,
  `button.formaction` needs a `form` (also not allowed), and `img.src`/`track.src` are inert.
  The report therefore claims `UI:R` and nothing better.
* **False negative worth flagging:** 7.0.4 first appeared unaffected. It was a lab artifact —
  I browsed `127.0.0.1:8372` against a `localhost:8372` `siteurl`, so the interactivity module
  was CORS-blocked and never hydrated. The two runtimes are byte-identical apart from three
  `catch (e)` → `catch` rewrites. Re-run on the correct host, 7.0.4 is affected.
