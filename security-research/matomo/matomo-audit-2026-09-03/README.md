# Matomo 5.13.0 — stored XSS / RCE / path-traversal audit (2026-09-03)

Deep audit of **Matomo core** (`github.com/matomo-org/matomo` @ tag `5.13.0`, the current stable
release) and **matomo-org/tracker-proxy** (@ HEAD), both in scope on the Matomo HackerOne program.

Everything below was run against a **live instance**, because the program explicitly rejects
findings "based solely on code analysis … without demonstrated exploitability".

| | |
|---|---|
| Target | Matomo 5.13.0, PHP 8.4.19, MariaDB, `http://127.0.0.1:8400` |
| Roles provisioned | anonymous, `view`, `write`, `admin`, `superuser` (session cookies **and** API tokens for each) |
| Execution oracle | headless Chromium (Playwright) with `alert`/`confirm`/`prompt` hooked, `window.__XH` sink, and every DOM event dispatched on every node in every frame |

**Result: no exploitable stored XSS, RCE or path traversal found.** One genuine defect was found
and is reported below as **hardening only** — I could not demonstrate a delivery path, and I am not
claiming it as a vulnerability.

---

## 1. Finding (hardening, not a vulnerability): tracking-code options bypass the HTML escaping

**File:** `core/Tracker/TrackerCodeGenerator.php` → `generate()`
**Class:** CWE-116 (improper encoding) — escape-then-substitute ordering
**Privilege to reach the sink:** `view` on the site (`SitesManager.getJavascriptTag` only calls
`Piwik::checkUserHasViewAccess($idSite)`)

### The defect

`generate()` escapes the tracking-code *template* and only afterwards substitutes the
placeholders, so everything substituted in — including the whole `$options` block — lands
unescaped:

```php
$jsCode = $view->render();
$jsCode = htmlentities($jsCode, ENT_COMPAT | ENT_HTML401, 'UTF-8');   // template escaped

foreach ($codeImpl as $keyToReplace => $replaceWith) {
    $jsCode = str_replace('{$' . $keyToReplace . '}', $replaceWith, $jsCode);   // <-- filled in after
}
```

`$options` is built earlier from `json_encode()`d request values:

```php
$options .= '  _paq.push(["setExcludedReferrers", ' . json_encode($excludedReferrers) . ']);' . "\n";
```

`json_encode()` escapes `"` and `/` but **not** `<` or `>`, so `<img …>` survives verbatim.

The result is consumed as raw HTML in two places:

* `plugins/SitesManager/templates/_matomoTabInstructions.twig` → `<pre …>{{ jsTag|raw }}</pre>`
* that rendered tab is returned by `SitesManager.getTrackingMethodsForSite` and injected by
  `plugins/SitesManager/vue/src/SiteWithoutData/SiteWithoutData.vue` via
  `<VueEntryContainer :html="showMethodDetails.content" />` — raw HTML, no `$sanitize`.

### Proof (live, `view` user)

`poc/t_trackingtab.py` — the surrounding template is entity-escaped while the injected value is not:

```
parameter                        raw <img> in tab content?
excludedReferrers                YES   …&quot;trackPageView&quot; */   _paq.push(["setExcludedReferrers", ["<img src=x onerror=alert(1)>"]]);
excludedQueryParams              YES   …_paq.push(["setExcludedQueryParams", ["<img src=x onerror=alert(1)>"]]);
customCampaignNameQueryParam     YES   …_paq.push(["setCampaignNameKey", "<img src=x onerror=alert(1)>"]);
customCampaignKeywordParam       YES   …_paq.push(["setCampaignKeywordKey", "<img src=x onerror=alert(1)>"]);
visitorCustomVariables           no
pageCustomVariables              no
piwikUrl (control, sanitized)    no
```

`poc/poc_trackercode.php` isolates the ordering defect with no Matomo needed:

```
template '<' escaped        : yes
injected '<img' still live  : YES  <-- unescaped markup
```

### Why I am **not** claiming this as a vulnerability

I could not find a way for an attacker to get those parameters into a *victim's* request:

* `SiteWithoutData.vue` calls `AjaxHelper.fetch({module, action})`, and
  `AjaxHelper.mixinDefaultGetParams()` only ever adds `idSite`, `period`, `date` and `segment` —
  it does **not** forward arbitrary URL query parameters, so a crafted link does not reach the
  AJAX call. Verified in the browser: five candidate URLs, 0 executions, payload not in the DOM.
* Requesting `SitesManager.getTrackingMethodsForSite` directly returns
  `Content-Type: application/json`, which the browser does not render.
* `module=API&method=SitesManager.getJavascriptTag&format=html|xml|original` re-escapes the whole
  string (verified: output contains `&lt;img …`), so the API renderers are not a sink.
* The values are **never** read from stored site settings on this path — `getJavascriptTag`
  defaults them to `''` and only `Request::processRequest` resolution from the *current* request
  fills them, so there is no second-order/stored variant.
* `CoreAdminHome.trackingCodeGenerator` renders the result with `v-text`, not `v-html`.
* `plugins/Installation/Controller.php:403` (the other `_displayJavascriptCode` consumer) is
  blocked post-install ("Matomo is already installed").

So in 5.13.0 this is reachable only by the user attacking their own browser. It is still worth
fixing: the escaping contract is inverted, and any future caller that renders `jsTag` from stored
or cross-user data turns it into a real stored XSS.

### Fix

Escape each substituted value rather than the template, e.g. build `$options` with
`json_encode($v, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT)`, or apply
`htmlentities()` to `$codeImpl` values inside the substitution loop instead of to `$jsCode`
beforehand.

---

## 2. Stored XSS — negative, empirically

~150 payloads across 12 shapes (attribute breakout in both quote styles, `</script>` breakout,
`javascript:` URL, unicode-escaped `<`, `<noscript>` mXSS, entity-encoded `javas&#99;ript:`,
comment/double-escape `<!--<script>-->`, backslash-terminated JS string) were **stored** through
the real write paths and then rendered.

**Injected through:**

| surface | privilege |
|---|---|
| tracker `matomo.php`: `action_name`, `url`, `urlref`, `uid`, `_rcn`, `_rck`, `search`, `e_c/e_a/e_n`, `c_n/c_p/c_t/c_i`, `dimension1`, `link`, `download`, `ua`, `pv_id`, `_cvar` | **unauthenticated** |
| `Annotations.add`, `SegmentEditor.add`, `Goals.addGoal`, `ScheduledReports.addReport`, `Dashboard.createNewDashboardForUser` | write |
| `SitesManager.addSite` / `updateSite` (name, group, excluded params/UA/referrers), `TagManager.addContainer` / `addContainerVariable` / `addContainerTrigger` | admin |
| `UsersManager.setUserPreference` | superuser |

**Rendered and event-fuzzed in Chromium:** 181 page loads across three runs — the SPA dashboard,
Visitor Log, Actions (pages/titles/entry/exit/outlinks/downloads/site-search), Referrers
(all/campaigns/keywords/websites/socials), Events, Contents, Custom Variables, UserId, Goals,
MultiSites, Annotations, Insights, DevicesDetection, every management screen (Sites, Users,
Segments, Goals, Custom Dimensions, Email Reports, Tag Manager containers/tags/variables/triggers,
Privacy, General Settings, Tracking-code generator), Row Evolution and Multi-Row Evolution
popovers, Transitions popovers, and every visualization (`graphEvolution`, `graphVerticalBar`,
`graphPie`, `cloud`, `sparkline`, `tableAllColumns`, `tableGoals`).

**0 executions.**

Two mechanisms explain the result, and both were verified rather than assumed:

* `Common::getRequestVar()` runs `html_entity_decode()` → `htmlspecialchars(ENT_QUOTES)` on every
  request value, so the database holds encoded text. Double-encoding does not help because the
  decode happens first.
* Display uses `rawSafeDecoded` → `SafeDecodeLabel::decodeLabelSafe()`, which is
  `urldecode()` → `htmlspecialchars_decode()` → `htmlspecialchars(ENT_QUOTES|ENT_IGNORE)`. The
  final step is an *encode*, so `<` can never reach the DOM through it, including inside the
  single-quoted `href='…'` in `_dataTableCell.twig`.

Also confirmed inert: HTML e-mail reports (`ScheduledReports.generateReport reportFormat=html`
contains no raw tag), PDF reports, and the CSV/TSV exporters (`Csv::formatFormulas()` prefixes
`=`, `+`, `-`, `@` with `'`; the leading-`%` and leading-quote bypasses do not survive it).

## 3. Reflected XSS — negative, empirically

A global pool of **275 request parameter names** was harvested from the whole tree
(`getRequestVar('…')`, `get*Parameter('…')`, `$_GET[…]`, `$_POST[…]`) and replayed against **every
controller action** with five payload shapes, matching only unescaped reflection in a
`text/html` response.

| run | probes | hits |
|---|---|---|
| unauthenticated, all plugins except auth/updater/marketplace | 1692 | 0 |
| `view` user, same set | 1692 | 0 |
| unauthenticated, `Login` + `Installation` + `CoreUpdater` + `CorePluginsAdmin` + `Marketplace` + `TwoFactorAuth` | 594 | 0 |
| all 453 API methods × `html`/`original`/`xml`/`rss`/`json`, looking for raw markup in a `text/html` body | 1065 | 0 |

A static cross-reference was run alongside it: 116 template variables are printed with `|raw`, and
11 view variables are assigned from unsanitized request values — **the two sets do not intersect**.

This matters because `Piwik\Request` (the modern parameter API, 126 call sites) deliberately does
**not** HTML-encode — its own docblock says "should never be used raw in templates or other
output". The discipline holds in 5.13.0, but it is a single mistake away from a reflected XSS, and
`Common::getRequestVar()` gives no such warning by encoding for you.

## 4. Path traversal — negative, empirically

| run | probes | hits |
|---|---|---|
| all 453 API methods, traversal payload in every path-shaped parameter (9 payloads incl. `php://filter`, `%00`, `....//`, absolute paths) | 2457 | 0 |
| all controller actions as `view` | 1316 | 0 |
| all controller actions × 275-parameter pool × 4 payloads (unauth + `view`) | included in §3 counts | 0 |

Detection was content-based (`root:x:0:0`, `[database]`, `tables_prefix`, base64 of the config).

Manually reviewed and cleared, with the reason:

| site | why it holds |
|---|---|
| `Proxy::getUmdJs` → `asset_manager_chunk.{$chunk}.js` | `$chunk` must match an existing chunk name or `ThingNotFoundException` is thrown; the `asset_manager_chunk.` prefix also has to survive as a real path segment. Probed live with 6 payloads → 404. |
| `Proxy::getPluginUmdJs` | `Manager::isValidPluginName()` allowlist |
| `LanguagesManager::getAvailableLanguagesInfo` `file_get_contents(sprintf('%s/lang/%s.json', …))` | `$filename` comes from a filesystem `glob()`, not the request; `isLanguageAvailable()` additionally requires `Filesystem::isValidFilename()` + membership in the glob result |
| `DeviceDetectorCache::getCachePath()` (unauthenticated, User-Agent derived) | path is `md5($ua)`; cache body is `var_export()` |
| `CoreAdminHome/CustomLogo.php` | fixed filenames; temp dir is `sha1(login)` |
| `TagManager` `Context/Storage/Filesystem::save()` | path is `getJsTargetPath()` = storage dir + prefix + server-generated `idcontainer` + `(int)$idSite` |
| `GeoIP2AutoUpdater::unzipDownloadedFile()` | archive member reduced with `basename()`; result must pass `getGeoIPDatabaseTypeFromFilename()`; the download host must match `geolocation_download_from_trusted_hosts` |
| `CorePluginsAdmin` plugin-zip upload | superuser + password re-auth + nonce; out of scope by the program's own "Matomo requires write access to its own directories" note |
| every `new View($template)` (9 sites) | all called with string literals from internal callers |

## 5. RCE — negative

* **No dynamic execution primitives.** `eval`, `create_function`, `assert`, `preg_replace /e`,
  `proc_open`, `passthru`, `popen`: zero hits outside `CliMulti`/`Filechecks` (which use fixed
  command strings) and tests.
* **Object injection blocked.** Every `unserialize()` in `core/` and `plugins/` goes through
  `Common::safe_unserialize()`, which passes `['allowed_classes' => false]`. The two callers of the
  legacy global `safe_unserialize()` (`core/Cookie.php`, `plugins/CoreUpdater/Controller.php`) use
  `libs/upgradephp`'s hand-written parser, which returns `false` for any `O:` token
  ("object or unknown/malformed type").
* **No SSTI.** No `Twig\Loader\ArrayLoader`, `createTemplate()` or `renderString()` anywhere; all
  templates are files named by literals.
* **No dynamic includes from request data.** The `include`/`require` sites take fixed paths or
  values from `Manager::getPluginDirectory()`.
* `CoreUpdater/Controller.php:265` unserialises a POST parameter, but through the object-free
  parser, and the result is printed with Twig autoescaping (`{{ message }}`), not `|raw`.
* Segment-driven SQL injection: 680 probes (10 dimensions × 4 operators × 17 injection strings)
  through `Live.getLastVisitsDetails` as a `view` user — **0** SQL errors or driver exceptions.

## 6. Privilege boundaries — negative

All 453 API methods were called as **anonymous** and as a **`view`** user with filled-in
parameters (906 calls). Every state-changing method that succeeded is legitimately available at
that level and self-scoped: `Annotations.add`, `Dashboard.createNewDashboardForUser` /
`removeDashboard` / `resetDashboardLayout` (all gated by
`Piwik::checkUserHasSuperUserAccessOrIsTheUser($login)` — verified by reading the source after the
probe), `CorePluginsAdmin.setUserSettings`, `LanguagesManager.set*ForUser`, and the `Feedback.*`
endpoints. No cross-user or cross-site write was reachable.

## 7. tracker-proxy (matomo-org/tracker-proxy @ HEAD) — negative

* `matomo-proxy.php` gates `?file=` with `in_array($filerequest, $VALID_FILES, true)` — a strict
  allowlist of one entry — and `module.action` against a two-entry `$SUPPORTED_METHODS`
  allowlist. No traversal, and `$path` is a literal in every endpoint, so the upstream URL cannot
  be redirected (no SSRF).
* The proxy lends its `$TOKEN_AUTH` only when the client sent none of Matomo's auth-gated tracking
  parameters. I checked that list against core and it is **complete**: `Tracker\Request` gates
  `cip` (`getIpString()`) and `cdt`/`cdo` (`getCurrentTimestamp()`), and
  `RequestHandlerTrait::$fieldsThatRequireAuth` gates exactly `city`, `region`, `country`, `lat`,
  `long` — the same seven the proxy checks, plus `token_auth`. The string-only/array-value edge
  cases are handled the same way core reads them, so array or empty values cannot slip past.
* Header injection is not reachable: `Accept-Language` is CRLF-stripped, and `User-Agent`/`Cookie`
  come from request headers that the web server will not let contain CRLF.
* `sanitizeContent()`'s `preg_replace('^' . $filepath . '…^', …)` interpolates only hard-coded
  `$VALID_FILES` entries, so the delimiter choice is not attacker-influenced.
* Visitor-IP spoofing via `X-Forwarded-For` → `cip` is possible but is both the documented purpose
  of the proxy and explicitly out of scope ("analytics pollution through the public tracking
  endpoint").

## 8. Methodology notes (two traps that would have produced false results)

1. **Self-poisoning oracle.** The first Chromium run reported "hits" on 37/37 pages. They were all
   my own instrumentation: I had hooked `window.eval`, and Playwright's `page.evaluate()` goes
   through it. Removing the hook and filtering to the payload tag format gave the true result, 0.
2. **Inactive plugins.** `TagManager`, and initially the tracking data itself, produced empty
   report pages. Injecting into a surface whose plugin is not activated looks like "sanitised" when
   it is really "never rendered" — every surface here was confirmed to contain the payload
   (`__XH` present in the served HTML) *before* being counted as a negative. For example
   `Actions.getPageTitles` served 94 encoded occurrences and 0 raw ones.

## Reproduce

```
php  poc/poc_trackercode.php                     # ordering defect, standalone
python3 poc/t_trackingtab.py <matomo-url> viewer <password>
```
