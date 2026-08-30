# safecss_filter_attr() CSS-rule-injection PoC

Reproduces the finding in `../round27-CONFIRMED-safecss-filter-attr-css-rule-injection.md`.

## Requirements

A local clone of `WordPress/wordpress-develop`. Set `WP_SRC` to its `src/` directory before
running (defaults to `/home/user/drivers/wordpress-develop/src` below — edit the `require` paths
in `exploit3.php`/`exploit4.php` if your checkout lives elsewhere).

## Files

- `stubs2.php` — minimal, faithful stand-ins for the handful of WordPress functions
  `kses.php`/the Style Engine classes call that aren't themselves security-relevant
  (`apply_filters`, `did_action`, `wp_allowed_protocols`, `wp_parse_args`, `sanitize_key`,
  `wp_strip_all_tags`). No sanitization logic is reimplemented — every security-relevant
  function (`safecss_filter_attr`, `wp_kses_bad_protocol`, `WP_Style_Engine_CSS_Declarations`,
  `WP_Style_Engine_CSS_Rule`) is `require`'d directly from the real WordPress core source.
- `exploit3.php` — the `clip-path: path(...)` variant, using a function only added to the
  allowlist in the unreleased 7.1/7.2 hardening commit (`996c6d6864`).
- `exploit4.php` — the `color: var(...)` variant, using a function that has been in the
  allowlist since WordPress 5.8.0 — proves the bug predates that commit and is live in the
  current stable release.
- `poc2.html` / `poc3.html` — the exact `<style>` output from `exploit3.php`/`exploit4.php`
  respectively, wrapped in a minimal page that reads `getComputedStyle(document.body)
  .backgroundImage` into `document.title` on load, for browser verification.

## Running it

```sh
php exploit3.php   # or exploit4.php
# => prints the literal <style> tag content WordPress's style engine would emit
```

```sh
/opt/pw-browsers/chromium-1194/chrome-linux/chrome \
  --headless=new --disable-gpu --no-sandbox --virtual-time-budget=3000 --dump-dom \
  "file://$(pwd)/poc3.html" 2>/dev/null | grep -io "<title>.*</title>"
# => <title>BODY-BG=url("https://evil.example/exfil.png")</title>
```

(Any Chromium/Chrome build with `--headless=new` works; the path above is this session's
pre-installed binary.)
