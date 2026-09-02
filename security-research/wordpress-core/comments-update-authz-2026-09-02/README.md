# WordPress Core 7.1 — comment update authorization audit

**Finding:** `WP_REST_Comments_Controller::update_item_permissions_check()` validates only the
comment being edited and never the new values, so every target-side check the create path
enforces is bypassable by creating a comment/note where it is allowed and then moving and
re-attributing it in one `POST /wp/v2/comments/<id>`.

Confirmed by execution on **WordPress 7.1** and **7.0.4**:

* **Contributor → forged, Administrator-attributed note on the Administrator's page**, after the
  same endpoint refused the direct create with `403 rest_cannot_create_note`.
* **Author → approved, publicly rendered comment on a comments-CLOSED post, attributed to the
  Administrator**, after the same endpoint refused the direct create with
  `403 rest_comment_closed`.

Neither role holds `moderate_comments`. `author`, `author_name`, `author_email`, `status` and
`date` are all accepted on update from a user without it; `post` may be changed to any existing
post, including private posts and pages owned by others.

Severity claimed: **CVSS 3.1 7.1** (`AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N`), or **6.5** with
`S:U`. CWE-639 / CWE-863.

`HACKERONE-REPORT.md` is the submission.

## Lab

Two throwaway installs on one host, both driven over real HTTP with ordinary logged-in cookies
plus `X-WP-Nonce` (exactly what the block editor sends):

| | version | port | database |
|---|---|---|---|
| primary | 7.1 (released `wordpress-7.1.zip`) | 8371 | `wp71` |
| control | 7.0.4 (git tag `7.0.4`) | 8372 | `wp704` |

PHP 8.4.19 CLI server, MariaDB 10.11.14. Users: `admin`, `editor`, `author`, `contributor`,
`subscriber`, each with its stock role.

## Files

| file | what it is |
|---|---|
| `poc/wplab.py`, `poc/wplab704.py` | tiny HTTP harness (login, REST nonce, request helpers) |
| `poc/evidence_comment_authz.py` | the report's evidence run against 7.1 |
| `poc/evidence_comment_authz.txt` | its literal output (quoted in the report) |
| `poc/evidence_704.txt` | the same run against 7.0.4 |
| `poc/poc_comment_update_authz.py` | narrated two-chain PoC |
| `poc/t_notes.py` | notes read/write authorization matrix across all five roles |
| `poc/t_notes2.py` | which update fields and which target posts are unchecked |
| `poc/comments-controller-7.0.4-to-7.1.diff` | the whole controller diff between the two versions (4 insertions, 6 deletions, all cosmetic) |
| `poc/kses_batch.php`, `poc/kses_fuzz.py` | the kses differential fuzzer — **negative result** |
| `poc/kses_fuzz_hits.json` | its 152 hits, all the same inert attribute-free `<object>` |

## Negative results from the same audit (not reported as vulnerabilities)

Recorded so the work is not repeated:

* **kses is holding.** 50,067 payloads through WordPress 7.1's real `pre_comment_content` and
  `content_save_pre` chains, each output parsed in headless Chromium and scanned for event
  handlers, `javascript:`/`data:`/`vbscript:` URLs, `<script>`, `srcdoc`, and dangerous `style`
  values. Curated seeds covered the new 7.1 `wp_kses_split2()` bogus-comment-state branch, the
  note-mention `<span class>` allowance, protocol smuggling, entity tricks, and the expanded
  `safecss_filter_attr()` SVG/`url()`/transform allowances. The only survivor was an
  attribute-free `<object>` from `wp_kses_post`, which is inert.
* **Block attributes are kses-filtered.** `filter_block_content()` /
  `filter_block_kses_value()` (`wp-includes/blocks.php:2121-2213`) run `wp_kses()` over every
  string block attribute at save time, which closes the "unescaped block attribute" class for
  users without `unfiltered_html` — including the unescaped `$attributes['label']` in
  `render_block_core_post_navigation_link()` (`wp-includes/blocks/post-navigation-link.php:59-60`),
  which is otherwise emitted raw by `get_adjacent_post_link()`. Verified by executing it: a
  `<`-encoded payload is decoded, kses'd, and re-serialized before storage.
* **`wp-admin/includes/media.php:1717`, `:3180`, `:3230` are still unescaped** — the three
  output sinks named in HackerOne #3931771 and its addendum. WordPress 7.1 fixed the *write*
  primitive (the finalize provenance allowlist in
  `class-wp-rest-attachments-controller.php:3087-3115`) but did not add `esc_url()` to the
  sinks. I could not find any remaining way to put a quote into `_wp_attachment_metadata`
  (`sanitize_file_name()` strips `'` and `"`; `wp-admin/post.php:231` uses `wp_basename()`; the
  ID3 path is confined to id3 keys), so this is a hardening observation, not a vulnerability,
  and is deliberately not in the report.
* **REST read authorization is clean.** All 127 GET-reachable routes probed anonymously and as
  each of the five roles; nothing readable that should not be.
* **SSRF blocked.** `/wp-block-editor/v1/url-details` at Contributor privilege rejects
  `127.0.0.1`, `localhost`, `[::1]`, `0`, `127.1`, decimal/octal/hex encodings, and
  `169.254.169.254` at the validation stage; a local canary listener recorded no hits.
* **Posts controller re-checks its own fields.** A Contributor cannot change `author`, `status`,
  `sticky` or `type` on their own post — the asymmetry is specific to the comments controller.
* **`admin-ajax` handlers without a nonce or capability check** (`date_format`, `time_format`,
  `oembed_cache`, `dashboard_widgets`, `rest_nonce`) are reachable by any logged-in user, but
  `sanitize_option()` runs `strip_tags()` + `wp_kses_data()` on the reflected format strings, so
  the reflection is inert.
