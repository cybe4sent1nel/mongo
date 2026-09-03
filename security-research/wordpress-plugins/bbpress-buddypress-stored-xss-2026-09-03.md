# bbPress + BuddyPress — stored XSS audit of user-generated content (2026-09-03)

Targeted hunt for **stored XSS reachable by a low-privilege member** across the surfaces that
matter in these two plugins: forum topics/replies, activity streams, group name/description,
private messages, and profile data. Live lab: WordPress 7.1, PHP 8.4.19, BuddyPress
`15.0.0-alpha` (@`4af6c90`) and bbPress `2.7.0-alpha-2`, both installed and activated with the
relevant components on.

**No exploitable stored XSS found.** Every payload was driven through the *real* save filter
chain and the *real* display filter chain, then rendered in **headless Chromium** with `alert`
hooked and `mouseover/click/focus/load/error` dispatched to every node. 75 rendered cases,
**0 executed**.

## Method

For each surface, content was pushed through the genuine hooks rather than reimplemented:

* **BuddyPress** — `apply_filters('bp_activity_content_before_save')` →
  `apply_filters('bp_get_activity_content_body')`; same shape for
  `group_description_before_save` → `bp_get_group_description`, `group_name_before_save` →
  `bp_get_group_name`, and `messages_message_content_before_save` →
  `bp_get_the_thread_message_content`.
* **bbPress** — the real reply chain `bbp_new_reply_pre_content`
  (`bbp_encode_bad` 10 → `bbp_code_trick` 20 → `bbp_filter_kses` 30 → `balanceTags` 40), with
  request-accurate slashing (`wp_unslash( filter( wp_slash( $payload ) ) )`, modelling
  `$_POST` → `wp_insert_post`), then the front-end display chain `bbp_get_reply_content`
  (`wptexturize` → `convert_chars` → `capital_P_dangit` → `convert_smilies` →
  `force_balance_tags` → `bbp_make_clickable` → `wpautop` → `bbp_rel_nofollow`).

## Hypotheses tested and rejected

### 1. bbPress has **no display-time kses on the front end**

```php
if ( is_admin() ) {
    add_filter( 'bbp_get_reply_content', 'bbp_kses_data' );   // admin only
    add_filter( 'bbp_get_topic_content', 'bbp_kses_data' );
} else { /* responsive images only — no kses */ }
```

So the front end depends entirely on save-time kses. That would be exploitable if a display-time
transform could *build markup out of sanitized text* — and the chain does exactly that:
`bbp_make_clickable` turns bare URLs into `<a href="…">` and `convert_smilies` turns `:)` into
`<img>`. Tested with URLs carrying quote/entity/backtick/space breakouts
(`http://example.com/"onmouseover="alert(1)`, `www.`, `mailto:` variants, `&quot;`-encoded, …).
`wptexturize` runs **before** `bbp_make_clickable` and converts the quotes to `&#8221;`/`&#8217;`,
so the generated `href` never contains a raw quote. All inert. The save-time kses is also added
**unconditionally** (not capability-gated), so it applies to every role.

### 2. kses-then-`stripslashes` ordering in BuddyPress activity

`bp_activity_filter_kses` runs at priority **1** and `stripslashes_deep` at priority **5** on
display — the classic "sanitize first, unescape after" bypass shape. Tested backslash-hidden
protocols (`java\script:`, `\j\a\v\a…`, `javascript\:`, `vb\script:`, `dat\a:`) and
backslash-split event handlers. `wp_kses_bad_protocol` normalises through the backslashes and
strips the protocol before `stripslashes_deep` ever runs. All inert.

### 3. `data-*` attributes that survive kses and are consumed by BuddyPress's own JS

This is the pattern behind the confirmed WordPress Interactivity finding, so it was checked
directly. `bp_get_allowedtags()` permits `a[data-bp-tooltip]` and `span[data-livestamp]`:

* `data-bp-tooltip` is consumed **only by CSS** (`content: attr(data-bp-tooltip)`) — not a script
  sink.
* `data-livestamp` is consumed by `livestamp.js`, which passes the value to `moment()` and then
  writes `$this.html( data.moment.fromNow() )` — the string written is moment's own formatted
  output, never the attribute value. Non-moment values fail
  `moment.isMoment(...) && !isNaN(+timestamp)` and are dropped.

### 4. Attribute-context breakout (kses passes tag-free text)

kses sanitises *markup*, so `x" onmouseover=alert(1) z="` passes it as harmless text and is only
dangerous if something later drops it into an HTML attribute. Confirmed that WordPress stores a
`display_name` with **raw quotes intact** (`pre_user_display_name` ends in `_wp_specialchars`
with `ENT_NOQUOTES`), then checked every attribute sink:

| sink | result |
|---|---|
| bbPress `title="…"` (user-details.php) via `bbp_displayed_user_field('display_name')` | `&quot;` — safe; `bbp_sanitize_displayed_user_field` maps name fields to `esc_html` (display) / `esc_attr` (edit) |
| bbPress `value="…"` first_name / nickname edit fields | `&quot;` — safe |
| bbPress anonymous author name / topic title form values | escaped |
| BuddyPress member display name in `title="…"` | `&quot;` — safe |
| BuddyPress xProfile edit form `<input value="…">` | safe — `bp_get_form_field_attributes()` applies `esc_attr()` to every value and `sanitize_key()` to every name |

## Hardening observations (not vulnerabilities)

* `xprofile_get_field_data()` and `bp_get_the_profile_field_value()` return values that are
  kses-filtered but **not attribute-safe** — a stored `x" onmouseover=…` comes back with the
  quote intact. Every first-party sink uses them in HTML *content* context or escapes them, so
  BuddyPress itself is fine; but a theme or third-party plugin placing them in an attribute would
  have XSS. Worth an `esc_attr()` at the sink or a documented contract.
* bbPress's front end has no display-time kses (above). It holds today because save-time kses is
  unconditional, but it means any future write path that bypasses
  `bbp_*_pre_content` renders unsanitised.

## Two false positives caught (methodology)

Recording these because they would each have been a bogus report:

1. **Inactive component.** The first run showed every `message__*` payload passing through
   completely unfiltered (`<script>`, `<svg onload>`, `<iframe srcdoc>` verbatim) — which looks
   like a critical unsanitised sink. It was a lab artifact: the BuddyPress **messages component
   was not activated**, so its filters were never registered. After activating it
   (`has_filter('messages_message_content_before_save')` → YES) every payload was correctly
   sanitised.
2. **Regex vs. browser.** A naive `on[a-z]+\s*=` detector flagged 9 outputs such as
   `aria-label="x&quot; onmouseover=alert(1) y=&quot;"`. The quotes are entity-encoded, so the
   whole thing is the attribute *value* and renders as inert text. The browser oracle returned
   0 executions, which is the authoritative result.

## Conclusion

Across forum posts, activity, group name/description, private messages and profile fields, both
plugins sanitise user-generated content correctly on the paths a low-privilege member can reach.
75 rendered cases, 0 executions in a real browser. No stored XSS to report.
