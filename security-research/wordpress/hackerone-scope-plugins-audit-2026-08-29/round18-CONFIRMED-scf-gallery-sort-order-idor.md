# Round 18: CONFIRMED — Secure Custom Fields, `ajax_get_sort_order` missing
# per-attachment access check (IDOR / broken access control), dynamically
# reproduced with a real cross-privilege HTTP request and a negative control

> **STATUS CORRECTION (see README's "Scope correction #3"): this finding is real and correctly
> root-caused, but it is self-rated Low severity below — existence + relative-ordering disclosure
> only, no content/metadata. The standing bar for this audit is now Medium-and-above. This is NOT
> a reportable finding under that bar and is not being submitted. Kept as-is for the historical
> record of what was actually verified.**

Follows up round 17's static-read finding on `ACF_Field_Gallery::ajax_get_sort_order()` — this
round builds the fixture needed to reproduce it over real HTTP and confirms it.

## Setup

- A gallery field (`field_idor_test_gallery2`, field group `group_idor_gallery_test2`) attached to
  `post_type == post`, created via `acf_import_field_group()` (SCF's own API, not a hand-rolled
  DB row, to guarantee the fixture matches the real runtime shape ACF expects).
- An **Administrator**-owned post, `post_status = 'private'` (ID 98), with a real attachment
  (`idor-secret-image.png`, ID 99) attached to it via `wp_insert_attachment()`.
- A real **Contributor** account (`sec_research_contributor`, role `contributor` — cannot read or
  edit other users' posts, especially not an Administrator's `private` post) with its own, unrelated
  draft post (ID 100).
- Logged in as the Contributor via a real `wp-login.php` POST (cookie auth), loaded the
  Contributor's own draft-post edit screen, and scraped the gallery field's own
  `data-nonce="9c8b9b55a2"` attribute straight out of the rendered HTML — this is the exact nonce
  the Contributor's own browser would use for this field's AJAX calls, tied to a field/post the
  Contributor legitimately owns and can access.

## The request (real HTTP, Contributor session, admin's private-post attachment as target)

```
POST /wp-admin/admin-ajax.php
Cookie: <contributor session>
action=acf/fields/gallery/get_sort_order
field_key=field_idor_test_gallery2   (the Contributor's OWN field/post)
nonce=9c8b9b55a2                     (the Contributor's OWN nonce for that field)
sort=date
ids[]=99        <- Administrator's PRIVATE post's attachment (not the Contributor's)
ids[]=1
ids[]=999999    <- doesn't exist

→ HTTP 200  {"success":true,"data":[99]}
```

The Contributor's own, legitimately-obtained nonce for their own gallery field was accepted to
query sort-order data for an attachment belonging to a completely unrelated `private` post they
have no read or edit access to, and the server confirmed it exists (returned `99`) while correctly
filtering out the non-attachment/non-existent IDs (`1`, `999999`).

## Negative control: the properly-gated sibling in the same file blocks the identical request

```
POST /wp-admin/admin-ajax.php
Cookie: <same contributor session>
action=acf/fields/gallery/get_attachment
field_key=field_idor_test_gallery2
nonce=9c8b9b55a2
id=99

→ HTTP 200, empty body (wp_die() with no output — request denied)
```

`ajax_get_attachment()` — in the same class, using the exact same nonce/field-key pair — correctly
calls `current_user_can( 'read_post', $attachment->ID )` (falling back to the parent post's
visibility) and denies the Contributor. This is the fix from round 6 / commit `7b08cac`, reconfirmed
still working. The contrast is the point: two sibling AJAX handlers gated by the *identical*
nonce/field-key check, one enforces object-level authorization on top of it and one doesn't.

## Root cause

`includes/fields/class-acf-field-gallery.php`, `ajax_get_sort_order()`:

```php
if ( ! acf_verify_ajax( $args['nonce'], $args['field_key'], true, 'gallery' ) ) {
    wp_send_json_error();
}
// ... no current_user_can() check of any kind before this point ...
$ids = get_posts( array(
    'post_type'   => 'attachment',
    'numberposts' => -1,
    'post_status' => 'any',        // matches private/inherited-from-any-post attachments too
    'post__in'    => $args['ids'], // fully attacker-controlled
    'order'       => $order,
    'orderby'     => $args['sort'],
    'fields'      => 'ids',
) );
```

`acf_verify_ajax( $nonce, $field_key, true, 'gallery' )` only proves the requester holds a valid
nonce for *some* gallery field they have legitimate access to (their own field key or post) — it
says nothing about which attachment IDs they're allowed to ask about. Because nonces are per-user
CSRF tokens, not object-level permission grants, a nonce minted for the Contributor's own,
completely unrelated gallery field satisfies this check for a request about *any* attachment ID
site-wide. Neither `field_key` nor the field's own configuration is used to scope which attachments
the query is allowed to touch, and `post_status => 'any'` means no post-visibility filtering happens
either. Compare directly to `ajax_get_attachment()` (line ~134) and `ajax_update_attachment()`
(line ~175 — `current_user_can( 'edit_post', $id )` per attachment inside its loop) in the exact
same file, which both add the missing object-level check on top of the same nonce/field-key gate.

## Impact

This is Missing Authorization / IDOR (CWE-639, CWE-862) — a real, reproducible access-control gap,
not a theoretical one. The disclosed information is narrow: the response is only the filtered,
reordered list of `ids` that exist as `attachment`-type posts (any status) — no title, filename,
URL, byte content, or other metadata. Chained impact is still real, if modest: it gives any
authenticated user with access to *any* single gallery field (a very low bar — one draft post with
a gallery field they own is enough) an oracle to (a) enumerate which numeric post IDs across the
entire site are attachments regardless of the visibility of the post they belong to, and (b) recover
the *relative* creation-date or title ordering of an arbitrary attacker-chosen set of those IDs —
i.e., a timing/ordering side-channel on private content's attachment metadata that the plugin's own
sibling functions are explicit about not allowing. Rating this honestly as **Low severity** (no
content/PII disclosed, requires an authenticated account with at least one accessible gallery field,
authorization bypass is real but the leak itself is thin) rather than inflating it — this is the
in-scope, reproducible bug the audit found this round, reported at the severity the evidence
actually supports.

## Fix suggestion

Add the same object-level check present in `ajax_get_attachment()`/`ajax_update_attachment()`
before querying: for each ID in `$args['ids']`, drop it from the query (or the result) unless
`current_user_can( 'read_post', $id )` (or the inherited-attachment parent-post visibility check
`ajax_get_attachment()` already implements) passes for the current user.

## Reproduction artifacts

- `tooling/setup_gallery_idor_test2.php` — fixture setup (field group via `acf_import_field_group()`,
  admin private post + attachment, contributor account + own draft post).
- `tooling/gallery_sort_order_idor_poc.sh` — the two curl requests above (vulnerable call +
  negative control) against the live throwaway install.

## Scope note

Reachable via Secure Custom Fields' own `admin-ajax.php` action (`acf/fields/gallery/get_sort_order`)
— no WordPress Core or other in-scope plugin involved. In scope for the program's Secure Custom
Fields plugin coverage.
