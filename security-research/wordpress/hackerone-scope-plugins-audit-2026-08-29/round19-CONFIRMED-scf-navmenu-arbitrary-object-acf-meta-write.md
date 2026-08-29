# Round 19: CONFIRMED — Secure Custom Fields, arbitrary-object ACF meta
# write via `menu-item-acf`, wrong-nonce accepted (Missing Authorization /
# broken access control), dynamically reproduced with a real bypass +
# negative control

Found by reading SCF's own recent security-hardening commit `64a2287` ("Hardening and
code-quality improvements across fields, REST, and abilities") — the same technique that
surfaced round 15/16's leads: when a maintainer just finished hardening several related-but-
distinct code paths against the same bug class (here: "a form-save handler writing `$_POST['acf']`
data without checking the requester is actually allowed to touch the target object"), the paths
they *didn't* touch are the first place to look for an unfixed sibling.

## What `64a2287` fixed (for context) and what it missed

That commit added `is_admin() && current_user_can('edit_shop_orders') && acf_verify_nonce('post')`
to `includes/forms/WC_Order.php`'s `save_order()`, which is hooked to WooCommerce's
`woocommerce_update_order` action and, before the fix, called
`acf_save_post('woo_order_' . $order_id)` completely unconditionally — no nonce, no capability
check, no admin-context check. The commit message frames this correctly as a real gap. But
`WC_Order::save_order()` is only one of many "form save" handlers in `includes/forms/` that funnel
`$_POST` data into ACF's central `acf_save_post( $post_id, $values )` — and one of the others has
a structurally different, unfixed version of the same class of bug.

## Root cause: `SCF_Form_Nav_Menu::update_nav_menu_items()` trusts attacker-controlled IDs

`includes/forms/form-nav-menu.php`:

```php
function update_nav_menu( $menu_id ) {                 // line 136
    $post_id = 'term_' . $menu_id;
    if ( ! acf_verify_nonce( 'nav_menu' ) ) {
        return $menu_id;
    }
    acf_validate_save_post( true );
    acf_save_post( $post_id );                          // fine: $post_id is the menu itself
    $this->update_nav_menu_items( $menu_id );            // <-- called unconditionally after the gate
}

function update_nav_menu_items( $menu_id ) {            // line 167
    if ( empty( $_POST['menu-item-acf'] ) ) {
        return;
    }
    $posted_values = acf_sanitize_request_args( $_POST['menu-item-acf'] );
    foreach ( $posted_values as $post_id => $values ) {  // $post_id is an ATTACKER-CHOSEN ARRAY KEY
        acf_save_post( $post_id, $values );              // no per-target check of any kind
    }
}
```

`update_nav_menu_items()` is only reached after `acf_verify_nonce( 'nav_menu' )` passes, so on its
face it looks gated the same way every other form handler is. The difference is what it does once
inside: every *other* handler in `includes/forms/` (`form-post.php`, `form-user.php`,
`form-comment.php`, `form-taxonomy.php`, `form-widget.php`, `form-attachment.php`) receives a
single `$post_id`/`$user_id`/`$comment_id` as a **parameter from the WordPress core action that
invoked it** (`save_post`, `profile_update`, `edit_comment`, `edit_term`, ...) — a value WordPress
core already resolved and implicitly authorized before firing that action. `update_nav_menu_items()`
is the only one that instead iterates the **keys of an attacker-controlled POST array**
(`$_POST['menu-item-acf']`) and treats each key as a save target, with no relationship to which
menu items are actually being saved and no re-check of whether the current user may touch that
specific target.

`acf_save_post()` itself (`includes/acf-form-functions.php:119`) and the `_acf_do_save_post()` it
triggers add no authorization of their own — they've always relied entirely on the caller having
already verified the *right* nonce for the *right* object. That assumption is what
`update_nav_menu_items()` breaks: it lets a single `'nav_menu'`-scoped nonce (obtained from loading
the ordinary "Appearance → Menus" screen) authorize a `$_POST` array entry addressed at **any of
ACF's other pseudo-ID save targets** — `user_<id>`, a raw post ID, `term_<id>`, `comment_<id>`,
`widget_<id>`, `options`, or (per `WC_Order.php`'s own registration) `woo_order_<id>` — each of which
has its *own*, differently-scoped nonce action (`'user'`, `'post'`, `'term'`... ) that this path
never checks.

## Dynamic confirmation (real WordPress hook, real nonce, negative control)

Simulated exactly what `wp-admin/nav-menus.php` sends when an Administrator clicks "Save Menu" —
a valid `'nav_menu'`-nonce plus the `menu-item-acf` array WordPress core's own menu-item form
fields sit alongside — with one extra, attacker-added entry targeting **a different user's ACF
field**, then fired the real `wp_update_nav_menu` action SCF hooks (this is the same action
`wp-admin/nav-menus.php` fires at the end of every ordinary menu save; invoking it directly with
realistic `$_POST` state exercises the exact vulnerable code path a crafted/extra form field in a
real browser POST would):

```
Acting as: admin (id=1)
BEFORE attack: secret_user_note for user 5 = NULL

$_POST['_acf_nonce']    = wp_create_nonce('nav_menu');
$_POST['menu-item-acf'] = [ 'user_5' => [ 'field_navmenu_idor_usertext' => 'INJECTED_VIA_NAVMENU_...' ] ];
do_action( 'wp_update_nav_menu', $menu_id );

AFTER attack: secret_user_note for user 5 = 'INJECTED_VIA_NAVMENU_1788004767'
```

**Negative control** — proving this isn't just "any nonce works everywhere": the legitimate save
path for that exact same field, `form-user.php`'s `save_user()`, calls
`acf_verify_nonce( 'user' )`. Checked that call directly with the *same* `'nav_menu'` nonce used
above:

```
form-user.php's own acf_verify_nonce('user') check, using a 'nav_menu' nonce: false (expected false)
```

The object-specific gate correctly rejects the wrong-scoped nonce when checked directly — the bug
is specifically that `update_nav_menu_items()` never performs that check at all for its targets.

**Breadth check** — repeated against a raw post ID (not a pseudo-ID) to confirm this isn't
user-field-specific:

```
BEFORE: injected_post_note on post 98 = NULL
$_POST['menu-item-acf'] = [ 98 => [ 'field_navmenu_idor_posttext' => 'INJECTED_POST_VIA_NAVMENU' ] ];
do_action( 'wp_update_nav_menu', $menu_id );
AFTER:  injected_post_note on post 98 = 'INJECTED_POST_VIA_NAVMENU'
```

Post 98 has no relationship to the nav menu being saved and belongs to a different post-editing
context entirely — same result.

## Impact and honest severity reasoning

This is Missing Authorization (CWE-862) / IDOR: the code checks *a* valid nonce, but not the
*correct, object-scoped* one, and never checks a target-specific capability
(`current_user_can('edit_post', $id)`, `current_user_can('edit_user', $id)`,
`current_user_can('edit_shop_orders')`, etc.) before writing. The write primitive is real ACF field
data — not just an existence/ordering leak like round 18's finding — landing in postmeta/usermeta/
termmeta for an object the requester did not go through the intended, capability-checked screen for.

Reachability requires holding a **valid `'nav_menu'`-action nonce**, which in turn requires access
to `wp-admin/nav-menus.php` — gated on WordPress's `edit_theme_options` capability. In a **default**
WordPress install only the Administrator role holds that capability, and an Administrator can
already reach most of these same objects through their own dedicated screens, which limits the
severity under a strict default-configuration reading. Two things push this above that narrow
reading, though:

1. **It concretely bypasses a fix `64a2287` just added for a specific, sensitive object type.**
   That commit added `current_user_can('edit_shop_orders')` + a `'post'`-scoped nonce specifically
   because writing arbitrary ACF data onto a WooCommerce order without those checks was judged
   worth fixing. `update_nav_menu_items()` reaches the exact same `'woo_order_<id>'` pseudo-ID
   (verified by code reading against `WC_Order.php`'s registration — not independently
   re-verified dynamically in this environment, since WooCommerce isn't installed on this
   throwaway install) via a completely different call path that checks neither of those things —
   only the unrelated `'nav_menu'` nonce. The vendor's own threat model treats unauthorized writes
   to this object type as worth a dedicated fix; this path reopens exactly that gap.
2. **`edit_theme_options` is commonly delegated to non-Administrator roles in real deployments** —
   "menu manager" / "site builder" custom roles (via role-editor plugins, a very common WordPress
   customization pattern) routinely grant `edit_theme_options` without granting broad `edit_posts`/
   `edit_users`/WooCommerce capabilities, specifically so a marketing or content-ops person can
   manage navigation without touching everything else. For any such role, this is a genuine
   privilege escalation: the ability to write arbitrary ACF field values onto **any post, any
   user's profile, any taxonomy term, any comment, any widget, any WooCommerce order, and the
   site's global ACF options** that they otherwise have no edit rights to at all.

### Severity ceiling check: does not reach High (verified, not assumed)

Checked explicitly whether this could be argued past Medium into High (CVSS 3.1 High band is
7.0–8.9; this sits at `AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N` ≈ **4.9**) by attacking the three
things that would actually move the score, rather than reaching for the `woo_order_<id>` angle or
the "admin-only by default" framing as if either changed the arithmetic (they don't: `I:H` is
already the ceiling for the Integrity metric — the write already reaches every ACF pseudo-ID target,
so "and orders too" doesn't push it further; and `PR` is unaffected by *which* object the write
lands on, only by *what's needed to trigger it at all*):

- **Can `PR` drop below High?** Traced every real caller of `wp_update_nav_menu_object()` (the
  function backing the `wp_update_nav_menu` action this bug hooks) in WordPress Core:
  `wp-admin/nav-menus.php` (explicit `current_user_can('edit_theme_options')`), the REST API's
  `WP_REST_Menus_Controller` (inherits `WP_REST_Terms_Controller::update_item_permissions_check()`,
  which checks `current_user_can('edit_term', ...)` — and the `nav_menu` taxonomy hardcodes
  `edit_terms`/`manage_terms`/`assign_terms`/`delete_terms` all to `'edit_theme_options'` at
  registration, `wp-includes/taxonomy.php:124-129`, not filterable by a lower-privilege site
  config), and the Customizer's `WP_Customize_Nav_Menu_Setting` (gated by the `'customize'` meta
  capability, which `map_meta_cap()` maps unconditionally to `edit_theme_options`,
  `wp-includes/capabilities.php:698-700`). All three independent paths land on the same capability.
  No fourth path exists in Core. **`PR:H` stands.**
- **Is there a companion confidentiality-read primitive (`C:N` → `C:H`)?** No — this is a write-only
  sink (`update_nav_menu_items()` → `acf_save_post()`) with no response body that returns target
  data to the requester. Nothing in this code path discloses the value it wrote or any other data
  about the target object.
- **Is there a scope change?** No — the write still lands inside the same WordPress install's own
  postmeta/usermeta/termmeta via `acf_save_post()`; no different security authority is crossed.

None of the three moved. Reporting this as capped at Medium (~4.9) on the evidence actually
demonstrated, not reaching for `woo_order_<id>` reachability or the admin-only reachability angle
as if either were score-moving — they aren't. Those two points remain valid *context* for why this
is worth fixing (a deliberate, recent guard has a second, open door; the capability gating it is
commonly delegated in real deployments) without inflating the number.

Rating this **Medium** on that basis: real, dynamically-confirmed Missing Authorization with a
concrete arbitrary-write primitive and a demonstrated bypass of an intentional, recently-added
guard on a sensitive object type, whose practical blast radius depends on `edit_theme_options`
being held by a non-full-Administrator role — a realistic, common, but non-default configuration.
Not claiming High/Critical: default single-Administrator installs see limited incremental impact
since the only role that can reach it already has broad access to most of the affected objects.

## Fix suggestion

`update_nav_menu_items()` should validate each `$post_id` key against what is actually being saved
for this menu (e.g., cross-check against the menu-item IDs WordPress core itself just
processed/returned for this `$menu_id`) and, at minimum, call the object-appropriate capability
check (`current_user_can( 'edit_post', $post_id )`, or the equivalent decode-then-check for each
pseudo-ID prefix) before calling `acf_save_post()` — mirroring what `WC_Order.php` now does for
orders, applied consistently to every pseudo-ID `acf_save_post()` accepts.

## Reproduction artifacts

- `tooling/setup_navmenu_idor.php` — fixture (user-scoped + post-scoped ACF field groups, target
  user/post/menu IDs).
- `tooling/exploit_navmenu_idor.php` — the user-field bypass + negative control shown above.
- `tooling/exploit_navmenu_idor_breadth.php` — the raw-post-ID breadth check.

## Scope note

Reachable via Secure Custom Fields' own `wp_update_nav_menu` hook (`includes/forms/form-nav-menu.php`)
— no WordPress Core or other in-scope plugin involved. In scope for the program's Secure Custom
Fields plugin coverage.
