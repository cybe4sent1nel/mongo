# Round 24: SCF's paginated-repeater AJAX handler — tested a concrete IDOR/type-confusion
# hypothesis, confirmed not exploitable

Continuing into `pro/`/`includes/fields/class-acf-field-repeater.php` (flagged as not exhaustively
covered). `ajax_get_rows()` (`wp_ajax_acf/ajax/query_repeater`) is the AJAX action behind
paginated-repeater "load more" — a genuinely interesting candidate because it lets the client
override the field's `name` and `prefix` after the field/permission lookup ("we have to swap out
the field name with the one sent via JS, as the repeater could be inside a subfield"), which is
exactly the shape of a validate-one-thing/use-another bug.

## The hypothesis

`acf_current_user_can_edit_post( (int) $args['post_id'] )` ([`class-acf-field-repeater.php:1104`](https://github.com/WordPress/secure-custom-fields/blob/99cd25279b067f23afc93a75897739660a74da26/includes/fields/class-acf-field-repeater.php#L1104))
has an `int`-typed parameter, so the caller casts `$args['post_id']` with `(int)` before passing it.
ACF's `post_id` can legitimately be a non-numeric string — `"option"`, `"user_5"`, `"term_12"` — for
options pages, user profiles, and terms. `(int) "option"` and `(int) "user_5"` both evaluate to `0`
in PHP. The hypothesis: if this were the *only* capability gate, a request could smuggle a
non-numeric `post_id` past it (since `acf_current_user_can_edit_post(0)` checks an almost-certainly
nonexistent post) while the actual value-fetch a few lines later correctly resolves that same string
to a real user/option/term context via `acf_get_valid_post_id()` — a classic "the check parsed this
differently than the code that acts on it" gap, structurally the same shape as the disclosed
#3931777 report and the SQLite escaping bugs found in Round 22.

## Why it doesn't hold up

Traced the *other* check on the preceding line,
[`acf_current_user_can_edit_in_context()`](https://github.com/WordPress/secure-custom-fields/blob/99cd25279b067f23afc93a75897739660a74da26/includes/api/api-helpers.php#L2904),
which runs first and is required in addition (both checks must pass — this isn't an either/or).
It receives `$post_id_info = acf_decode_post_id( acf_get_valid_post_id( $args['post_id'] ) )` —
the correctly-typed decode, not the lossy `(int)` cast — and dispatches per resolved type:
`edit_post` for a post, `edit_user` for a user, `edit_term` for a term, the specific options page's
own registered capability for an option (with an extra guard that the claimed `options_page_slug`'s
own `post_id` actually matches the one resolved from the request, closing a page-slug/post-id
mismatch variant of the same idea). Since this check is comprehensive and correctly typed, and both
checks are ANDed together, the type-confused second check never gets to stand in as the sole gate —
it can only make an already-passing request additionally fail, not let a failing one through.

Also verified the value-fetch itself can't be walked outside the checked container: for the
`option` type, `acf_get_metadata()` builds the actual `wp_options` row name as
`"{$id}_{$name}"` — the resolved options-page id is always prepended to whatever `field_name` the
client supplies, so a client can only reach option rows namespaced under the *same* options page
they were just capability-checked against (e.g. `myoptionspage_anything`), never an unprefixed
core option like `siteurl` or another plugin's un-namespaced option — closing the "arbitrary option
read oracle" variant of this same hypothesis too.

## Conclusion

A real, worthwhile hypothesis to test given the code's own "swap out the field name" comment, but
it doesn't survive contact with the actual dispatch logic: `acf_current_user_can_edit_in_context()`
is the real, correctly-typed gate, the `int`-cast check is redundant rather than load-bearing, and
the options-page storage layer's id-prefixing independently closes the cross-namespace variant. No
finding here. Repeater/flexible-content fields' remaining surface (bulk row operations, the
flexible-content layout-swap AJAX action) is the next specific lead if this file group is revisited.
