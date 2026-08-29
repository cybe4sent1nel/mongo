# Round 23: closing the README's named "GEO/JSON-LD" lead — Secure Custom Fields's
# `<script type="application/ld+json">` structured-data output, checked for stored XSS

The README flagged this specific area as a concrete, plausible stored-XSS lead: `src/AI/GEO/`
builds JSON-LD (schema.org structured data) from post/ACF-field values and prints it inside a
`<script type="application/ld+json">` tag — exactly the shape where a field value containing
`</script>` could break out of the script context and execute as HTML/JS if the JSON encoding
isn't hardened for that sink. Verified against `secure-custom-fields` @ `99cd25279`.

**Result: this is a real potential vector in general, but it's already correctly defended here —
no bypass found.**

## The single, shared output site

Grepped the entire `src/AI/GEO/` tree (`GEO.php`, `Schema.php`, `SchemaData.php`,
`FieldSettings.php`, `Outputs/Posts.php`, `Outputs/Blocks.php`) for every place structured data or
raw field content reaches an `echo`/`print`/inline-script sink. There is exactly **one**:
`GEO::render_jsonld_script()`
([`GEO.php:345`](https://github.com/WordPress/secure-custom-fields/blob/99cd25279b067f23afc93a75897739660a74da26/src/AI/GEO/GEO.php#L345)),
a shared helper both `Outputs/Posts.php` and `Outputs/Blocks.php` route through — confirmed neither
file has its own separate `<script>`/`json_encode` call that might have missed the same hardening:

```php
echo "<script type=\"application/ld+json\">\n";
echo wp_json_encode( $jsonld_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_UNESCAPED_UNICODE );
echo "\n</script>\n";
```

`JSON_HEX_TAG` is the specific PHP `json_encode()` flag that converts every literal `<` and `>`
byte in the output to `<`/`>` — this is the standard, correct defense for embedding
JSON inside an HTML `<script>` element, because it makes it structurally impossible for the byte
sequence `</script` (or `<!--`, or any other tag-opening sequence) to ever appear literally in the
output, regardless of what any individual field value contains. Every other `echo` in this
subsystem (`Outputs/Posts.php`, `Outputs/Blocks.php`) is an HTML debug comment
(`<!-- SCF AI JSON-LD: ... -->`) with its interpolated value already wrapped in `esc_html()` —
confirmed each one individually.

## Why this holds regardless of field content

Traced that `$jsonld_data` is always a plain PHP array by the time it reaches this function — built
up through `Schema.php`'s property-mapping logic and `GEO::format_field_value_for_jsonld()`, which
normalizes every ACF field type's value to a plain scalar/array before it's inserted into the
structure. Since the entire array is passed through `wp_json_encode()` as a single call with
`JSON_HEX_TAG` set, there is no code path where a piece of field data reaches the output as raw,
unencoded text — the flag applies uniformly to the whole serialized result, not per-field, so
there's no field type or nesting depth that could slip through unescaped.

## Conclusion

This closes the one concrete, specifically-named lead left open from the initial SCF pass — it
does not clear the Medium+ bar for a finding, because it's correctly defended, not a live bug.
Combined with Round 22's SQLite Database Integration deep-dive, both of this audit's two
previously-named "not yet checked" leads are now closed with a real (if negative) answer rather
than left as an assumption.
