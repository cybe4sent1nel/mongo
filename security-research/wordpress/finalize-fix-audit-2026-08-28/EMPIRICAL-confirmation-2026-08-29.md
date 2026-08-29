# Empirical confirmation: the finalize_item() provenance fix holds on a live install

Follow-up to `README.md` in this directory, which concluded from source reading alone that the
`validate_sub_size_provenance()` fix (commit `1c3261dca3`) closes both HackerOne #3931771 (stored
XSS) and #3931777 (arbitrary file deletion). This round stood up a real WordPress 7.1 install (see
`../vaultpress-remote-endpoint-2026-08-28/EMPIRICAL-confirmation-2026-08-29.md` for the same
install) and replayed both original exploit payloads against it, with an Author-level account
created the same way both HackerOne reports assumed (lowest role holding `upload_files`).

## Test 1 — original XSS payload (#3931771), replayed directly against `finalize_item()`

`POST /?rest_route=/wp/v2/media/9/finalize` as `author1`, with the exact `sub_sizes[0].file` payload
from the original report (`a.jpg' /><svg onload='document.title=1'></svg><b x='`), sent with no
prior `sideload_item()` call — i.e. the original attack shape, calling `finalize` standalone.

Result: `HTTP 400`, `{"code":"rest_invalid_sub_size_file","message":"Invalid sub-size file name. File names must have been produced by a prior sideload for this attachment."}`

## Test 2 — original file-deletion payload (#3931777), replayed directly

Same attachment, `sub_sizes[0].file = "wp-config.php"` (the exact value from the original report's
reproduction steps).

Result: identical `400 rest_invalid_sub_size_file` rejection.

## Test 3 — control: a legitimately-sideloaded name is still accepted

`POST /?rest_route=/wp/v2/media/9/sideload&image_size=thumbnail&convert_format=false` with a real
JPEG body → `200`, produced `zap-thumb.jpg`. Immediately followed by
`POST /?rest_route=/wp/v2/media/9/finalize` with `sub_sizes[0].file = "zap-thumb.jpg"` (the name the
prior sideload actually produced) → `200`, metadata stored correctly.

## Test 4 — a provenance record on the attachment doesn't create a blanket bypass

Re-sent Test 1's malicious payload against the *same* attachment used in Test 3, which by this
point had one legitimately-recorded provenance entry (`zap-thumb.jpg`). Confirms the check is
per-value (the submitted name itself must match a recorded/derivable one), not "this attachment has
sideloaded something before, so anything goes":

Result: `400 rest_invalid_sub_size_file` again — unaffected by the attachment's prior legitimate
sideload.

## Conclusion

Both original exploit payloads are rejected exactly as the source-level fix predicted, and the
endpoint isn't just failing closed on everything — a real, legitimately-produced sideload name is
accepted on the same attachment in the same test run. This upgrades the earlier "read the fix and
found no bypass" conclusion to "replayed both original PoCs against a live instance and both are
blocked."
