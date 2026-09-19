# Title

Ruby Driver — raw KMS provider credentials (AWS/Azure/GCP/KMIP/local master key) are embedded verbatim in a raised `ArgumentError` message whenever CSFLE/Queryable-Encryption KMS options are misconfigured, and propagate unsanitized to application code

## Status note / scope

Found while sibling-hunting CSHARP-6164 (CVE-2026-81530, CVSS 6.8: `AutoEncryptionOptions.ToString()` in the C# driver reproduced KMS credentials verbatim in a diagnostic string) at the user's request, across every non-`libmongoc`-based driver (Go, Java, Python, Ruby — Rust has no client-side-encryption KMS credential surface of this shape to check). This is not the same code path as the C# bug (there is no `ToString()`/`inspect` involved) but is the same *class* of bug — a driver reproducing raw KMS secret material verbatim in text meant for human/diagnostic consumption — reached through a different mechanism (an exception message instead of a settings-object stringifier).

## Summary

`Mongo::Crypt::KMS::Validations#validate_param` (`lib/mongo/crypt/kms.rb`), the shared helper used by every KMS provider's credentials class (`AWS::Credentials`, `Azure::Credentials`, `GCP::Credentials`, `KMIP::Credentials`, `Local::Credentials`), raises an `ArgumentError` that interpolates the **entire raw per-provider options hash** — including any correctly-supplied secret values it contains — whenever a single required credential field is missing:

```ruby
# lib/mongo/crypt/kms.rb:53-83
def validate_param(key, opts, format_hint, required: true)
  value = opts.fetch(key)
  ...
  unless value.is_a?(String)
    raise ArgumentError.new(
      "The #{key} option must be a String with at least one character; " \
      "currently have #{value}"                                    # <-- leaks a wrongly-typed value
    )
  end
  ...
rescue KeyError
  if required
    raise ArgumentError.new(
      "The specified KMS provider options are invalid: #{opts}. " + # <-- leaks the WHOLE opts hash
      format_hint
    )
  end
end
```

`opts` here is the exact hash the application passed for one KMS provider, e.g. for AWS:

```ruby
# lib/mongo/crypt/kms/aws/credentials.rb:52-55
def initialize(opts)
  @opts = opts
  @access_key_id     = validate_param(:access_key_id, opts, FORMAT_HINT)
  @secret_access_key = validate_param(:secret_access_key, opts, FORMAT_HINT)
  ...
```

`opts.fetch(key)` raises Ruby's built-in `KeyError` when `key` is absent from the hash — which happens on an entirely ordinary, common misconfiguration: a typo'd key name (`secretAccessKey` instead of `secret_access_key`), a key supplied as the wrong-case symbol, a copy-pasted example missing a field, etc. When that happens for *any* field, the `rescue KeyError` branch fires and raises an `ArgumentError` whose message is `"The specified KMS provider options are invalid: #{opts}."` — and `opts` is the full hash, so **every other, correctly-provided field in that same hash — including real secrets — is printed in full** via `Hash#to_s`.

Concretely:

```ruby
Mongo::Client.new(
  ['localhost:27017'],
  auto_encryption_options: {
    key_vault_namespace: 'db.keyvault',
    kms_providers: {
      aws: {
        access_key_id: 'AKIAREALACCESSKEYVALUE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'  # typo: should be secret_access_key
      }
    }
  }
)
# => ArgumentError: The specified KMS provider options are invalid:
#    {:access_key_id=>"AKIAREALACCESSKEYVALUE", :secretAccessKey=>"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}.
#    AWS KMS provider options must be in the format: ...
```

Both the real access key ID and the real (mistyped-key) secret access key are now embedded verbatim in the exception's `message`. This propagates completely unhandled: `AutoEncrypter#initialize` (`lib/mongo/crypt/auto_encrypter.rb:97`) calls `Crypt::KMS::Credentials.new(@options[:kms_providers])` with no rescue/sanitization, so the raw `ArgumentError` — full credential text and all — surfaces directly out of `Mongo::Client.new(...)` to the application. This is exactly the kind of exception that ends up in application logs, error trackers (Sentry/Honeybadger/Bugsnag), CI failure output, or a support ticket / GitHub issue pasted by a developer trying to debug "why won't my encryption config validate" — the same downstream exposure vector CSHARP-6164 was rated for.

This affects **every** KMS provider type the Ruby driver supports, since all five credential classes funnel through the same helper:

| Provider | Fields that can leak this way |
|---|---|
| AWS | `access_key_id`, `secret_access_key`, `session_token` |
| Azure | `tenant_id`, `client_id`, `client_secret` |
| GCP | `email`, `private_key`, `access_token` |
| KMIP | `endpoint` (lower sensitivity) |
| Local | `key` (the raw local master key material) |

A secondary, narrower variant of the same defect is the `unless value.is_a?(String)` branch (line 63-68 in the same method), which echoes the raw (wrongly-typed) value via `"currently have #{value}"` — lower severity since it only fires on a type mismatch rather than a missing key, but the same "diagnostic text should never contain the actual secret" principle applies.

## Why this matters / comparison to CSHARP-6164

CSHARP-6164 (CVE-2026-81530) was about `AutoEncryptionOptions.ToString()` reproducing `kmsProviders` verbatim because the redaction that was correctly applied to `TlsOptions` was never extended to `KmsProviders`. This Ruby finding is the same underlying mistake — a code path whose entire purpose is to produce human-readable diagnostic text about KMS configuration, written without threading the same "treat KMS credentials as secret" discipline the driver applies elsewhere (e.g. `Mongo::Client#inspect`, `lib/mongo/client.rb:720-722`, is deliberately overridden to show only `cluster.summary` rather than the raw options hash — proving the driver team is otherwise careful about this exact class of leak, just not here).

## Other drivers checked for the same bug class (verbatim KMS credential leak in diagnostic/error text)

- **Go driver**: `AutoEncryptionOptions` (`mongo/options/autoencryptionoptions.go`) has no `String()`/`GoString()` method at all, and nothing else in the driver serializes it for diagnostics. There is no feature here to have this bug in.
- **Java driver**: `AutoEncryptionSettings.toString()` (`driver-core/.../AutoEncryptionSettings.java:573-576`) returns the literal string `"AutoEncryptionSettings{<hidden>}"` — the entire object is redacted, not just individual fields. This is the safest possible version of the pattern and has no gap to find.
- **Python driver (PyMongo)**: `AutoEncryptionOpts` (`pymongo/encryption_options.py`) defines no `__repr__`/`__str__`. `MongoClient.__repr__`/`_repr_helper()` (`pymongo/synchronous/mongo_client.py:1339-1379`) does enumerate every client option — including `auto_encryption_opts` — through `option_repr(key, value!r)`, and it explicitly special-cases `authmechanismproperties` for redaction (`common.redact_auth_mechanism_properties_for_repr`), showing the team is aware of this exact risk class. `auto_encryption_opts` has no such special case, but is currently safe only as a side effect: since `AutoEncryptionOpts` itself defines no custom `__repr__`, `value!r` falls back to Python's default opaque `<pymongo.encryption_options.AutoEncryptionOpts object at 0x...>`, which does not enumerate instance attributes. **This is safe today but fragile** — if a future PR ever adds a convenience `__repr__`/`__str__`/`dataclass` decorator to `AutoEncryptionOpts` (a very ordinary refactor for debuggability) without separately remembering to redact `kms_providers`, this exact CSHARP-6164-shaped bug reappears immediately. Not filing this half as a live vulnerability, but flagging it as worth a defensive fix (an explicit `__repr__` on `AutoEncryptionOpts` that redacts `kms_providers`, mirroring what `authmechanismproperties` already gets) so it can't regress silently.
- **Ruby driver**: vulnerable as detailed above.

## Weakness

CWE-209 (Generation of Error Message Containing Sensitive Information) / CWE-532 (Insertion of Sensitive Information into Log File) — the same category CSHARP-6164 was filed under, reached via exception-message construction instead of a settings stringifier.

## Component / Version

- Repository: `mongodb/mongo-ruby-driver`
- Confirmed present on `main` (commit `840504121...`, "Release candidate for 2.26.0")
- File: `lib/mongo/crypt/kms.rb`, `Mongo::Crypt::KMS::Validations#validate_param`, lines 53-83
- Reached from all five provider credential constructors: `lib/mongo/crypt/kms/aws/credentials.rb`, `.../azure/credentials.rb`, `.../gcp/credentials.rb`, `.../kmip/credentials.rb`, `.../local/credentials.rb`
- Unsanitized propagation path confirmed via `lib/mongo/crypt/auto_encrypter.rb:97` (`Crypt::KMS::Credentials.new(@options[:kms_providers])`, no rescue)

## Suggested fix

In `validate_param`'s `rescue KeyError` branch, report which key is missing without echoing the hash's values, e.g.:

```ruby
rescue KeyError
  if required
    raise ArgumentError.new(
      "The specified KMS provider options are missing the required '#{key}' option. " +
      format_hint
    )
  end
end
```

and in the type-mismatch branch, report the actual class rather than the value itself:

```ruby
raise ArgumentError.new(
  "The #{key} option must be a String with at least one character; " \
  "currently have a #{value.class}"
)
```

Neither change needs the raw secret value to produce a useful error message for the developer.

## Notes on scope

This was found as a byproduct of sibling-hunting two separate MongoDB driver-family CVEs at the user's request: CSHARP-6164/CVE-2026-81530 (KMS credential redaction gap, addressed here) and CDRIVER-6409/CVE-2026-84964 (OCSP responder double-free). On the second one: I confirmed there is no sibling in Java, Rust, Go, Python, or Ruby, for two different structural reasons rather than one. Java and Rust implement no client-side OCSP-responder-contacting code at all (grepped every non-test `.java`/`.rs` file for "ocsp": zero and zero matches respectively, aside from one unused rustls trait parameter `_ocsp: &[u8]` in `driver/src/runtime/tls_rustls.rs` that is never read) — both defer certificate revocation checking entirely to the JVM's own PKIX validation and to the `rustls`/`native-tls` crates, respectively, so there is no driver-authored code for this bug to live in. Go, Python, and Ruby *do* implement their own OCSP logic (`x/mongo/driver/ocsp/*.go`, `pymongo/ocsp_support.py`/`ocsp_cache.py`, `lib/mongo/socket/ocsp_verifier.rb`/`ocsp_cache.rb`), but the underlying vulnerability class — a C heap object (`OCSP_REQUEST*`) freed twice because a loop-scoped pointer variable is declared outside the loop and never reset to `NULL` after being freed — has no analog in a garbage-collected language with no manual `free()`: none of these three drivers manipulate raw OpenSSL/OCSP pointers directly (Go's `crypto/ocsp` is pure Go with no cgo; PyMongo's OCSP code operates on already-parsed `cryptography`/`pyOpenSSL` Python objects; the Ruby driver's OCSP code operates through Ruby's own `openssl` stdlib binding). There is no way for any of the three to reproduce a double-free of a native OCSP object from their own driver-level source, so I did not force a report on that axis.
