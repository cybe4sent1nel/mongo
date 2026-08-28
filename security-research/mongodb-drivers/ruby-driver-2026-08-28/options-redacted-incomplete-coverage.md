# MongoDB Ruby Driver 2.25.0 — `Options::Redacted` incomplete sensitive-field coverage leaks AWS session tokens and TLS private-key passphrases

**Severity: Medium-High — CWE-532 (Insertion of Sensitive Information into Log File) / CWE-200
(Exposure of Sensitive Information).** Live-verified against the real driver code
(`mongo-ruby-driver` commit `8222a3d20d9be66b003e9bfeb3696fa0ad77b85d`, version `2.25.0`), not a
theoretical read.

## Summary

`Mongo::Options::Redacted` (`lib/mongo/options/redacted.rb`) is the driver's own,
purpose-built mechanism for preventing exactly this class of bug — its class comment states
outright: *"Class for wrapping options that could be sensitive. When printed, the sensitive values
will be redacted."* `Mongo::Client#options` (the normal, public, documented way to introspect a
client's configuration — exactly what a developer reaches for when logging/debugging a connection
problem) returns exactly this type. Its actual redaction coverage is incomplete: it correctly
redacts `:password`/`:pwd`, but misses two other credential-shaped values that reach the same
options structure through entirely ordinary, documented connection-string syntax:

1. **AWS temporary session tokens** (`authMechanismProperties=AWS_SESSION_TOKEN:...`, the
   documented way to supply STS/temporary credentials for `MONGODB-AWS` auth) — nested inside the
   `auth_mech_properties` hash, which itself is a plain, un-wrapped `Hash`, not another
   `Options::Redacted` instance, so the outer class's per-key redaction check never reaches it.
2. **The TLS client-key passphrase** (`tlsCertificateKeyFilePassword=...`) — stored at the
   **top level** as `:ssl_key_pass_phrase`, structurally identical to `:password`/`:pwd` (a plain
   string value at the top of the same hash), simply omitted from the `SENSITIVE_OPTIONS`
   allow-list.

## Root cause

`lib/mongo/options/redacted.rb`:
```ruby
SENSITIVE_OPTIONS = %i[password
                       pwd].freeze
...
def redact(k, v, method)
  return STRING_REPLACEMENT if SENSITIVE_OPTIONS.include?(k.to_sym)
  v.public_send(method)
end
```
Two structural gaps:
- The allow-list only names `:password`/`:pwd` — `:ssl_key_pass_phrase` (from
  `lib/mongo/uri/options_mapper.rb:287`, `uri_option 'tlsCertificateKeyFilePassword',
  :ssl_key_pass_phrase`) is never checked, despite sitting at the exact same top level.
- `redact` is not recursive: when the value under a key is itself a `Hash` (as
  `:auth_mech_properties` always is — see `convert_auth_mech_props` in
  `lib/mongo/uri/options_mapper.rb:616-623`, which returns a plain `Hash` from `hash_extractor`),
  `v.public_send(method)` just calls that plain `Hash`'s own `#inspect`/`#to_s`, printing every
  key inside it — including `aws_session_token` — verbatim, with no per-key check at all.

## Live reproduction

```
$ ruby -Ilib -e '
require "mongo"
Mongo::Logger.logger.level = Logger::FATAL

uri_str = "mongodb://AKIAEXAMPLE:supersecretpw@cluster.example.com/" \
  "?authMechanism=MONGODB-AWS&authMechanismProperties=AWS_SESSION_TOKEN:FQoGZXIvYXdzEBOOM_SUPER_SECRET_SESSION_TOKEN_LEAK_ME" \
  "&connect=direct&serverSelectionTimeoutMS=1"

client = Mongo::Client.new(uri_str)
puts client.options.inspect
client.close
'
```
Output (real, from a live run against the actual `Mongo::Client` public API — nothing synthetic):
```
{"database"=>"admin", "auth_source"=>"$external", "retry_reads"=>true, "retry_writes"=>true,
 "auth_mech"=>:aws,
 "auth_mech_properties"=>{"aws_session_token"=>"FQoGZXIvYXdzEBOOM_SUPER_SECRET_SESSION_TOKEN_LEAK_ME"},
 "connect"=>:direct, "server_selection_timeout"=>0.001,
 "user"=>"AKIAEXAMPLE", "password"=><REDACTED>}
```
`password` is correctly redacted; the AWS session token sitting one level deeper is not.

Second reproduction, the TLS key passphrase (top-level, no nesting involved at all):
```
$ ruby -Ilib -e '
require "mongo"
Mongo::Logger.logger.level = Logger::FATAL
uri_str = "mongodb://user:pw@cluster.example.com/?tls=true&tlsCertificateKeyFile=/tmp/client.pem" \
  "&tlsCertificateKeyFilePassword=MyPrivateKeyPassphraseSECRET&connect=direct"
puts Mongo::URI.new(uri_str).uri_options.inspect
'
```
Output:
```
{"ssl"=>true, "ssl_cert"=>"/tmp/client.pem", "ssl_key_pass_phrase"=>"MyPrivateKeyPassphraseSECRET",
 "connect"=>:direct, "ssl_key"=>"/tmp/client.pem"}
```

Both confirmed with the real gem (`bson` 5.2.0 installed via `gem install bson`, driver loaded
directly via `-Ilib` against the checked-out `2.25.0` source, no mocking).

## Reachability

Not an automatic per-connection leak (the driver itself was not found to log `client.options` or
`auth_mech_properties` unconditionally anywhere in its own source), but reachable through entirely
ordinary developer behavior this class exists specifically to protect against: any code that logs,
inspects, or serializes `client.options` (or a `Mongo::URI` instance's `uri_options`) for debugging
— a routine, common pattern when troubleshooting connection problems, and exactly the scenario the
class's own doc comment describes handling safely. `Mongo::Client#inspect` itself is minimal
(`"#<Mongo::Client:0x... cluster=...>"`, checked directly — it does not dump `@options`), so this
requires the developer (or a wrapping tool/logging integration) to reach for `client.options`
specifically, but that is the documented, public, and idiomatic way to see a client's effective
configuration.

## Suggested fix

1. Add `:ssl_key_pass_phrase` (and any other top-level passphrase/token-shaped option keys) to
   `SENSITIVE_OPTIONS`.
2. Make `auth_mech_properties` itself an `Options::Redacted` instance (or otherwise make `redact`
   recurse into `Hash`/`Options::Redacted` values), and add the AWS/OIDC-related property names
   (`aws_session_token`, `aws_secret_access_key`, and any OIDC callback/token-bearing properties)
   to a redaction list that applies inside that nested structure — mirroring the top-level
   protection `:password`/`:pwd` already get.

## Scope note

Checked adjacent auth mechanisms for the same pattern: GSSAPI's `auth_mech_properties` entries
(`service_name`, `canonicalize_host_name`) are not secrets, and no OIDC callback/token property
name was found stored in `auth_mech_properties` in this version — the AWS session token is the
concrete instance of the nested-hash gap found and confirmed in this pass; the top-level
`ssl_key_pass_phrase` gap is independent of it and was confirmed separately.
