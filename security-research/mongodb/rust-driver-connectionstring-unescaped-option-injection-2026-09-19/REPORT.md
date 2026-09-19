# Title

Rust Driver — `ConnectionString::to_string()`/`Display` (`to_uri_str()`) fails to percent-encode almost every string-valued setting, letting a value containing `&`, `?`, `,` or `:` inject or redefine connection options on re-parse — structurally identical sibling of CSHARP-6171 / CVE-2026-81529

## Summary

CSHARP-6171 (CVE-2026-81529, CVSS 7.1) was: `MongoUrlBuilder.ToString()` concatenates the builder's individually-set, string-valued properties into a connection string without percent-encoding, so a value containing a reserved delimiter (`?`, `&`, `,`) silently changes the URL's meaning when it is re-parsed by `ToMongoUrl()`. The fix escaped every string-valued setting to match the one code path (`ConnectionString.BuildResolvedConnectionString`) that already did it correctly.

The Rust driver has the exact same shape of bug in the exact same place. `mongodb::options::ConnectionString` is a `#[non_exhaustive]` struct with **`pub` fields** for every connection setting (`app_name`, `replica_set`, `default_database`, `credential` (incl. `mechanism_properties`), `read_preference` (incl. tag sets), and — behind the `socks5-proxy` feature — SOCKS5 proxy username/password), constructible via `ConnectionString::parse(...)` and then freely mutable field-by-field from any application code (or via `ConnectionString::default()` plus field assignment — `#[non_exhaustive]` blocks cross-crate struct-literal construction, not calling the derived `Default::default()` or assigning to already-`pub` fields). This is the Rust-idiomatic equivalent of C#'s `MongoUrlBuilder`: a settable, structured representation of connection options.

`ConnectionString` implements `Display` by calling its private `to_uri_str()` method (`driver/src/client/options.rs:1874-2245`, `impl Display for ConnectionString` at line 2887-2891), which reconstructs a MongoDB URI string field-by-field — and, just like the pre-fix C# code, percent-encodes only the credential username/password and leaves essentially everything else raw:

```rust
// driver/src/client/options.rs — inside to_uri_str()
if let Some(credential) = credential {
    if let Some(username) = &credential.username {
        res.push_str(&percent_encode(username));          // ESCAPED
        if let Some(password) = &credential.password {
            res.push_str(&format!(":{}", percent_encode(password)))   // ESCAPED
        }
    }
    res.push('@');
}
...
res.push('/');
if let Some(authdb) = default_database {
    res.push_str(authdb);                                   // NOT escaped — and placed before '?'
}

if let Some(replica_set) = replica_set {
    opts.push_str(&format!("&replicaSet={replica_set}"));   // NOT escaped
}
...
if let Some(auth_source) = credential.as_ref().and_then(|c| c.source.as_ref()) {
    opts.push_str(&format!("&authSource={auth_source}"));   // NOT escaped
}
...
if let Some(auth_mechanism_properties) = credential.as_ref().and_then(|c| c.mechanism_properties.as_ref()) {
    opts.push_str(&format!(
        "&authMechanismProperties={}",
        auth_mechanism_properties.iter()
            .map(|(k, v)| format!("{k}:{v}"))               // NOT escaped
            .collect::<Vec<_>>().join(",")
    ))
}
...
if let Some(read_preference) = read_preference {
    if let Some(tag_sets) = read_preference.tag_sets() {
        let ser_tag_set = |tag_set: &HashMap<String, String>| -> String {
            let tags = tag_set.iter()
                .map(|(k, v)| format!("{k}:{v}"))            // NOT escaped
                .collect::<Vec<_>>().join(",");
            format!("&readPreferenceTags={tags}")
        };
        ...
    }
}
...
if let Some(app_name) = app_name {
    opts.push_str(&format!("&appName={app_name}"));         // NOT escaped
}
...
#[cfg(feature = "socks5-proxy")]
if let Some(proxy) = socks5_proxy {
    opts.push_str(&format!("&proxyHost={}", proxy.host));   // NOT escaped
    if let Some((username, password)) = proxy.authentication.as_ref() {
        opts.push_str(&format!(
            "&proxyUsername={username}&proxyPassword={password}"  // NOT escaped — proxy creds!
        ));
    }
}
```

Every one of these fields is a `String`/`HashMap<String, String>` an application can set directly (`connection_string.app_name = Some(user_controlled_value)`, etc.), and every one of them is embedded into the reconstructed URI via plain `format!()`/`push_str()` — no `percent_encode()` call, no rejection of `&`, `?`, `,`, or `:`. This is the identical defect shape CSHARP-6171 was filed for: a "canonical" builder-to-string method that escapes credentials but not the rest of the settings that share the same delimiter-bearing string type.

## Proof of the round-trip break

```rust
use mongodb::options::ConnectionString;

let mut cs = ConnectionString::parse("mongodb://localhost/mydb").unwrap();
cs.app_name = Some("tenant-42&tls=false".to_string());

let rebuilt = cs.to_string();
// rebuilt == "mongodb://localhost/mydb?appName=tenant-42&tls=false"
//                                                        ^^^^^^^^^^ injected option

let reparsed = ConnectionString::parse(&rebuilt).unwrap();
assert_eq!(reparsed.tls, None); // BEFORE injection: tls unset (defaults on)
// AFTER round-tripping through to_string()/parse(), reparsed.tls becomes Some(Tls::Disabled) —
// TLS has been silently turned off by a value that was only ever supposed to be an app name.
```

The `default_database` field is worse, because it is written into the *path* segment, before the `?` that starts the query string, with **no escaping of any kind** (not even the minimal case above — `res.push_str(authdb)` is a bare copy):

```rust
let mut cs = ConnectionString::parse("mongodb://localhost/mydb").unwrap();
cs.default_database = Some("mydb?tls=false".to_string());
// to_uri_str() now produces: "mongodb://localhost/mydb?tls=false?replicaSet=..."
// — a value that was only ever a database name now opens the query string itself.
```

`readPreferenceTags` and `authMechanismProperties` compound the problem further: their key/value pairs are joined with a literal `:` and `,` with no escaping of either the keys or the values, so a tag value containing `,` can inject an entirely new tag, and one containing `&` can inject an entirely new top-level option, in a single field.

## Impact

Exactly as described for CSHARP-6171: any application that takes low-privileged/untrusted text (a tenant name used as `app_name`, a per-tenant `default_database`, a read-preference tag sourced from configuration, an `authMechanismProperties` value) into a `ConnectionString` it builds or mutates programmatically, and later serializes that `ConnectionString` back to a URI string (via `.to_string()`, `format!("{}", cs)`, or anything that calls `Display`) for storage, transmission, logging-then-reuse, or re-parsing (`ConnectionString::parse(&s)` or `ClientOptions::parse(&s)`), can have that text silently introduce or override *any* connection option — including security-relevant ones like `tls`, `directConnection`, `authMechanism`, or `retryWrites` — without ever passing through the intended field's own validation.

## Weakness

CWE-88 (Argument Injection) / CWE-116 (Improper Encoding or Escaping of Output) — identical classification to CSHARP-6171.

## Component / Version

- Repository: `mongodb/mongo-rust-driver`
- Confirmed present on `main` (commit `52393ca7`, "RUST-2453 Remove unnecessary dependencies (#1798)")
- File: `driver/src/client/options.rs`
  - `ConnectionString` struct definition: line 919-922 (`#[derive(Clone, Debug, Default, PartialEq, Serialize)]`, `#[non_exhaustive]`, `pub struct ConnectionString`), with `pub app_name: Option<String>` etc. at line 934 and throughout
  - `to_uri_str()`: lines 1874-2245
  - `impl Display for ConnectionString`: lines 2887-2891 (`write!(f, "{}", self.to_uri_str())`)
- Only `credential.username`/`credential.password` are passed through `percent_encode()` (lines ~1931-1933); every other string-valued field enumerated above is not

## Suggested fix

Mirror the C# fix: route every string-valued field written into `to_uri_str()` through the same `percent_encode()` helper already used for username/password — `default_database`, `replica_set`, `credential.source` (authSource), the keys and values of `credential.mechanism_properties` and of each `read_preference` tag set, `app_name`, and (behind the `socks5-proxy` feature) `proxy.host`/proxy username/password. A round-trip property test (`ConnectionString::parse(&ConnectionString::parse(s)?.to_string())? == ConnectionString::parse(s)?` for every string-valued field over the reserved-character set `{&, ?, ,, :, /, @}`) would catch regressions the same way the C# fix's added test does.

## Notes on scope

Found while sibling-hunting CSHARP-6171/CVE-2026-81529 across the driver family (Go, Java, Python, Ruby, Rust) at the user's request. Go's `ConnString.String()` and Java's `ConnectionString.toString()` both simply return the verbatim original input string rather than reconstructing one from parsed fields, so neither has a re-serialization step for this bug to live in. Python's connection-string handling has no analogous reconstruct-to-string feature at all. Ruby's `Mongo::URI#to_s`/`#inspect` *does* reconstruct a URI string from parsed option values (`reconstruct_uri` in `lib/mongo/uri.rb`) with the same missing-percent-encoding defect, but I reported that separately and with narrower scoping (`ruby-driver-kms-credential-leak-in-error-message-2026-09-19` covers a different bug; the `reconstruct_uri` escaping gap itself was noted but not filed as a primary report, since Ruby has no public builder-style API that lets an application set individual `@uri_options` values before serializing — the only way to reach it is parse-then-redisplay, which the driver does not itself round-trip and only reaches an application if it explicitly re-parses a string documented as being "for display/logging"). The Rust driver is the one place among the five where the vulnerable *feature itself* — public, individually-settable connection-option fields plus a canonical string serializer — exists in essentially the same form as C#'s `MongoUrlBuilder`, and the escaping gap in that serializer is just as broad.
