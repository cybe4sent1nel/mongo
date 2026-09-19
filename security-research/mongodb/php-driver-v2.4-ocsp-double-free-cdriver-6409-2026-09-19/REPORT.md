# Title

PHP Driver (`mongodb/mongo-php-driver`) release line `v2.4` — latest published release `2.4.1` — still vendors the pre-fix, double-free-vulnerable OCSP responder code from CDRIVER-6409 / CVE-2026-84964

## Summary

CDRIVER-6409 (CVE-2026-84964, CVSS 8.2) is a heap double-free in `mongo-c-driver`'s OpenSSL-based OCSP-responder-contacting code, `_contact_ocsp_responder()` (`src/libmongoc/src/mongoc/mongoc-openssl.c`), fixed upstream on 2026-09-04 (commit `19ee915a8599477b7eb183f59b061b51cb6542f2` on `master`, backported same day to `r1.30` as `7e4c66515a46abaf2f488ed0fe5a5c21887b6e1d` and to `r2.5` as `676d0d0fb0e7b5970a3e1cd97db9e25aa88826d9`).

The PHP driver embeds `mongo-c-driver` as a git submodule (`src/libmongoc`) rather than dynamically linking a system-installed, independently-updatable copy, so a PHP driver release "contains" whatever `libmongoc` commit its submodule pointer names at packaging time, permanently, until a new PHP driver release bumps that pointer.

I checked every currently active PHP driver release branch's submodule pin against the fix:

| PHP driver branch | Latest tag | `src/libmongoc` submodule pin | Fix present? |
|---|---|---|---|
| `v1.21` | `1.21.9` | `f64476433230847fb0f43afaeb7be048eb817f8b` | **Yes** — `req`/`host`/`path`/`port`/`ssl` are declared inside the loop body |
| `v2.4` | `2.4.1` (2026-08-27) | `9dbd6910091dd0a0ff8bebd6904a05aefee33d97` | **No** — pre-fix code verbatim |
| `v2.5` | `2.5.2` | `52ffca1e649b597c51162b5b3b37f057b73b059d` | **Yes** |

`v2.4`'s branch HEAD (`a37d3c7c2634a3d9d9f2467ed1c974f51f1d19bb`, 2026-08-28) is a day older than the upstream fix and has received no commits since — the submodule bump that landed on `v1.21` and `v2.5` was never applied to `v2.4`. The latest published `v2.4` release, `2.4.1`, was tagged 2026-08-27, a week *before* the fix even existed upstream, so it necessarily ships the vulnerable code; nothing has been released on the `v2.4` line since to correct it.

This is not a "the fix isn't merged into an unreleased branch" observation — `2.4.1` is a real, currently-latest, installable release (via PECL/Composer) of MongoDB's own officially maintained PHP driver, and it ships the exact vulnerable function, unmodified, compiled directly into the extension binary.

## Vulnerable code (as vendored in PHP driver `2.4.1`, i.e. `libmongoc` commit `9dbd6910091dd0a0ff8bebd6904a05aefee33d97`)

`src/libmongoc/src/mongoc/mongoc-openssl.c`:

```c
static OCSP_RESPONSE *
_contact_ocsp_responder(OCSP_CERTID *id, X509 *peer, mongoc_ssl_opt_t *ssl_opts, int *ocsp_uri_count)
{
   STACK_OF(OPENSSL_STRING) *url_stack = NULL;
   OPENSSL_STRING url = NULL, host = NULL, path = NULL, port = NULL;
   OCSP_REQUEST *req = NULL;                      // <-- declared ONCE, outside the loop
   const unsigned char *resp_data;
   OCSP_RESPONSE *resp = NULL;
   int i, ssl;

   url_stack = X509_get1_ocsp(peer);               // attacker-controlled: cert's AIA extension
   *ocsp_uri_count = sk_OPENSSL_STRING_num(url_stack);
   for (i = 0; i < *ocsp_uri_count && !resp; i++) {
      ...
      url = sk_OPENSSL_STRING_value(url_stack, i);

      if (!OCSP_parse_url(url, &host, &port, &path, &ssl)) {
         MONGOC_DEBUG("Could not parse URL");
         GOTO(retry);                              // <-- can skip straight to retry: with `req`
      }                                             //     still holding last iteration's freed value

      if (!(req = OCSP_REQUEST_new())) {            // only reached if OCSP_parse_url succeeded
         ...
      }
      ... /* build + send the OCSP request; several more GOTO(retry) failure paths */

   retry:
      if (host) OPENSSL_free(host);
      if (port) OPENSSL_free(port);
      if (path) OPENSSL_free(path);
      if (req)  OCSP_REQUEST_free(req);             // <-- freed but never reset to NULL
      if (request_der) OPENSSL_free(request_der);
      _mongoc_http_response_cleanup(&http_res);
   }
   ...
}
```

## Root cause

`req` (and `host`/`port`/`path`) are function-scoped locals initialized to `NULL` exactly once, before the loop starts — not re-initialized at the top of each loop iteration. The `retry:` cleanup label is shared by every iteration and unconditionally frees whatever these variables currently point to, but never resets them to `NULL` afterward.

A certificate's Authority Information Access (AIA) X.509v3 extension can list an arbitrary number of OCSP responder URLs (`X509_get1_ocsp(peer)`), fully attacker-controlled by whoever presents the certificate. This produces an exploitable sequence:

1. **Iteration 1**: a URL that parses successfully. `req = OCSP_REQUEST_new()` succeeds, and some later step fails (e.g. the HTTP POST to the responder times out or is refused, or the response body fails to parse). Any of these failures `GOTO(retry)`, which frees `req` — but `req` is left holding the now-dangling pointer value.
2. **Iteration 2**: a second URL crafted so `OCSP_parse_url()` itself fails immediately (e.g. an out-of-range port, per the upstream regression test's `"http://localhost:99999/"`). This jumps to `retry:` *before* `req` is reassigned by anything in this iteration — so `retry:` runs `OCSP_REQUEST_free(req)` again on the exact same pointer freed in iteration 1: a **double free** of a heap-allocated `OCSP_REQUEST`.

Because certificate revocation checking runs as part of TLS handshake/certificate verification, this executes before any MongoDB authentication takes place. Per the CVE description, the attacker only needs to be "a TLS endpoint that the client already trusts" — i.e. any server (rogue, compromised, or MITM'd) that the client's connection string points to and whose certificate chains to a CA the client's trust store accepts — to crash (and, depending on the allocator/heap state, potentially achieve further heap corruption in) the connecting client process. No valid MongoDB credentials are required.

## Impact

Any application built against the PHP driver's `v2.4` line — including the latest published release, `2.4.1` — that connects to a MongoDB deployment with OCSP checking enabled (the default posture for TLS connections built against OpenSSL, unless `tlsDisableOCSPEndpointCheck` is set) over OpenSSL can be crashed via heap corruption by a malicious/compromised server it connects to, exactly as described in CVE-2026-84964, despite the upstream `mongo-c-driver` fix having existed since 2026-09-04.

## Weakness

CWE-415 (Double Free) — inherited unmodified from CDRIVER-6409 — combined with a supply-chain/vendoring gap: the fix exists upstream but was never propagated into this still-active, still-released downstream branch.

## Component / Version

- Repository: `mongodb/mongo-php-driver`
- Branch: `v2.4`, latest tag `2.4.1` (tagged 2026-08-27, commit `3d7e69fd9ed9ed3893b5a3fcdc204c6864ef2241`)
- Vendored `src/libmongoc` submodule commit: `9dbd6910091dd0a0ff8bebd6904a05aefee33d97` (pre-fix)
- Confirmed by direct comparison of `mongoc-openssl.c`'s `_contact_ocsp_responder` at that exact submodule commit against the upstream fix commit `19ee915a8599477b7eb183f59b061b51cb6542f2`
- Confirmed *not* present on `v1.21` (latest tag `1.21.9`) or `v2.5` (latest tag `2.5.2`), both of which have already bumped their `src/libmongoc` submodule pin past the fix

## Suggested fix

Bump the `src/libmongoc` submodule pin on the `v2.4` branch to a `libmongoc` version that includes commit `19ee915a8599477b7eb183f59b061b51cb6542f2` (e.g. `1.30.9`/`2.5.2` or later), then cut a new `2.4.x` release — the same remediation already applied on `v1.21` and `v2.5`. If `v2.4` is intentionally no longer maintained, that end-of-support status should be stated clearly wherever `2.4.1` is still distributed (PECL, Packagist, docs), since it is currently indistinguishable from an actively maintained release carrying a known, fixed-elsewhere CVE.

## Notes on scope

Found while sibling-hunting CDRIVER-6409/CVE-2026-84964 at the user's request ("check every driver to find similar bug"). I first confirmed the bug is exclusive to `mongo-c-driver`'s OpenSSL TLS backend — the Secure Channel (Windows) and Secure Transport (macOS/iOS) backends delegate OCSP/revocation checking entirely to native OS APIs (`SCH_CRED_IGNORE_REVOCATION_OFFLINE` / `SecPolicyCreateRevocation`) and contain no hand-rolled OCSP request/response code, so there is no equivalent bug in those backends, and `mongo-c-driver`'s own `master`/`r1.30`/`r2.5` branches are all already fixed directly per the Jira ticket. The `mongo-cxx-driver` (C++ driver) does not vendor `libmongoc` at all — it build-requires `libmongoc >= 2.5.3`, which is already past the fix, so it inherits the fix through the ordinary dependency-version mechanism rather than a stale vendored copy. The one place the vulnerable code is still concretely shipping today is the PHP driver's `v2.4` release line, documented above.
