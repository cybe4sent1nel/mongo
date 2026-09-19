# Title

SERVER-130264 / CVE-2026-18691's fix does not close `negotiateSaslMechanism`'s fallback path — a forged all-`PLAIN` hello reply still reaches an unfiltered `.front()` mechanism selection for internal auth, and the connection does not "fail with a clear error" as the fix's own acceptance criteria require; full credential exposure is currently prevented only by a second, independent guard

## Summary

I audited the SERVER-130264/CVE-2026-18691 fix (present and correct on `r8.3.11`, confirmed below) for completeness rather than just checking it exists, and traced what happens on the exact scenario the fix's own acceptance criteria describe: *"A hello reply advertising no recognised mechanisms causes the connection setup to fail with a clear error rather than falling back to PLAIN."*

That is not what currently happens. When the allowlist in `TLConnectionSetupHook::validateHost` filters a forged, `PLAIN`-only `saslSupportedMechs` down to an empty list (exactly the attack the fix targets), the connection setup does **not** fail — it falls through to a second, completely different mechanism-negotiation function, `negotiateSaslMechanism` (`src/mongo/client/authenticate.cpp`), which issues its own fresh `hello` to the same peer and picks a mechanism via `availableMechanisms.front()` with **no allowlist at all**. Against the same attacker who only ever advertises `PLAIN`, this fallback selects `"PLAIN"` as the negotiated mechanism for the internal `__system` user.

The reason this doesn't currently leak the keyfile is a *separate* guard: `getInternalAuthParams` (`src/mongo/client/internal_auth.cpp:121-123`) explicitly returns an empty `BSONObj` when asked for parameters for mechanism `"PLAIN"`, which both `InternalAuthParametersProvider` implementations (`DefaultInternalAuthParametersProvider` and `TransientInternalAuthParametersProvider`) route through. So the attack is blocked — but only because two independently-maintained pieces of code happen to agree, not because the primary fix (the allowlist gate in `validateHost`) actually closes the loop the way its own acceptance criteria say it should.

## Confirmed: the primary fix is present and correct on r8.3.11

- `src/mongo/executor/connection_pool_tl.cpp`: `kInternalAuthAllowlist = {SCRAM-SHA-256, SCRAM-SHA-1, MONGODB-X509}` and `filterInternalAuthSaslMechs()` are present, matching the ticket's proposed fix exactly.
- `src/mongo/client/internal_auth.cpp:121-123`: `getInternalAuthParams` explicitly rejects `PLAIN`:
  ```cpp
  // Defence in depth: PLAIN must never be used for internal authentication, ...
  if (mechanism == kMechanismSaslPlain) {
      return BSONObj();
  }
  ```
Both pieces described in the ticket's "Proposed Fix" section are genuinely there. This report is not a "fix missing" claim.

## The gap: what happens when the allowlist-filtered list is empty

`src/mongo/executor/connection_pool_tl.cpp` (`TLConnection::setup`):

```cpp
.then([this, helloHook, authParametersProvider](bool authenticatedDuringConnect) {
    if (_skipAuth || authenticatedDuringConnect) {
        return Future<void>::makeReady();
    }

    boost::optional<std::string> mechanism;
    if (!helloHook->saslMechsForInternalAuth().empty())
        mechanism = helloHook->saslMechsForInternalAuth().front();
    return _client->authenticateInternal(std::move(mechanism), authParametersProvider);
})
```

If the peer's hello reply advertised only `PLAIN`, the allowlist filter drops it, `saslMechsForInternalAuth()` is empty, and `mechanism` stays `boost::none` — there is **no early error here**. `authenticateInternal(boost::none, ...)` is called anyway.

`src/mongo/client/authenticate.cpp` (`authenticateInternalClient`, called by `AsyncDBClient::authenticateInternal`):

```cpp
Future<void> authenticateInternalClient(..., boost::optional<std::string> mechanismHint, ...) {
    auto systemUser = internalSecurity.getUser();
    return negotiateSaslMechanism(runCommand, (*systemUser)->getName(), mechanismHint, stepDownBehavior)
        .then([...](std::string mechanism) -> Future<void> {
            auto params = internalParamsProvider->get(0, mechanism);
            ...
        });
}
```

`negotiateSaslMechanism`, same file, lines 256-298:

```cpp
Future<std::string> negotiateSaslMechanism(RunCommandHook runCommand,
                                           const UserName& username,
                                           boost::optional<std::string> mechanismHint,
                                           StepDownBehavior stepDownBehavior) {
    if (mechanismHint && !mechanismHint->empty()) {
        return Future<std::string>::makeReady(*mechanismHint);
    }

    BSONObjBuilder builder;
    builder.append("hello", 1);
    builder.append("saslSupportedMechs", username.getUnambiguousName());   // <-- fresh hello, same peer
    ...
    return runCommand(...)
        .then([](BSONObj reply) -> Future<std::string> {
            auto mechsArrayObj = reply.getField("saslSupportedMechs");
            ...
            std::vector<std::string> availableMechanisms;
            for (const auto& elem : obj) {
                availableMechanisms.push_back(std::string{elem.checkAndGetStringData()});
                if (availableMechanisms.back() == kMechanismScramSha256) {
                    return availableMechanisms.back();
                }
            }

            return availableMechanisms.empty() ? std::string{kInternalAuthFallbackMechanism}
                                               : availableMechanisms.front();   // <-- NO allowlist
        });
}
```

Because `mechanismHint` is empty (per the previous step), execution falls into the `else` branch: a **second, brand-new `hello` command is sent to the same peer**, and the mechanism is chosen from *that* reply with no allowlist whatsoever — the exact `.front()`-on-unfiltered-input pattern the original ticket identifies as the root cause, reproduced verbatim in a code path the fix never touched. If the attacker answers this second hello with `saslSupportedMechs: ["PLAIN"]` too (trivial — it's the same forged peer), `"PLAIN"` is returned as the negotiated mechanism and flows into `authenticateInternalClient`'s continuation as `mechanism = "PLAIN"`.

Crucially, this second `hello` is issued via `_makeAuthRunCommandHook()` (`async_client.cpp`), a plain per-command execution path — **not** `TLConnectionSetupHook::validateHost`, which only runs once, during the connection pool's initial setup handshake. The allowlist that was supposed to be the authoritative gate simply isn't in the loop for this second round trip.

## Why this doesn't (currently) leak the keyfile

`authenticateInternalClient`'s continuation calls `internalParamsProvider->get(0, "PLAIN")`. Both implementations of `InternalAuthParametersProvider` (`DefaultInternalAuthParametersProvider::get` and `TransientInternalAuthParametersProvider::get`, when not using a transient X.509 SSL context) delegate to `auth::getInternalAuthParams(index, mechanism)`, which — per the defense-in-depth check confirmed above — returns an empty `BSONObj` for `mechanism == "PLAIN"`. `authenticateInternalClient` sees `params.isEmpty()` and returns `Status(ErrorCodes::BadValue, "Missing authentication parameters for internal user auth")` instead of issuing a `saslStart` with the keyfile.

So: **no credential is actually sent**, and the connection setup fails — just not for the reason, or at the point, the fix's own acceptance criteria describe, and not in a way that's guaranteed to keep holding.

## Why this still matters

1. **It's a direct violation of the fix's own stated acceptance criterion**: *"A hello reply advertising no recognised mechanisms causes the connection setup to fail with a clear error rather than falling back to PLAIN."* Current behavior does fall back — to a second, unfiltered negotiation attempt that can and does select `"PLAIN"` — and only fails afterward, for an unrelated reason ("missing authentication parameters"), at a different layer than intended.
2. **The system's actual safety now depends on two independently-maintained components staying in agreement**, when the ticket's own design was for `validateHost`'s allowlist to be the single authoritative gate ("As a defence-in-depth **second** layer, `getInternalAuthParams` ... should also reject PLAIN" — the ticket itself frames `getInternalAuthParams`'s check as backup, not as the thing actually doing the blocking in this scenario. Here, it is doing all of the blocking, alone, for this specific trigger.)
3. **Fragile to future change**: any new `InternalAuthParametersProvider` implementation (e.g. for a cloud-managed or KMS-backed internal credential source, a realistic kind of future addition) that does not happen to route through `getInternalAuthParams`'s specific `mechanism == kMechanismSaslPlain` check would silently reopen the exact CVE-2026-18691 impact — a forged `PLAIN`-only hello reply causing the cluster's internal credential to be sent in cleartext — without touching `validateHost`'s allowlist at all, because that allowlist is never in this loop.
4. **Unnecessary extra round trip to an already-suspicious peer**: even in the fully-patched-as-intended reading, a peer whose hello reply failed the allowlist check (advertised nothing usable) is, by definition, either misconfigured or attacker-controlled — the current code rewards that by opening a second SASL negotiation with it rather than terminating the connection attempt immediately, which is both wasted work and unnecessary additional exposure (a second `hello` carrying the internal username, `username.getUnambiguousName()`, is sent to the same untrusted peer).

## Suggested fix

Make the empty-post-filter case a hard failure at the point the ticket's acceptance criteria describe, instead of falling through to `negotiateSaslMechanism`'s own hello-based negotiation:

```cpp
// connection_pool_tl.cpp, TLConnection::setup
if (helloHook->saslMechsForInternalAuth().empty()) {
    // The peer's hello reply contained no mechanism safe for internal authentication
    // (e.g. only PLAIN, or nothing at all). Do not fall back to an unfiltered
    // negotiation with the same peer — fail the connection setup outright.
    return Future<void>::makeReady(
        Status(ErrorCodes::AuthenticationFailed,
               "No allowlisted SASL mechanism advertised for internal authentication"));
}
auto mechanism = helloHook->saslMechsForInternalAuth().front();
return _client->authenticateInternal(std::move(mechanism), authParametersProvider);
```

This also removes the dependency on `negotiateSaslMechanism`'s empty-hint branch ever being reached for internal auth at all, so `getInternalAuthParams`'s `PLAIN` check goes back to being genuine defense-in-depth (a backstop that should never actually fire) rather than the only thing standing between a forged hello reply and a cleartext keyfile transmission.

## Weakness

CWE-757 (Selection of Less-Secure Algorithm During Negotiation, 'Algorithm Downgrade') — same classification as the original ticket. Also relevant: CWE-696 (Incorrect Behavior Order), since the intended "fail closed" behavior is reordered to "attempt an extra unfiltered negotiation, then fail for an unrelated reason."

## Component / Version

- Repository: `mongodb/mongo`
- Confirmed on `r8.3.11`: `src/mongo/executor/connection_pool_tl.cpp` (allowlist present, lines ~259-331 and ~505-511), `src/mongo/client/authenticate.cpp` (`negotiateSaslMechanism`, lines 256-298; `authenticateInternalClient`, lines 301+), `src/mongo/client/internal_auth.cpp` (`getInternalAuthParams`, lines 100-136, PLAIN check at 121-123), `src/mongo/client/async_client.cpp` (`authenticateInternal`, confirms the second hello runs through `_makeAuthRunCommandHook()`, not `TLConnectionSetupHook`)
- Not yet checked against `master`/9.x, but the ticket's own commit (`eae98acfb8eb698f642652f80d0bd1d82d529432`) only touches `connection_pool_tl.cpp` and `internal_auth.cpp` per the Jira "Notes" section, so this is very likely still present there too

## Notes on scope

Found while verifying SERVER-130264/CVE-2026-18691's fix on `r8.3.11` at the user's implicit request to sibling-hunt/deep-audit around this CVE. This is not a "the fix isn't in master" observation (both pieces of the documented fix are genuinely present and correctly implemented) — it's a trace of the fix's own acceptance criteria against the actual control flow, which surfaced a second, unfixed path that reaches the identical unfiltered-mechanism-selection pattern the ticket describes as the root cause. I verified end-to-end that current behavior does not leak the credential in practice (a separate, correctly-implemented guard catches it), so I'm reporting this as an incomplete-fix / fragile-defense-in-depth finding rather than as a live, currently-exploitable credential-exposure bug.
