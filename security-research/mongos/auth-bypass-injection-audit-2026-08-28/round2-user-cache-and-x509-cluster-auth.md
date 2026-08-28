# Round 2: user-cache staleness and internal x.509 cluster auth

**Status: no vulnerability found. Both leads traced to a concrete, defensible conclusion.**

## User-cache / authorization staleness (`UserCacheInvalidator`, `src/mongo/db/auth/user_cache_invalidator_job.cpp`)

This is a periodic job (interval controlled by `userCacheInvalidationIntervalSecs`) that runs on
`mongos`, polls the config server's `_getUserCacheGeneration` command, and invalidates the local
user/role cache when the generation changes (a role grant/revoke on the config server bumps this
generation). Between two polls, `mongos` keeps honoring its locally cached privileges — meaning a
just-revoked privilege can keep working on that `mongos` for up to one polling interval.

This is a real staleness window, but it's **by design and already documented**: the parameter
itself (`userCacheInvalidationIntervalSecs`) is a public, user-facing server parameter, which is
itself the tell that this window is a known, accepted, and tunable trade-off (make it smaller for
tighter consistency, at the cost of more load on the config server) — not an undocumented gap. It
also fails toward safety on error: if the config-server poll itself fails, the code invalidates
the cache unconditionally ("When in doubt, invalidate the cache", line 164-169) rather than
silently continuing to trust stale data. Not filing this as a fresh finding.

Did not find a way to make the window larger than documented/configured, or to defeat the
invalidation entirely (e.g., no code path where a poll failure is swallowed without either
invalidating or logging a warning).

## Internal x.509 cluster authentication (`SaslX509ServerMechanism`, `SSLConfiguration::isClusterMember`)

Traced the full trust chain an attacker would need to break to get treated as a cluster member
(`local.__system`, effectively full admin) via a spoofed x.509 SASL conversation:

1. `stepImpl` (`sasl_x509_server_conversation.cpp`) first reads the caller-supplied `principalName`
   field from the raw SASL payload via `unpackName()` — this part *is* attacker-controlled.
2. It immediately overwrites that with the result of `getUserName()`, which:
   - Reads `clientName` from `sslPeerInfo->subjectName()` — the **TLS-verified** certificate
     subject DN (not attacker-suppliable; comes from the handshake, not the SASL payload).
   - If the caller's supplied `user` (principalName) is non-empty, `uassert`s it is **exactly
     equal** to the verified `clientName`, throwing `AuthenticationFailed` otherwise.
   - So after this point, `_principalName` is guaranteed to be the TLS-verified subject DN (or a
     value cryptographically forced to equal it) — the SASL payload's principalName field can't be
     used to claim a different identity than the certificate actually presented.
3. `isClusterMember()` is then evaluated using this now-verified principal name, calling into
   `SSLConfiguration::isClusterMember(subject, clusterExtensionValue)`
   (`util/net/ssl_manager.cpp:787`), which matches the verified subject DN's attributes (DC/O/OU,
   or a configured extension value) against the configured cluster-membership criteria
   (`clusterAuthX509Attributes`/`clusterAuthX509ExtensionValue`, with override variants) — a
   fixed, admin-configured server-side policy, not something the connecting client influences.

No point in this chain lets attacker-supplied SASL payload content substitute for the TLS-verified
certificate identity, and no point lets the client influence which DN/extension criteria counts
as "cluster member" — that's fixed server configuration. This is exactly what should be true for
this trust boundary to hold; found no way to shortcut it.

One thing worth flagging as reduced confidence rather than a vulnerability: this code path is
gated behind `gFeatureFlagRearchitectUserAcquisition` and `gFeatureFlagUseInternalAuthzInsteadOfLDAP`
(both explicitly checked in `stepImpl`/`makeUserRequest`), meaning it's actively-changing,
feature-flagged code rather than long-stable code — the kind of surface where a fresh bug is more
plausible than in a decade-old stable path. I read it carefully and didn't find one, but this is
exactly the kind of code worth another pass (ideally with the actual `UserRequestX509`/
`AuthorizationManager::acquireUser` call chain also read end to end, which this round did not do)
if there's appetite to keep digging here specifically.

## Conclusion

Two more historically-relevant angles chased to ground, both clean. Combined with round 1
(command-level auth-check review, code-injection structural check), this is now a reasonably
thorough — though still not exhaustive — pass over `mongos`'s auth surface. No confirmed
vulnerability across either round.

## Still open, in rough order of promise for a round 3

1. `UserRequestX509::makeUserRequestX509` and `AuthorizationManager::acquireUser` — the two calls
   downstream of the x.509 identity verification above, not read this round; this is where the
   verified identity actually gets turned into a privilege set, and where a "verified user in
   principle, over-privileged in practice" bug would live if one exists.
2. `gEnforceUserClusterSeparation`'s user-exists check (`sasl_x509_server_conversation.cpp:220-249`)
   — only skimmed; worth a closer look at whether the `userExists` check can race with a
   concurrent user creation, or whether the "cluster member vs. explicit user" conflict detection
   has an edge case with certificate rotation.
3. The remaining ~40 unread command files in `src/mongo/s/commands/`.
4. `src/mongo/db/auth/` privilege-resolution/role-graph code more broadly (role inheritance,
   `directAuthorizedResources` expansion) — a different, and arguably richer, bug class than the
   authentication-identity questions covered so far.
