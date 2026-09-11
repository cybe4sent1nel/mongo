# Broad case-sensitivity security audit — negative result after real effort in the highest-probability areas

Following SERVER-131229/CVE-2026-82067 (config-option validator case-insensitive, consumer
case-sensitive, silent fail-open), you asked for a deep, general sweep for the same *class* of bug
— anywhere a case-sensitivity mismatch could produce a high/critical security bypass, not just in
config-option validation. Covered the highest-probability areas for a database server; no new
finding, reported honestly rather than stretched.

## Areas checked

**1. Authentication/authorization subsystem (`src/mongo/db/auth/`)** — swept the entire directory
for any case-insensitive string comparison (`equalCaseInsensitive`, `toLower`/`toUpper`,
`boost::iequals`, `strcasecmp`): **zero hits**. Username, role name, and privilege-resource
matching in this codebase is uniformly case-sensitive with no exceptions found — the safest
possible state for this bug class (no risk of two different-cased principals/roles being
conflated, and no risk of a case-insensitive check anywhere disagreeing with a case-sensitive one
downstream).

**2. x.509 cluster-member certificate subject DN matching** (`SSLConfiguration::isClusterMember`,
`util/net/ssl_manager.cpp:809-857`) — the code explicitly documents two different comparison paths
(a normalized-DN path and a stringified/RFC4514-canonicalized path) and calls
`subject.normalizeStrings()` before comparison specifically to make matching correct per DN
comparison semantics (most X.509 RDN attribute types are `caseIgnoreMatch` per RFC 4519) — this
looks like a deliberately-designed, correctly-scoped normalization, not an accidental mismatch. Also
re-confirmed (from earlier this engagement's `mongos` auth-bypass round) that the SASL x.509
conversation forces the client-supplied `principalName` to exactly equal the TLS-verified subject
DN before it's trusted, closing the "attacker-supplied identity string differs in case from the
real cert" angle regardless.

**3. Database-name case-insensitive collision handling** (`DatabaseName::equalCaseInsensitive`,
`database_name.h:268`) — this exists specifically because case-differing DB names can collide on
case-insensitive filesystems (Windows, default macOS). Traced every consumer:
- `create_database_util.cpp:63-65` — blocks creating any case-variant of `admin`/`local`/`config`
  (the safe direction: protecting sensitive system databases from being shadowed/confused).
- `database_holder_impl.cpp:357-367` (`getAnyConflictingName`) — the general in-memory
  conflict-detector. Its **only** caller in the whole tree is `oplog.cpp:907`, and that call site is
  narrowly scoped to a secondary replica-set node reconciling a specific oplog-replay divergence
  (an empty, stale-cased database left open after a primary rolled back a `dropDatabase`) — not a
  general "block ordinary users from creating a case-colliding database" enforcement point.
- Checked whether this matters in practice for security: modern MongoDB (WiredTiger) names on-disk
  storage files by randomly-generated idents (confirmed directly — see the `applyOps` finding from
  earlier this engagement, which used real idents like `collection-c4b93a3f-...`), **not** by
  database/collection name. So even without general-purpose case-collision blocking, two
  differently-cased databases don't actually collide at the storage layer the way they would have
  under the old MMAPv1 engine (where this mechanism likely originated). This significantly limits
  the practical severity of the gap I found (no general enforcement outside the three protected
  names) — it's a real absence of defense-in-depth, but not a live storage-collision or
  privilege-bypass path against a modern WiredTiger deployment as far as I could establish.

**4. OIDC/JWT authentication** — only a protocol IDL file
(`src/mongo/db/auth/oidc_protocol.idl`) exists in this repository; the actual token
validation/issuer-audience-matching implementation is not present here (same situation as LDAP —
apparently Enterprise-only or otherwise not in the public tree), so this could not be audited.

## Conclusion

No new case-sensitivity-driven high/critical bug found. The one closest-looking gap (no general
database-name case-collision enforcement beyond the three protected system database names) is real
as an absence of defense-in-depth, but I could not construct a concrete exploitation path against
it on the modern WiredTiger storage engine, and it's a materially different (weaker) shape than the
CVE-2026-82067 pattern (validator says yes, consumer silently treats it as no, security control
silently disabled) — reporting it as a negative/inconclusive observation rather than a finding.
`security.authorization`'s bug looks like it really was the one place this bug class produced a
live, silent, fail-open security control — the rest of the codebase checked here is either
uniformly case-sensitive (auth) or deliberately and correctly case-normalized (x.509 DN matching).
