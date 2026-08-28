# MongoDB 8.3.8 — vendored ICU 57.1: outdated dependency with known CVEs, live-tested reachable path

**Status: real, disclosable supply-chain finding (CWE-1104/CWE-937, "Use of Unmaintained Third
Party Components") — reachability confirmed, live exploitation attempts via the one confirmed
user-reachable path did NOT crash the server.** Recorded honestly as a mitigated/inconclusive
result on the crash question, not oversold as a confirmed RCE/DoS.

## What was found

`src/third_party/icu4c-57.1` — MongoDB vendors ICU4C **57.1**, released by the ICU project in
2016, directly into the `mongod` binary (confirmed both from the exact source-tree directory name
in a fresh `r8.3.8` checkout and from the binary's own internal C++ namespace symbols, e.g.
`icu_57`, `icu_5710`...`icu_5713`). No patch files are tracked alongside it in the vendored copy.

Two CVEs are publicly documented as affecting ICU **"through 57.1"** (i.e. not yet fixed at that
exact version, fixed only in 57.2/58.1):
- **CVE-2016-7415**: stack-based buffer overflow in the `Locale` class, `common/locid.cpp`, "via a
  long locale string."
- **CVE-2016-6293**: out-of-bounds read in `uloc_acceptLanguageFromHTTP`, `common/uloc.cpp`, "via a
  long httpAcceptLanguage argument."

## Reachability

`src/mongo/db/query/collation/collator_factory_icu.cpp:532` passes the **raw, user-supplied**
`collation.locale` string from an ordinary `find`/`aggregate`/`createIndex` command directly into
`icu::Locale::createFromName(std::string{collation.getLocale()}.c_str())` — exactly the API surface
CVE-2016-7415 targets (`Locale` construction from an arbitrary caller-supplied string), reachable by
any user who can issue an ordinary query with a `collation` option. This is a genuinely
user-controlled, wire-protocol-reachable path into the vulnerable-by-version library code — not a
theoretical or CLI-only reachability question like the two dangerous-import leads closed in the
same day's earlier Ghidra pass.

`uloc_acceptLanguageFromHTTP` (CVE-2016-6293) was not found called anywhere from MongoDB's own code
(it's an HTTP `Accept-Language` header-negotiation helper; `mongod`'s wire protocol has no such
concept) — that CVE appears unreachable regardless of the underlying library's patch state.

## Live testing (real 8.3.8 binary, disposable standalone, no crash)

Tested directly against a live, disposable `mongod` 8.3.8 instance via ordinary `find` commands with
a crafted `collation.locale`:

- Plain long strings, `"en_US_" + "A"*N` for N up to 50,000 bytes.
- Locale strings with many short `@key=value;key=value;...` keyword pairs (200 pairs).
- A single huge post-`@` blob with no `=` separator (5,000 bytes).
- A long value for a real keyword name (`@collation=` + 5,000 `A`s).
- Many medium-length keyword pairs (50 pairs × 50 bytes each).

Every case was rejected cleanly — either MongoDB's own `validateLocaleID` round-trip check
(`Field 'locale' is not valid in: ...`) or a direct ICU status-code failure surfaced by MongoDB's
wrapper (`Failed to create collator: U_ILLEGAL_ARGUMENT_ERROR`). `mongod` answered `ping` normally
after every single attempt — same pid throughout, no crash, no hang.

Reading `Locale::init()` (the function `createFromName` calls into) shows it already has a
heap-fallback path for oversized input (`uloc_canonicalize`/`uloc_getName` first attempt into a
512-byte stack buffer; on `U_BUFFER_OVERFLOW_ERROR` or a returned length exceeding the buffer, it
retries into a freshly `malloc`'d buffer sized to the real length) and explicit bounds checks before
copying into the fixed-size `language`/`script`/`country` member arrays
(`if (fieldLen[0] >= sizeof(language)) break;`, matching pattern for the others).

**Traced one specific hypothesis to a conclusive dead end.** `_canonicalize()` (`uloc.cpp:1629`,
the shared implementation behind both `uloc_getName` and `uloc_canonicalize`) has a POSIX-style
variant handling branch, gated behind `OPTION_SET(options, _ULOC_CANONICALIZE)`, that calls
`_getVariantEx(tmpLocaleID+1, '@', name+len, nameCapacity-len, ...)` **without** first checking
`len < nameCapacity` — unlike every other write in the same function, which is properly guarded.
If `len` already exceeds `nameCapacity` by the time this line runs (a long enough language/script
prefix ahead of an `@`-suffixed POSIX variant with no `=`), `name+len` is a pointer past the
512-byte stack buffer and `nameCapacity-len` is negative — exactly the shape "via a long locale
string" suggests. But this branch is unreachable from MongoDB's path: `uloc_getName` calls
`_canonicalize` with `options=0` (`_ULOC_CANONICALIZE` unset, per `uloc.cpp:2043-2048`), and
`Locale::createFromName` — the only entry point `collator_factory_icu.cpp` uses — calls
`Locale::init(name, /*canonicalize=*/FALSE)`, which in turn calls `uloc_getName`, not
`uloc_canonicalize`. The vulnerable line simply never executes on this call path, regardless of
payload — confirmed by tracing the flag through three call layers, not just by a failed live test.
Live-tested this exact shape anyway (`'A'*600 + '@FOO'` through `'A'*5000 + '@Z'`, plus a
two-long-field variant) for completeness: all rejected via `Locale::init()`'s own
`fieldLen[0] >= sizeof(language)` field-length check (which runs on `_canonicalize`'s *output*,
after the call in question has already safely returned), `mongod` alive throughout — consistent
with, not contradicting, the reachability analysis above.

Whether this specific vendored 57.1 snapshot's *reachable* paths (as opposed to the
`_ULOC_CANONICALIZE`-gated one just closed off) contain some other unpatched trigger for
CVE-2016-7415 was not conclusively determined in the time available for this pass.

## PCRE2 checked for comparison — clean

MongoDB also vendors PCRE2 **10.40** (`src/third_party/pcre2`, `$regex`'s regex engine — a far more
central, heavily-used attack surface than collation). Checked this version against known PCRE2
CVEs: CVE-2022-1586/CVE-2022-1587 (JIT-compiler OOB reads) are explicitly fixed *in* 10.40 itself
(not before it) per public advisories — MongoDB's vendored copy is the fix release, not a vulnerable
predecessor. CVE-2025-58050 (PCRE2 10.45, the `(*scs:...)` Scan-Substring verb combined with
`(*ACCEPT)`) doesn't apply: grepping the vendored source confirms this verb doesn't exist in the
10.40 codebase at all — the feature was added in a later release, so 10.40 has no code path to be
vulnerable through. PCRE2 is current relative to its own CVE history; no lead here.

## SpiderMonkey/mozjs — noted, not pursued this pass

MongoDB embeds SpiderMonkey (Mozilla's JS engine) for server-side JS (`$where`, `mapReduce`, stored
functions). A source comment references "MozJS ESR128" (a comparatively recent, ~2024 Firefox ESR
branch) — this is a much better-maintained upstream than ICU 57.1, and pinning the *exact* patch
level within the ESR128 branch (to check for a specific unpatched CVE) wasn't done this pass; noted
as a candidate for a dedicated follow-up given the sheer size and historical bug-density of JS
engines generally, but not something a quick version check alone can respectably conclude anything
about.

## Assessment

This is real, verifiable, and disclosable as an "outdated bundled dependency" observation — MongoDB
ships a decade-old ICU with two CVEs publicly listed against it, via a genuinely user-reachable code
path, which is a fair thing to report. It falls short of a confirmed Critical/High *crash* finding:
extensive live-fuzzing of the one reachable path found no crash, and reading the vendored `init()`
code shows real bounds-checking machinery already in place that a naive "just make the string long"
attack doesn't get past. Reporting this honestly as "outdated dependency, confirmed reachable,
inconclusive on live exploitability" rather than rounding up to "confirmed RCE" or rounding down to
"nothing here."
