# mongo-python-driver: `_cbson` recursion guard is sound but its safety margin is borrowed from `sys.getrecursionlimit()` — segfaults on CPython 3.10/3.11 if that's ever raised; fixed by CPython 3.12 itself

Same sibling-bug hunt as the `mongo-c-driver` (clean) and `mongo-go-driver` (vulnerable,
reported separately) passes, triggered by the `mongo-csharp-driver`/`bson-rust` HackerOne
triage outcomes on the "unbounded BSON decode recursion" class.

Unlike C#, Go, and PHP, `mongo-python-driver`'s C extension (`_cbsonmodule.c`) is **not**
missing a guard — every recursive decode call is correctly wrapped in CPython's own
`Py_EnterRecursiveCall`/`Py_LeaveRecursiveCall`, and at the *default* `sys.getrecursionlimit()`
(1000) this safely raises a catchable `InvalidBSON` at depth, confirmed empirically. The gap
is one level up: that guard's safety margin is whatever the embedding *application* has set
`sys.getrecursionlimit()` to, not anything pymongo checks against real stack capacity — and
on CPython 3.10/3.11 specifically, exceeding real native-stack capacity while still under an
elevated configured limit segfaults the process (confirmed: `sys.setrecursionlimit(100000)`
+ a 20,000-level-deep BSON document → `SIGSEGV`, exit 139, on both 3.10.20 and 3.11.15).

The interesting empirical result: **the identical PoC is safe on CPython 3.12.3 and 3.13.12**,
even at 10x the nesting depth (200,000 levels) with the same raised limit — not because of
anything in this driver, but because CPython's own C-recursion protection was hardened
starting in 3.12 to no longer purely trust the configured limit. Built and tested against
all four interpreters from source (real `_cbson` extension, no driver code modified) to
confirm this rather than assume it from changelogs.

See `HACKERONE-REPORT.md` for the full write-up, code citations, and honest scoping of the
two preconditions this needs (CPython 3.10/3.11 + an app-raised recursion limit) relative to
the unconditional crashes already found in the sibling drivers. `poc.py` is the PoC source;
the five `poc_output_*.txt` files are raw output covering the default-safe case, both
crashing interpreters, and both safe-on-3.12+ interpreters.
