# Title

`bson`'s C extension (`_cbsonmodule.c`) BSON decode recursion guard trusts the caller's `sys.setrecursionlimit()` value instead of measuring real C-stack headroom — an application that has raised the limit (a common pattern for unrelated reasons) crashes with an uncatchable `SIGSEGV` on a single deeply-nested BSON document, on CPython 3.10/3.11; fixed as of CPython 3.12's own runtime, not by any code in this driver

## Summary

`bson/_cbsonmodule.c`'s BSON-to-Python decode path (`get_value` for nested documents/arrays, entered via `_get_object_size`/`_elements_to_dict`) correctly wraps every recursive decode call in `Py_EnterRecursiveCall`/`Py_LeaveRecursiveCall` — CPython's own built-in recursion-guard API. Under CPython's **default** `sys.getrecursionlimit()` of 1000, this works exactly as intended: decoding a deeply-nested BSON document raises a normal, catchable `bson.errors.InvalidBSON("maximum recursion depth exceeded while decoding a BSON document")`, never crashing the process. I confirmed this default-configuration behavior is safe.

However, on **CPython 3.10 and 3.11**, `Py_EnterRecursiveCall`'s check is a simple counter compared against the *application-configured* `sys.getrecursionlimit()` value — it does not measure actual remaining C-stack space. If the embedding application (or any other library loaded in the same process) has called `sys.setrecursionlimit()` to raise the limit beyond what the process's real C stack can safely support for this call depth — a well-known, common Python pattern for working around unrelated `RecursionError`s in application code (deeply recursive template rendering, deeply nested JSON/YAML processing, recursive data-structure traversal elsewhere in the same codebase) — the guard no longer protects against a genuine native stack overflow. I confirmed this **crashes the interpreter with an uncatchable `SIGSEGV`** (exit code 139) on both Python 3.10.20 and 3.11.15, using a single BSON document with 20,000 levels of nesting (160,005 bytes) and `sys.setrecursionlimit(100000)`.

Critically, I also confirmed this is **already fixed on CPython 3.12 and 3.13** — not by anything in `mongo-python-driver`'s own code, but by CPython's own improved C-recursion protection (its C-stack-depth tracking is no longer purely a function of the configured limit). The identical PoC that segfaults on 3.10/3.11 decodes safely (raising the normal `InvalidBSON`) on 3.12.3 and 3.13.12, even at **10x the nesting depth** (200,000 levels) and the same raised recursion limit.

## Weakness

CWE-674 (Uncontrolled Recursion) / CWE-1284 (Improper Validation of Specified Quantity in Input) — a real recursion guard exists and is correctly wired up, but its effective safety margin is fully delegated to a value pymongo does not control and does not itself validate against actual stack capacity, on CPython versions whose own recursion-limit enforcement has this same property.

## Component / Version

- Repository: `mongodb/mongo-python-driver` (HackerOne scope: **Drivers → Python**)
- Tag: `4.18.0`
- Commit: [`8e7ece47f3c5a3908ef886d431c3dcc3feb56316`](https://github.com/mongodb/mongo-python-driver/blob/8e7ece47f3c5a3908ef886d431c3dcc3feb56316/bson/_cbsonmodule.c) — current latest release
- Confirmed by building the driver's real, unmodified `_cbson` C extension from source against four CPython versions: 3.10.20, 3.11.15 (both **crash**), 3.12.3, 3.13.12 (both **safe**).

## Root cause, with links to the exact code

`bson/_cbsonmodule.c`, the document-decode recursion guard ([lines 3017-3021](https://github.com/mongodb/mongo-python-driver/blob/8e7ece47f3c5a3908ef886d431c3dcc3feb56316/bson/_cbsonmodule.c#L3017-L3021)):

```c
if (Py_EnterRecursiveCall(" while decoding a BSON document"))
    return NULL;
result = _elements_to_dict(self, string + 4, max - 5, options);
Py_LeaveRecursiveCall();
```

and the array-element recursion guard ([lines 2282-2288](https://github.com/mongodb/mongo-python-driver/blob/8e7ece47f3c5a3908ef886d431c3dcc3feb56316/bson/_cbsonmodule.c#L2282-L2288)):

```c
if (Py_EnterRecursiveCall(" while decoding a list value")) {
    Py_DECREF(value);
    goto invalid;
}
to_append = get_value(self, name, buffer, position, bson_type,
                      max - (unsigned)key_size, options, raw_array);
Py_LeaveRecursiveCall();
```

Both call sites are correctly paired (`Enter`/`Leave` symmetric, error path handled). This is a legitimate use of CPython's own C-API recursion guard — **not** an absent-guard bug like the sibling findings in `mongo-csharp-driver` (#3790290/#3996918, unbounded recursion, no guard at all) or the unbounded generic-decode recursion I separately found and reported in `mongo-go-driver`. The gap is one level up: `Py_EnterRecursiveCall`'s implementation on CPython 3.10/3.11 (`Include/ceval.h`/`Python/ceval.c` in CPython itself, not this repository) increments a counter and compares it against `tstate->recursion_limit`, which is set directly from whatever `sys.setrecursionlimit(n)` the *application* last called — pymongo neither reads nor caps this value, and has no independent tracking of actual remaining C-stack space. CPython 3.12 changed this (as part of its broader interpreter-frame rework) to track C-stack depth in a way that remains protective even when the Python-level recursion limit is set far higher than a single call chain's real native-stack budget — confirmed empirically below, not merely asserted from CPython's changelog.

## Steps to Reproduce

Requirements: `python3.10`, `python3.11`, `python3.12`, `python3.13` (all tested from Ubuntu 24.04's standard `python3.X` packages), a clean clone of `mongo-python-driver` at the tag/commit above, built for each interpreter (`pip install --no-build-isolation -e .`, or equivalently `python setup.py build_ext --inplace`) so each interpreter loads its own freshly-compiled `_cbson` extension — no driver source was modified for any of the four builds.

**PoC** (`poc.py`, included in this directory) builds a BSON document nested to an attacker-chosen depth via a single flat pre-allocated `bytearray` (O(depth), no repeated copies), then decodes it with the real, unmodified extension:

```python
import sys
if raise_limit:
    sys.setrecursionlimit(100000)
import bson
bson.BSON(data).decode()
```

**Default configuration (no `setrecursionlimit` call) — safe on every version tested:**
```
$ python3.11 poc.py 5000
recursion limit=1000, depth=5000
built 40005 bytes, decoding...
caught (safe): InvalidBSON: maximum recursion depth exceeded while decoding a BSON document
exit code: 0
```

**Raised limit, Python 3.11.15 — CRASHES:**
```
$ python3.11 poc.py 20000 raiselimit
recursion limit=100000, depth=20000
built 160005 bytes, decoding...
Segmentation fault
exit code: 139
```

Python 3.10.20 reproduces identically at the same depth (`poc_output_310_crash.txt`).

**Same PoC, same raised limit, Python 3.12.3 — even at 10x the depth, safe:**
```
$ python3.12 poc.py 200000 raiselimit
recursion limit=100000, depth=200000
built 1600005 bytes, decoding...
caught (safe): InvalidBSON: maximum recursion depth exceeded while decoding a BSON document
exit code: 0
```

Python 3.13.12 reproduces the same safe result (`poc_output_313_safe.txt`).

Full raw output: `poc_output_311_crash.txt`, `poc_output_311_default_safe.txt`, `poc_output_312_safe.txt` (included in this directory).

## Reachability

Any application calling `bson.BSON(data).decode()`, `bson.decode(data)`, or (via `pymongo`) receiving and decoding a query result, a `find_one`, an aggregation stage, or any other server response goes through this exact `_cbsonmodule.c` decode path when the C extension is loaded (the default; pymongo falls back to the pure-Python decoder, which is unaffected — see Honest Caveats). The only precondition beyond "a malicious or compromised server, or an on-path attacker on an unencrypted/improperly-verified connection, returns one crafted document" (the same threat model already accepted for the C#-driver sibling, #3790290/#3996918) is that the connecting process must be running CPython 3.10 or 3.11 **and** must have, somewhere in its lifetime before the crash, called `sys.setrecursionlimit()` to a value large enough to disable the guard's protection at the attacker's chosen nesting depth (I used 100,000; the real threshold is lower and depends on per-frame stack usage and the process's configured stack size). Raising the recursion limit globally is a real, documented pattern used to work around unrelated `RecursionError`s (deep template rendering, deep tree/graph traversal, some YAML/JSON libraries) — once raised, it affects every C extension in the process that relies on `Py_EnterRecursiveCall`, including this one, for the rest of the process's life.

## Impact

On CPython 3.10 or 3.11, a process that has ever raised `sys.setrecursionlimit()` above its real native-stack-safe threshold can be crashed unconditionally and without warning by a single crafted document in an otherwise ordinary query response, exactly like the accepted C#-driver finding — except here the crash is `SIGSEGV`, not a language-level uncatchable exception, so it also risks corrupting shared process state (other threads, memory-mapped files, unflushed buffers) rather than a clean unwind. No exception, no `try`/`except`, and no `signal`-based handler installed for anything other than `SIGSEGV` itself can intervene. For a long-running server process this takes down the entire process, not just the request or thread handling it.

## Suggested Fix

- Cap the effective recursion depth pymongo's own decode path will pursue, independent of the process's global `sys.getrecursionlimit()` — e.g. an explicit depth parameter threaded through `get_value`/`_elements_to_dict`/`_get_object`, checked against a fixed, conservative maximum (100–200, matching MongoDB server's own document nesting limit) before ever calling `Py_EnterRecursiveCall`, so pymongo's own safety does not depend on an application-wide setting it does not control.
- Apply the same fix to the pure-Python decoder path (`bson/__init__.py`'s `_get_object`/`_get_array`/`_elements_to_dict`) for defense-in-depth, even though it is not independently vulnerable to this exact crash (see caveats).

## Honest Caveats

- **Requires two preconditions beyond the base "malicious/compromised server" threat model**: (1) CPython 3.10 or 3.11 specifically — 3.12+ is unaffected at the interpreter level, and 3.9 and earlier were not tested but are architecturally similar to 3.10/3.11 and plausibly also affected; (2) the embedding process must have called `sys.setrecursionlimit()` to a sufficiently high value at some point before decoding the malicious document. Neither precondition is attacker-controlled or attacker-granted — they're properties of the victim's own deployment — but I want to be explicit that this is a narrower, conditional finding compared to the unconditional crashes already confirmed in `mongo-csharp-driver` and (separately reported by me) `mongo-go-driver`, both of which require no such precondition.
- **The pure-Python fallback decoder (`bson/__init__.py`, used when the C extension isn't available/loaded) was checked and is not equivalently vulnerable**: Python-level recursion there is bounded by the same `sys.getrecursionlimit()`, but exceeding it raises a normal, always-catchable `RecursionError`-derived exception at the *Python* interpreter level (no native C stack risk from CPython's own bytecode dispatch loop at these depths) rather than exhausting the native call stack the way native C recursion does — I did not attempt to construct a case where this also segfaults, and current evidence suggests it doesn't.
- Did not determine the precise minimum recursion-limit value or nesting depth needed to trigger the crash (I used round, comfortably-over-threshold numbers: limit 100,000, depth 20,000) — the real threshold depends on per-process stack size (`ulimit -s`) and would need to be profiled per-deployment for an exact minimum.
- Did not test CPython 3.9 or earlier, or non-CPython implementations (PyPy), for lack of readily available interpreters in this environment.
- No access to HackerOne's private report database — cannot rule out this has already been reported, though the specific "guard exists and is correctly wired, but its safety envelope is transitively controlled by an unrelated process-wide setting, and is fixed only by an unrelated CPython version upgrade" framing is fairly distinctive and different in shape from every other report in this bug class seen so far this engagement.

## Supporting Material

- Recursion guard call sites: [`bson/_cbsonmodule.c#L3017-L3021`](https://github.com/mongodb/mongo-python-driver/blob/8e7ece47f3c5a3908ef886d431c3dcc3feb56316/bson/_cbsonmodule.c#L3017-L3021) (document), [`bson/_cbsonmodule.c#L2282-L2288`](https://github.com/mongodb/mongo-python-driver/blob/8e7ece47f3c5a3908ef886d431c3dcc3feb56316/bson/_cbsonmodule.c#L2282-L2288) (array element)
- `poc.py` (PoC source), `poc_output_311_crash.txt`, `poc_output_310_crash.txt`, `poc_output_311_default_safe.txt`, `poc_output_312_safe.txt`, `poc_output_313_safe.txt` (included in this directory)
