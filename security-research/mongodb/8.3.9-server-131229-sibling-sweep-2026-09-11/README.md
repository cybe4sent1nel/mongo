# CVE-2026-82067 / SERVER-131229 sibling sweep — case-insensitive validator vs. case-sensitive consumer

**Result: no live sibling found.** The specific dangerous pattern behind this CVE — a config
validator accepting a case-variant value, and the actual consumer silently failing to recognize
it (server keeps running, feature silently off) — was checked against every other config option
sharing the same validator shape in the tree, and none reproduce it live.

## The bug and its fix, confirmed

`src/mongo/db/mongod_options_general.h`, `validateSecurityAuthorizationSetting`:
```cpp
inline Status validateSecurityAuthorizationSetting(const std::string& value) {
    if (!(value == "enabled"_sd || value == "disabled"_sd)) {   // now case-sensitive
        return {ErrorCodes::BadValue, "security.authorization expects either 'enabled' or 'disabled'"};
    }
    return Status::OK();
}
```
Per the ticket's own changelog note: before this fix, the validator (or the consumer, per the
ticket's phrasing — either way the net effect was the same) treated `"Enabled"`/`"eNaBlEd"` as
*not* matching `"enabled"`, and **silently left authorization off** rather than rejecting the
config outright. That's the dangerous shape: a value that looks superficially accepted, quietly
resulting in the opposite of the admin's intent, with the server still starting normally.

## Sweep method

Found every other config-option validator in the tree using the same
`str::equalCaseInsensitive`-based acceptance pattern (`grep -rl equalCaseInsensitive src/mongo/db`,
filtered to non-test files), then for each one traced its actual consumer to check: (a) does the
consumer do exact case-sensitive comparison against the validator-accepted values (the
precondition for this bug class), and if so, (b) is a case-mismatch's fallthrough **silent** (server
keeps running, feature quietly not applied — the dangerous shape) or **loud** (explicit `BadValue`
error, refusing to start — safe, fail-closed)?

## Findings, each checked

- **`operationProfiling.mode`** (`mongod_options_general.h`, `validateOperationProfilingModeSetting`)
  — validator accepts `off`/`slowOp`/`all` case-insensitively; consumer
  (`mongod_options.cpp:460-472`) does exact-case matching with an explicit `else` branch returning
  `ErrorCodes::BadValue` ("Bad value for operationProfiling.mode..."). **Loud, fail-closed.** Not
  the dangerous shape — worth a minor code-quality note (validator/consumer disagree on what's
  "valid", so a technically-accepted value like `"SlowOp"` fails startup with a confusing error
  instead of either working or being rejected up front) but not a security bug.

- **`sharding.clusterRole`** (`mongod_options_sharding.h`, `validateShardingClusterRoleSetting`) —
  validator accepts `configsvr`/`shardsvr` case-insensitively. Consumer has **both** shapes present
  in the same file: a loud check (`mongod_options.cpp:641-662`, explicit `BadValue` on mismatch)
  *and* two silent-looking ones with no `else` branch at all (`mongod_options.cpp:222-225` and
  `718-721`, e.g. `setConfigRole = setConfigRole || clusterRole == "configsvr";` with nothing
  triggered if that's false). This looked like the strongest candidate for a live sibling, so I
  tested it directly rather than trusting the static read: started the real 8.3.9 binary with
  `sharding.clusterRole: "ConfigSvr"` (wrong case) in a YAML config file. **Result: startup refused
  outright** — `BadValue: Bad value for sharding.clusterRole: ConfigSvr. Supported modes are:
  (configsvr|shardsvr)`. The loud check runs earlier in startup and aborts the process before the
  silent-looking lines are ever reached — they're effectively dead code for this specific failure
  mode, not a live gap. **Ruled out empirically, not just read from source.**

- **`systemLog.destination`** (`server_options_base.cpp`, `validateSystemLogDestinationSetting`) —
  same shape, validator accepts `syslog`/`file` case-insensitively; consumer
  (`server_options_helpers.cpp:389-408`) has an explicit loud `else` branch. **Fail-closed,** same
  as the others.

- Remaining `equalCaseInsensitive` call sites in the tree (`fts_spec.cpp`, `fts_spec_legacy.cpp`,
  `key_string_decode.cpp`, `database_holder_impl.cpp`, `database_name.h`,
  `create_database_util.cpp`, `wiredtiger_global_options.cpp`) are runtime string-comparison logic
  unrelated to startup config-option validation (FTS language/tokenizer matching, key-string
  decoding, database-name normalization) — not instances of this specific validator/consumer bug
  shape, so not relevant siblings for this particular class.

## Conclusion

Every other config option sharing this validator pattern fails closed (loud startup error) on a
case-mismatched value, including one (`sharding.clusterRole`) that had a code shape closely
resembling the vulnerable one and needed a live test to be sure. `security.authorization` appears
to have been the one place this actually resulted in silent, fail-open behavior — consistent with
it being the one that got a CVE. No fresh finding to report for this CVE's sibling class.
