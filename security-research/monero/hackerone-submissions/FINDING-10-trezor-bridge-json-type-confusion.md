# `monero-wallet-cli`/`monero-wallet-gui` crash (and undefined behavior in release builds) from a malicious or spoofed Trezor Bridge response, in code left un-hardened by a recent sibling fix to the same file

## Summary

A recent commit ("device_trezor: validate bridge response size before parsing") added a missing length check to `BridgeTransport::read()` before it processes a hex-encoded response from the local Trezor Bridge HTTP service. Two other functions in the same file that consume the Bridge's plain JSON responses — `BridgeTransport::enumerate()` and `BridgeTransport::open()` — were not touched by that fix and still perform **no type validation at all** on the parsed JSON before indexing into it and dereferencing the result.

The Trezor Bridge HTTP client connects over plaintext (`ssl_support_t::e_ssl_support_disabled`) to `127.0.0.1:21325` by default. Any local process that can occupy that port ahead of the genuine Bridge, or a compromised/malicious Bridge installation, can serve a JSON response that isn't shaped the way this code assumes — and the wallet will parse it with rapidjson's unchecked accessors, which are guarded only by `assert()`-based checks (`RAPIDJSON_ASSERT`) that are compiled out in Monero's normal Release build (`-DNDEBUG`).

## Severity

Monero severity: **LOW-to-MEDIUM** ("must be carefully exploited" / individual-client crash; requires local co-residence with, or compromise of, the Trezor Bridge service — the same threat model the maintainers already accepted as worth a dedicated fix in the sibling commit for this exact file).
Suggested CVSS v3.1: `4.4` with `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`.

Rationale:
1. Requires local access to the machine's loopback interface (to preempt or MITM the Bridge's `127.0.0.1:21325` service) or a compromised Bridge installation — not remotely exploitable over the network (`AV:L`).
2. Once positioned, no interaction beyond the user's normal act of opening their Trezor hardware wallet in `monero-wallet-cli`/`monero-wallet-gui` is required (`AC:L/PR:N/UI:N`).
3. Impact is process termination/undefined behavior in the wallet, not a memory-corruption primitive I have identified a concrete exploitation path for beyond crash — scored `A:H/C:N/I:N`, matching a hardware-wallet-workflow denial-of-service class.

## Affected Versions

Confirmed present, identically, in both:
- **`master`**, commit `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f` (the actively maintained branch):
  https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/device_trezor/trezor/transport.cpp#L385-L387
  https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/device_trezor/trezor/transport.cpp#L429
- **`v0.18.5.1`**, the latest tagged release, commit `4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5`:
  https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/device_trezor/trezor/transport.cpp#L378-L380
  https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/device_trezor/trezor/transport.cpp#L422

This predates, and is untouched by, the recent size-validation fix to `BridgeTransport::read()` in the same file — that fix addressed response *length*, this report addresses response *type/shape*, a different validation gap in the same trust boundary.

## Root Cause

`src/device_trezor/trezor/transport.cpp`, `invoke_bridge_http()` (in `transport.hpp`) only validates that the Bridge's HTTP response has status 200 and parses as *some* JSON — it never checks the parsed JSON's shape:

```cpp
bool t_deserialize(const std::string & in, json & out){
  if (out.Parse(in.c_str()).HasParseError()) {
    throw exc::CommunicationException("JSON parse error");
  }
  return true;
}
```

`BridgeTransport::enumerate()` then immediately treats the result as an array of objects, each with a string `"path"` field, with no checks at any step:

```cpp
void BridgeTransport::enumerate(t_transport_vect & res) {
  json bridge_res;
  std::string req;
  bool req_status = invoke_bridge_http("/enumerate", req, bridge_res, m_http_client);
  if (!req_status){
    throw exc::CommunicationException("Bridge enumeration failed");
  }

  for(rapidjson::Value::ConstValueIterator itr = bridge_res.Begin(); itr != bridge_res.End(); ++itr){
    auto element = itr->GetObject();
    auto t = std::make_shared<BridgeTransport>(boost::make_optional(json_get_string(element["path"])));
    ...
```

`BridgeTransport::open()` does the analogous unchecked access on `/acquire/<path>/null`'s response:

```cpp
void BridgeTransport::open() {
  ...
  bool req_status = invoke_bridge_http(uri, req, bridge_res, m_http_client);
  if (!req_status){
    throw exc::CommunicationException("Failed to acquire device");
  }

  m_session = boost::make_optional(json_get_string(bridge_res["session"]));
  ...
```

And `json_get_string()` itself unconditionally calls `.GetString()`:

```cpp
static std::string json_get_string(const rapidjson::Value & in){
  return std::string(in.GetString());
}
```

None of `Value::Begin()`/`Value::End()` (require the value to be an Array), `Value::GetObject()` (requires Object), `Value::operator[](const Ch*)` (requires the named member to exist), or `Value::GetString()` (requires String) are preceded anywhere in this call chain by the corresponding `IsArray()`/`IsObject()`/`HasMember()`/`IsString()` check. rapidjson's own implementation only guards these preconditions with `RAPIDJSON_ASSERT`, which expands to the standard `assert()` and is compiled out under `-DNDEBUG` — the flag Monero's own build system sets for `Release` builds (the project's default/normal packaging configuration). In a Release build, calling `Begin()`/`GetObject()`/`operator[]`/`GetString()` on a JSON value of the wrong shape is undefined behavior (type-confused reinterpretation of rapidjson's internal tagged-union storage as array/object/string fields it isn't); in a Debug build, it is a guaranteed `abort()`.

Concretely, any of the following malformed-but-still-syntactically-valid-JSON responses trigger this:
- `/enumerate` responds with anything that isn't a JSON array (e.g. `{}`, `null`, `42`, `"error"`) → `bridge_res.Begin()`/`.End()` operate on a non-array `Value`.
- `/enumerate` responds with an array containing a non-object element (e.g. `[1,2,3]`) → `itr->GetObject()` operates on a non-object `Value`.
- `/enumerate` responds with an array of objects that lack a `"path"` key (e.g. `[{}]`) → `element["path"]` hits `operator[]`'s unconditional not-found assertion path.
- `/acquire/<path>/null` responds with a non-object JSON value, or an object lacking `"session"` (a very plausible response shape for an error body such as `{"error":"wrong previous session"}`, which the real Trezor Bridge itself returns in some conditions with HTTP 200) → `bridge_res["session"]` fails the same way.
- Any of the above fields present but not a JSON string (a number, `null`, an array) → `json_get_string()`'s unconditional `.GetString()` call fails the same way even when the enclosing object/array shape is otherwise correct.

## Steps to Reproduce

### 1. Build the wallet CLI with Trezor hardware-wallet support

```
git clone --branch v0.18.5.1 --depth 1 --recursive https://github.com/monero-project/monero.git
cd monero
mkdir -p build/release && cd build/release
cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_TESTS=OFF -D USE_DEVICE_TREZOR=ON ../..
make -j"$(nproc)" wallet_cli
```

### 2. Stand up a fake Trezor Bridge on the default port, ahead of any real one

```python
#!/usr/bin/env python3
# poc_fake_trezor_bridge.py
#
# Minimal stand-in for the real Trezor Bridge daemon on 127.0.0.1:21325.
# Serves a syntactically-valid but structurally-malformed JSON response to
# /enumerate, matching none of the shapes BridgeTransport::enumerate()
# assumes without checking.

import http.server
import json

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(length)  # drain the request body

        if self.path == "/enumerate":
            # Not a JSON array -- BridgeTransport::enumerate() calls
            # bridge_res.Begin()/.End() on this without an IsArray() check.
            body = json.dumps({"unexpected": "shape"}).encode()
        else:
            body = json.dumps({"version": "2.0.0"}).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass

if __name__ == "__main__":
    server = http.server.HTTPServer(("127.0.0.1", 21325), Handler)
    print("[fake-bridge] listening on 127.0.0.1:21325")
    server.serve_forever()
```

```
python3 poc_fake_trezor_bridge.py
```

### 3. Start the wallet and trigger hardware-wallet device enumeration

```
./bin/monero-wallet-cli --generate-new-wallet /tmp/monero-poc-trezor/testwallet \
  --restore-from-seed <any-valid-testnet-seed> --hw-device Trezor --testnet --daemon-address 127.0.0.1:38081
```

(Any wallet-cli invocation or in-CLI command that triggers Trezor device enumeration/open — e.g. `--hw-device Trezor` at startup, or the equivalent path in `monero-wallet-gui` — reaches `BridgeTransport::enumerate()`/`open()`.)

### Expected result on the vulnerable build

- **Release build**: the process crashes (SIGSEGV or similar) or exhibits other undefined behavior while handling the `/enumerate` response, rather than reporting a clean "device not found"/"bridge error" message the way a genuinely absent Bridge or a benign non-matching response would.
- **Debug build** (for a clean, unambiguous confirmation signal): the process aborts with a `RAPIDJSON_ASSERT` failure (`assert` trap) at `rapidjson::GenericValue::Begin()` (or the equivalent failing call), pinpointing the exact unchecked accessor.

## Possible Solution

Add the same discipline the sibling fix applied to response length, to response shape, before any rapidjson accessor that assumes a type:

```cpp
void BridgeTransport::enumerate(t_transport_vect & res) {
  json bridge_res;
  std::string req;
  bool req_status = invoke_bridge_http("/enumerate", req, bridge_res, m_http_client);
  if (!req_status){
    throw exc::CommunicationException("Bridge enumeration failed");
  }
  if (!bridge_res.IsArray()){
    throw exc::CommunicationException("Bridge enumeration: unexpected response shape");
  }

  for(rapidjson::Value::ConstValueIterator itr = bridge_res.Begin(); itr != bridge_res.End(); ++itr){
    if (!itr->IsObject() || !itr->HasMember("path") || !(*itr)["path"].IsString()){
      MWARNING("Bridge enumeration: skipping malformed device entry");
      continue;
    }
    auto element = itr->GetObject();
    ...
```

and similarly guard `bridge_res.IsObject() && bridge_res.HasMember("session") && bridge_res["session"].IsString()` in `open()` before calling `json_get_string(bridge_res["session"])`. Consider also hardening `json_get_string()` itself to check `in.IsString()` and throw a clean `CommunicationException` rather than relying on every call site to check first.

## Impact

A local attacker (or a compromised/malicious Trezor Bridge installation) can crash `monero-wallet-cli`/`monero-wallet-gui` — or trigger undefined behavior in a Release build — on the very first Trezor hardware-wallet interaction, by serving a syntactically-valid JSON response that doesn't match this code's unchecked shape assumptions. This affects any user relying on Trezor hardware-wallet support, a widely-used security feature for protecting private keys.

## Note on AI usage

Source-code analysis (continuing from the size-only scope of the already-shipped sibling fix to identify the untouched type-validation gap in the same file, tracing rapidjson's `RAPIDJSON_ASSERT`-based precondition checks and confirming they compile out under the project's own `-DNDEBUG` Release build configuration) and drafting of this report were done with AI assistance, working directly against the `v0.18.5.1` and `master` source. **This has been verified by static code reading only, including confirming the exact unchecked accessor chain (`Begin()`/`End()`, `GetObject()`, `operator[]`, `GetString()`) against the current source and against rapidjson's documented precondition-assertion behavior — it has not been verified with a live reproduction against a running `monero-wallet-cli` process.** Please run the reproduction (or a debug build, for the clearest crash signal) and attach the resulting crash log/backtrace before submitting, per this program's requirement for a working PoC with logs.
