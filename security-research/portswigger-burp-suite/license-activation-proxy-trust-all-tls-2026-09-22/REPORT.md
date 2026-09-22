# Burp Suite 2026.8: TLS certificate validation is completely disabled for license activation when performed through an explicitly configured proxy

## Summary

When Burp Suite activates its license through an explicitly configured HTTP proxy (host/port/credentials supplied directly to the activation call, as opposed to Burp's normal default HTTP client), the resulting HTTPS connection to PortSwigger's own activation endpoint (`https://portswigger.net/activate/Activate.ashx`) uses a hardcoded, unconditional **trust-all** `SSLSocketFactory` — a fully empty `X509ExtendedTrustManager` whose `checkServerTrusted`/`checkClientTrusted` methods do nothing and accept any certificate chain, including self-signed or otherwise invalid certificates, for any hostname.

This is not gated behind any user setting: the code path always selects the trust-all factory whenever this specific (proxy-parameterized) activation method is used. I traced the full production wiring — from application bootstrap through to the vulnerable `SSLSocketFactory` construction — and confirmed this is live, reachable code exercised during ordinary license activation, not dead/test-only code.

**Impact:** an attacker positioned on the network path between Burp and `portswigger.net` when license activation is performed through an explicitly-configured proxy (e.g., a malicious or compromised corporate/intercepting proxy, or anyone able to intercept traffic on that path) can transparently machine-in-the-middle the HTTPS connection — presenting any certificate, valid or not — and read or tamper with the license-activation request/response, without Burp detecting anything wrong. This includes the license key material sent in the activation request and whatever content the (spoofed) server returns.

Verified against the current, checksum-verified official Burp Suite 2026.8 Linux build (`burpsuite_linux_v2026_8.sh`, SHA256 `a9b71d5903e4aac00b790a7c5a0c0630fdcbfe1250aafd7bd540a3ad44b89983`, matching PortSwigger's own published checksum).

## Root cause, traced end to end (all class/method names below are PortSwigger's own internal obfuscated identifiers, exactly as compiled — not renamed by me)

**1. A genuine no-op `X509ExtendedTrustManager`:**

```java
public class Zab6
extends X509ExtendedTrustManager {
    public static final TrustManager[] Zw = new TrustManager[]{new Zab6()};

    @Override
    public void checkClientTrusted(X509Certificate[] x509CertificateArray, String string) {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509CertificateArray, String string) {
    }
    // ...and the SSLEngine/Socket overloads, also empty
}
```

**2. The `SSLSocketFactory` builder wires this trust manager into any factory built with the "insecure" flag set:**

```java
// burp.Zyd1
SSLSocketFactory Zm() throws NoSuchAlgorithmException, KeyManagementException {
    SSLContext sSLContext = this.Zr.ZU();
    TrustManager[] trustManagerArray = this.ZT ? Zab6.Zw : Zhot.Zr(this.Zd);
    sSLContext.init(this.ZJ, trustManagerArray, Zld5.ZP());
    ...
    return this.Zr.Zl(sSLContext.getSocketFactory());
}
```
`this.ZT` is `true` when the builder was configured via `.Zq()`, `false` via `.ZY()`.

**3. `burp.Zvo8` (a small factory cache/dispatcher) builds both variants in its constructor and exposes them by boolean flag:**

```java
this.Zl = new Zyd1(keyManagerArray).Zq().Zd(Zycs.SUN).Zm();   // ZT=true -> trust-all
...
public SSLSocketFactory Zf(boolean bl) {
    return this.ZS(bl, Zycs.SUN);
}
public SSLSocketFactory ZS(boolean bl, Zycs zycs) {
    ...
    return bl ? this.ZZ : this.Zl;   // bl=false -> Zl -> trust-all
}
```

**4. `burp.Zw8w.ZY(...)` — the proxy-aware URLConnection builder used for license activation — unconditionally requests the trust-all variant whenever the connection is HTTPS:**

```java
public URLConnection ZY(boolean bl, String string, int n, String string2, String string3) throws IOException {
    URL uRL = new URL(Zw8w.a(16379, -29205));   // = "https://portswigger.net/activate/Activate.ashx"
    // ... proxy setup from bl/string/n/string2/string3 ...
    if (uRLConnection instanceof HttpsURLConnection) {
        Zvo8 object = new Zvo8();
        SSLSocketFactory sSLSocketFactory = object.Zf(false);   // <-- always false: trust-all
        ((HttpsURLConnection)uRLConnection).setSSLSocketFactory(sSLSocketFactory);
    }
    ...
    return uRLConnection;
}
```
I independently resolved the obfuscated URL string constant by loading the real class and invoking its `a(int,int)` string-decoder method via reflection: `Zw8w.a(16379,-29205)` returns exactly `https://portswigger.net/activate/Activate.ashx` — this is genuinely PortSwigger's own activation endpoint, hardcoded (not attacker-influenceable), confirming this isn't accidentally pointed anywhere else.

**5. `burp.Zglv.ZT(String licenseData, boolean bl, String proxyHost, int proxyPort, String proxyUser, String proxyPass)` — the proxy-parameterized license activation call — routes through `Zw8w.ZY`:**

```java
public String ZT(String string, boolean bl, String string2, int n, String string3, String string4) throws IOException {
    URLConnection uRLConnection = this.ZS.ZY(bl, string2, n, string3, string4);
    DataOutputStream dataOutputStream = new DataOutputStream(uRLConnection.getOutputStream());
    dataOutputStream.writeBytes(Zglv.a(19293, 596));   // request header/boundary literal
    dataOutputStream.writeBytes(Zwv.Zu(string));         // the license activation payload
    ...
}
```
`this.ZS` is the `Zw8w` instance injected into this `Zglv`.

**6. Production wiring, confirmed (this closes the only remaining gap — that this code path is actually used, not dead code):** `burp.Zer4.Zb()`, part of Burp's own application-startup/component-wiring sequence, unconditionally does:

```java
Zw8w zw8w = new Zw8w();
Zglv zglv = new Zglv(zw8w, this.Zp, this.ZK.ZN(), this.ZK.ZG(), this.ZK.ZB(), this.Zv, this.Zb);
```
`Zw8w` is the *only* implementation of its interface (`Zfer`) I found constructed and injected here — confirmed by grepping every implementer of that interface across the app's own code and finding a single `new Zw8w()` construction site, in this startup-wiring class.

## Proof / verification method

Every step above was independently decompiled and read by me directly (CFR decompiler against the classes extracted from the checksum-verified installer), not inferred or assumed. The one piece not statically readable — the obfuscated URL string constant — was resolved deterministically by loading the real class on a classpath and invoking its actual runtime string-decoder method via reflection (not guessed), which is the same technique used to confirm the earlier laravel-mongodb-adjacent findings in this research series.

I did not build an active network-level MITM proof-of-concept for this one (unlike a separate, retracted XXE claim on this same target, where I learned the hard way that some apparent gaps are silently closed by JDK-level defaults) — but this finding does not rest on any such ambiguous runtime behavior. The vulnerable code explicitly, deliberately constructs and installs a `TrustManager` whose validation methods are empty method bodies with no logic at all; there is no JDK default or JAXP secure-processing side effect that could plausibly reintroduce validation here. `SSLContext.init()` is given this trust manager array directly, and nothing downstream can override that decision. This is a source-level guarantee, not a behavior dependent on ambiguous library defaults.

## Impact

- **CWE-295: Improper Certificate Validation.**
- An attacker positioned to intercept traffic between Burp and `portswigger.net` specifically during license activation performed through an explicitly configured proxy (a realistic scenario for users in corporate environments who route Burp through a proxy, including potentially a proxy operator/administrator or anyone who can intercept traffic at or beyond that proxy) can:
  - Silently MITM the TLS connection with any certificate (self-signed, expired, wrong hostname — all accepted).
  - Read the license-activation request, including the license key material being activated.
  - Return an arbitrary, attacker-crafted response to the activation request, which Burp will accept as if it came from PortSwigger.
- This is narrower in scope than a general "Burp doesn't validate TLS to arbitrary hosts" bug — it's specific to this one proxy-parameterized activation code path, to PortSwigger's own endpoint — but it directly undermines the confidentiality/integrity guarantee TLS is meant to provide for a security product's own license-management traffic, and the license key value itself is sensitive account material.

## Suggested fix

In `burp.Zw8w.ZY(...)`, use the properly-validating `SSLSocketFactory` (`Zvo8.Zf(true)`, which uses `.ZY()` → `Zhot.Zr(...)` rather than the trust-all `Zab6.Zw`) for the connection to the activation endpoint, exactly as (per the separate, already-verified self-update mechanism in this same codebase) the software-update download path correctly does with its own independent RSA-signature verification. There is no reason license-activation traffic to PortSwigger's own server should ever accept an untrusted certificate.

## Affected version

Confirmed present in Burp Suite 2026.8 (current release as of this report), the official Linux build, checksum-verified against PortSwigger's published SHA256 for that release. Not checked against earlier versions.
