# Follow-up: XXE audit

**Status: not applicable — merino-py's own source code never parses XML at all.** Stronger than
"mitigated"; the vulnerable primitive (an XML parser resolving external entities) doesn't exist
anywhere in this codebase.

## What was checked

Repo-wide grep across `apps/` and `packages/` non-test code for every XML-parsing entry point:
`import xml`/`from xml` (stdlib `xml.etree.ElementTree`, `xml.dom.minidom`, `xml.sax`, `expat`),
plus the common third-party parsers `lxml`, `feedparser`, `xmltodict`, `defusedxml`. Exactly one
line matched, and it was a false positive: a base64-looking string literal in a large static data
table (`domain_category_mapping.py`) that happens to contain the substring `sax`, not an
`xml.sax` import.

## The one place that looked like it should parse XML — and doesn't

The codebase has an `rss` provider package (`apps/merino/merino/providers/rss/`) with a
`wikimedia_potd` backend — naming that strongly suggests RSS/Atom (XML) feed consumption. Read
the full backend implementation (`backends/wikimedia_potd.py`) plus its `base.py`, `manager.py`,
and `utils.py`: despite the package name, the current implementation fetches Wikimedia's
**Featured API** and **Commons API**, both JSON endpoints — every response is consumed via
`response.json()` or Pydantic's `model_validate_json()`, never through any XML/feed parser. The
"rss" naming appears to be a holdover from an earlier implementation (or just an organizational
label); there is no live RSS/XML ingestion in the current code.

## Conclusion

No XXE finding, for the strongest possible reason: there's nothing here that parses XML. This
closes out the item flagged as unchecked in the original RCE/SQLi audit
(`README.md` in this same directory).

## Explicitly out of scope for this check

Third-party dependencies (`httpx`, `google-cloud-storage`, `elasticsearch`, etc.) may parse XML
internally for their own protocols (e.g., some cloud SDKs use XML for certain APIs) — auditing
those libraries' own XXE posture is a different task from auditing merino-py's application code,
and wasn't attempted here.
