# mozilla-services/merino-py: audit for RCE and SQLi

**Status: no vulnerability found.** Clean result, but a substantive one — several of the classic
sinks for both bug classes are structurally absent from this codebase, and the ones that exist
use the safe/parameterized pattern rather than string-built queries or scripts.

Repo: `mozilla-services/merino-py`, `main`, commit `c2a06177b3698b73e5b8c7392a8688e3b2918b2b`
(2026-08-27). Merino is Mozilla's backend service for Firefox's address-bar/New-Tab suggestions
(a FastAPI app fronting several data backends: Elasticsearch, Redis, GCS, BigQuery, Pub/Sub).

## SQLi: not applicable — there is no SQL database in this service

Checked `apps/merino/pyproject.toml` for the actual data-store dependencies: Elasticsearch,
Redis, Google Cloud Storage, BigQuery, Pub/Sub. No `sqlalchemy`, `psycopg`, `asyncpg`, `mysql`, or
`sqlite3` dependency anywhere. Grepped the whole app tree for SQL-shaped code
(`SELECT`/`INSERT`/`UPDATE`/`DELETE`, `.execute(`, `sqlalchemy`) and found exactly one hit: a
static, hardcoded BigQuery SQL string in
`apps/merino/merino/jobs/navigational_suggestions/io/domain_data_downloader.py` — no
user/request input is ever interpolated into it; it's run as-is by an internal batch job. No
relational database is in the request-serving path at all, so classic SQL injection has no
target here.

The closest analogous risk — Elasticsearch query-DSL injection on the user-facing Wikipedia
suggest path — was checked directly:
`apps/merino/merino/providers/suggest/wikipedia/backends/elastic.py:search()` builds the query as
a Python dict (`{"prefix": q, "completion": {...}}`) passed to the official `elasticsearch` async
client, which JSON-serializes it properly — the user's search string `q` becomes a JSON string
value, never concatenated into a raw query/script text. This is the same protection model as a
parameterized SQL query: there's no character sequence in `q` that lets it escape the string
context it's placed in. No `query_string`/`simple_query_string` (raw Lucene syntax) or `script`/
`scripted_metric`/Painless usage found anywhere in the app (grepped for all of these) — those
would have been the closer analogues to worry about (Lucene syntax injection, or Painless
scripting reintroducing an ES-side RCE-shaped risk), and neither is used.

## RCE: every classic sink checked, all clean

Repo-wide grep for `eval(`, `exec(`, `pickle.*`, `marshal.loads`, `yaml.load(`, `subprocess`,
`os.system`, `__import__`, `importlib` in non-test app code turned up exactly four hits, each
traced:

- `jobs/csv_rs_uploader/__init__.py`: `importlib.import_module(f".{model_name}", ...)` —
  `model_name` is a CLI argument to an operator-run batch job (uploading CSV data), never derived
  from an HTTP request. Not attacker-reachable.
- `jobs/utils/domain_tester.py`: `ast.literal_eval(...)` — safe by construction; only parses
  Python literal structures, cannot execute code regardless of input.
- `utils/logos.py`: `importlib.resources.files` — standard-library static resource loading, no
  dynamic name.
- `curated_recommendations/ml_backends/gcs_interest_cohort_model.py`: `self._cohort_model.eval()`
  — this is `torch.nn.Module.eval()` (inference mode), not Python's `eval()` builtin; a
  false-positive match on the grep.

No `subprocess`/`os.system`/shell-out call anywhere in the app code at all (confirmed by the same
repo-wide grep coming back empty for those specifically) — no command-injection sink exists in
this codebase.

Also checked the ML-model-loading path specifically, since deserializing a model file is a classic
RCE vector (`torch.load` is pickle-based and executes arbitrary code embedded in a malicious
tensor file) — `gcs_interest_cohort_model.py` deliberately uses `safetensors.torch.safe_open`
instead of `torch.load`. `safetensors` is a flat tensor-storage format with no pickle/executable
payload capability by design, specifically created to close this exact vector. Good choice on the
maintainers' part; not exploitable even if the backing GCS blob were somehow attacker-influenced.

Checked Redis server-side scripting (`register_script`, used in the Polygon/finance and
AccuWeather backends) for the "script text built from user input" version of Lua injection: both
call sites register a fixed, hardcoded Lua script constant once at startup; per-request values
are passed as script arguments (`KEYS`/`ARGV`), not interpolated into the script source. Same safe
"code vs. data" separation as a parameterized SQL query.

No `Jinja2`/template-rendering usage found anywhere in the app (it's a JSON API, not an
HTML-templating service), so server-side template injection (SSTI) isn't a relevant surface
either. No `debug=True`/`reload=True` on the FastAPI/uvicorn app (ruling out the
Werkzeug-debugger-style "debug console gives you code execution" class, though that's a
Flask/Werkzeug pattern more than a FastAPI one regardless).

## What this pass did not cover

This was a grep-driven sweep for the sinks that actually matter for these two specific bug
classes (RCE, SQLi), not a full line-by-line review of all ~800 files. Not examined this round:
- XML parsing of any RSS/Atom feeds the curated-recommendations pipeline might ingest (XXE is a
  different bug class from what was asked, but worth a look if there's appetite — XXE can lead to
  SSRF/local file read via external entity expansion).
- The full request-validation layer (`web/models_v1.py`) for anything that could let oversized or
  malformed input reach the ES/Redis calls in a way this pass didn't anticipate.
- Deserialization of any other external data format (e.g., how BigQuery/GCS job outputs get
  parsed) beyond the model-loading path specifically checked above.
