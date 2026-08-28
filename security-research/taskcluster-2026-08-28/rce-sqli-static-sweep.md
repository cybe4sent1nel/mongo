# taskcluster/taskcluster — RCE and SQLi static-analysis sweep

**Status: no exploitable bug found. Systematic, file-by-file sweep across every category the
request asked for; every promising lead traced to a concrete, verified safe conclusion.**

**Scope note before anything else:** this repo (`taskcluster/taskcluster`) is not itself
listed in the pasted Mozilla HackerOne program's asset table (that lists `www.mozilla.org`,
`www.firefox.com`, `vpn.mozilla.org`, `support.mozilla.org`, `relay.firefox.com`,
`monitor.mozilla.org`, `developer.mozilla.org` — no Taskcluster asset). This was a pure
static-source-code review of a public repo (no live testing, no scope violation either way),
done at explicit request; treat anything here as research value, not a submission-ready
Mozilla bounty report, without confirming Taskcluster's own security contact/scope first
(`SECURITY.md` in the repo is the right place to check for that).

Checked out at `ac99a93b` (2026-08-27, merge of PR #9019).

## Method

Went category by category rather than reading files at random, since "RCE or SQLi only" in
a ~2,700-file, multi-language monorepo (936 JS, 540 Go, 242 JSX, 110 Python, 72 SQL, 32 Rust)
needs a search strategy, not a linear read. For each hit, read the surrounding function fully
and traced the data back to its source before ruling it in or out — the same standard used
throughout this program for every other target.

## RCE surface

1. **Classic JS sinks (`child_process`, `eval`, `new Function`, `vm.*`)** — grepped the whole
   repo outside tests. Two real hits, both traced to dead ends:
   - `services/web-server/src/utils/unpromisify.js:20` — builds and `eval()`s a function
     signature string. Looked exploitable at a glance (`eval` + template string), but the
     interpolated `args` array is generated internally from `fn.length` (`arg0`, `arg1`, ...),
     never from any external input — confirmed by reading the whole 21-line file. The
     project's own `biome-ignore` comment already documents this ("No user input, args are
     all generated above and static").
   - `services/worker-manager/src/providers/azure/azure-ca-certs/download-certs.js` — five
     `execSync` calls building shell strings from `url`/`filename`. Traced the source: both
     come from a static, repo-committed `certificates.json` maintained by developers, read at
     build/maintenance time — not runtime request data. A one-off dev tool, not a live
     attack surface.
   - No other `eval`/`new Function`/`vm.runIn*` calls exist anywhere in the non-test source.

2. **GitHub-integration comment/command handling** (`services/github/`) — this looked like
   the most promising lead going in, since PR comments are attacker-reachable text and
   Taskcluster's GitHub app parses a `/taskcluster <command>` directive out of them
   (`getTaskclusterCommand` in `utils.js`). Traced its one use fully
   (`api.js` → `job.js`): the extracted string is placed into
   `event.taskcluster_comment` and handed to the repo owner's *own* `.taskcluster.yml`
   as JSON-e template data — it's exposed as a template variable, never interpreted,
   executed, or used to build a command inside the Taskcluster-GitHub service itself.
   The blast radius of whatever a commenter writes there is bounded by what the target
   repo's own CI config chooses to do with it, which is the repo owner's responsibility, not
   a vulnerability in the service.

3. **YAML deserialization** — `js-yaml`'s `yaml.load()` is used in ~13 places across the
   repo, including on data that traces back to a GitHub-hosted `.taskcluster.yml`
   (`services/github/src/api.js:972`, `handlers/index.js:578` — fetched via the GitHub API,
   base64-decoded, then parsed). In `js-yaml` v3.x, plain `load()` (as opposed to
   `safeLoad()`) is genuinely unsafe and accepts `!!js/function`/`!!js/undefined` type tags
   that can execute arbitrary code during parsing — would have been a real, critical,
   attacker-reachable RCE (any GitHub user able to edit `.taskcluster.yml` on a branch/PR
   could get code execution inside the `github` service's process). Checked
   `package.json`: pinned to `js-yaml@^4.3.1`. In v4, `load()` *is* the safe function
   (the unsafe API was removed, not just renamed) — confirmed this is the actual resolved
   version before ruling it out, not assumed from habit.

4. **Python `subprocess`/`os.system`** — repo-wide grep across all 110 `.py` files (mostly
   under `clients/client-py` and `tools/`) for `subprocess.*`, `os.system`, `os.popen`: zero
   hits outside tests. No Python shell-execution surface at all.

5. **Go worker command construction** (`workers/generic-worker`, `tools/d2g`) —
   generic-worker's entire purpose is to execute task-defined commands, so "the worker runs
   attacker-supplied commands" isn't itself a finding; the security-relevant question is
   whether task-payload fields can escape their intended argv-element boundary into
   something more privileged. Read the docker-worker→generic-worker translation layer
   (`tools/d2g/d2g.go`) end to end for this: image names, env var names/values, and cache/
   artifact paths are all assembled into Go string *slices* (`args = append(args, ...)`) that
   become individual `exec.Command` argv elements, not concatenated into a shell string — the
   safe pattern. No `sh -c`/string-interpolated shell invocation found built from task-payload
   fields in this layer.

6. **Dynamic `require()`/`import()`** — grepped for template-literal or request-derived
   module paths (`require(\`...\`)`, `require(req....)`) across `services/`: zero hits.

## SQLi surface

The entire runtime DB layer funnels through one chokepoint, `libraries/postgres/src/Database.js`,
which every service calls as `db.fns.<name>(...)`. Read this file's query-building code
directly rather than assuming an ORM-style wrapper is automatically safe:

- Stored-procedure calls are built as `` `select * from "${method.name}"(${placeholders})` ``
  with `values`/`args` passed as a **separate, parameterized** array to `client.query()` —
  the standard, correct pattern for calling a dynamically-named Postgres function (Postgres
  can't parameterize identifiers, only values, so the identifier is quoted and the values
  are `$1,$2,...`-bound).
- Confirmed `method.name` is never attacker-influenced: grepped every `db.fns.xxx(...)` call
  site across all services (~30+ call sites checked) and found exclusively static,
  hardcoded property names (`db.fns.get_client`, `db.fns.update_worker_pool_with_launch_configs`,
  etc.) — never a bracket/dynamic property access (`fns[userInput]`) anywhere in the codebase.
  The function name space is fixed at build time from the `db/` schema, not reachable from any
  request.
- Checked the other raw-string `client.query()` calls in `Database.js`/`migration.js`
  (`grant select on tcversion to ${username}`, `create extension ${ext}`, DB version-upgrade
  scripts): all administrative/migration-time code paths using deploy-time config
  (`usernamePrefix`, the fixed internal `schema.access.serviceNames()` list) — not reachable
  by an external request at runtime.
- Checked all 72 `.sql` files under `db/` for dynamic SQL construction inside stored
  procedures (`EXECUTE ...`, `format(...)` used to build a query string) — the classic
  PL/pgSQL injection pattern. Zero hits; no stored procedure in this codebase builds SQL
  dynamically at all.

## Assessment

Same conclusion pattern as most rounds this program: every immediately-plausible-looking
lead (the PR-comment command extraction, the YAML-parsing-of-repo-controlled-config path,
the docker→generic-worker translation layer, the dynamic-stored-procedure-name question)
traced to a genuine, verified-safe design decision rather than an assumption of safety. No
RCE or SQLi finding from this sweep.
