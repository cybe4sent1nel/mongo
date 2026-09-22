# `database-query-mongodb` MCP tool: server-side JavaScript execution bypasses the tool's "read-only" guarantee (DoS)

## Summary

`mongodb/laravel-mongodb`'s Laravel Boost / MCP integration ships a tool, `MongoDB\Laravel\Tools\DatabaseQuery`, that is explicitly documented and annotated as safe for an AI agent to call autonomously: it is marked `#[IsReadOnly]`, its description says *"Execute a read-only MQL command... Only read commands are allowed"*, and its own code comment says the aggregation-stage allow-list exists specifically so unsafe operations are "rejected by default."

The tool's actual enforcement only checks the **top-level command name** (`aggregate`/`count`/`distinct`/`find`) and, for `aggregate`, only the **stage names** in the pipeline. It never inspects the *contents* of a filter/stage body. As a result, any caller of this tool — including a prompt-injected AI agent that has been auto-granted this "read-only" tool without human review, which is the entire point of the `#[IsReadOnly]` annotation in MCP/agentic frameworks — can smuggle MongoDB's server-side JavaScript-execution operators (`$where` in a `find`/`count`/`distinct` filter, or `$expr.$function`/`$expr.$accumulator` inside an allowed aggregation stage such as `$match`/`$project`/`$group`) straight through to the server. This is not a "read" operation in any meaningful security sense — it runs attacker-supplied code inside the mongod process, defeating the tool's core safety claim and enabling denial of service (and, depending on server configuration/version, a strictly larger footprint than a data read).

This is live in the current stable release: `src/Tools/DatabaseQuery.php` at HEAD is **byte-identical** to the file shipped in the latest tagged release, `5.11.0` (`git diff 5.11.0 HEAD -- src/Tools/DatabaseQuery.php` is empty), and has been unchanged since it was introduced in commit `1bf7f53` ("PHPLARA-251: Create database query tool for Boost", first released in `5.9.0`).

## Where

`src/Tools/DatabaseQuery.php`, method `handleMql()` (line ~103) and `ensureNoNestedWriteInAggregation()` (line ~130).

```php
private function handleMql(array $command, Connection $connection): array
{
    if ($command === []) {
        throw new InvalidArgumentException('Please pass a valid MongoDB command');
    }

    // Allowed CRUD commands (https://www.mongodb.com/docs/manual/reference/mql/crud-commands/)
    $allowList = ['aggregate', 'count', 'distinct', 'find'];
    $operation = array_key_first($command);

    if (! in_array($operation, $allowList, true)) {
        throw new InvalidArgumentException(sprintf('Only read commands are allowed (%s).', implode(', ', $allowList)));
    }

    if ($operation === 'aggregate') {
        // Check nested write ops recursively with conservative allow list
        $this->ensureNoNestedWriteInAggregation($command['pipeline'] ?? []);
    }

    return $connection->getDatabase()->command($command)->toArray();
}
```

Two independent gaps:

1. **`find` / `count` / `distinct` get no content validation at all.** Only `aggregate` triggers `ensureNoNestedWriteInAggregation()`. A `find`/`count`/`distinct` command's `filter`/`query` document is forwarded to `$connection->getDatabase()->command($command)` completely unexamined — including a `$where` key, which MongoDB evaluates as a JavaScript function/expression against every scanned document.

2. **`aggregate`'s stage-body content is never inspected, only stage *names*.** `ensureNoNestedWriteInAggregation()` walks the pipeline and checks each `$stageName` (e.g. `match`, `project`, `group`) against an allow-list to block write stages (`$merge`/`$out`), and only recurses into `facet`/`lookup`/`unionWith` to find *nested pipelines* that might smuggle a write stage. It never looks inside the body of an allowed stage like `$match`, so `{"$match": {"$expr": {"$function": {...}}}}` sails through unchanged — `$function` (and `$accumulator`) let the caller supply an arbitrary JavaScript function body that MongoDB executes server-side per document.

The `tests/Tools/DatabaseQueryTest.php` test suite confirms this is an actual gap, not an intentionally-scoped design choice with a compensating control elsewhere: it only exercises `$merge`/`$out` rejection nested in `lookup`/`unionWith`/`facet` — nothing tests `$where`, `$expr`, `$function`, or `$accumulator`.

## Proof of concept

Verified empirically against a real `mongod` (v8.3.9) instance, sending the *exact* command documents `handleMql()` would forward unmodified (via `Database::command()`, the same driver call the tool uses):

**1. `find` with `$where` (bypasses validation entirely — only `aggregate` is checked):**

```json
{
  "connection": "<any configured mongodb connection>",
  "command": {
    "find": "users",
    "filter": {
      "$where": "function(){ var s = new Date(); while(new Date() - s < 2000) {}; return true; }"
    }
  }
}
```

Result: 5 documents in the test collection took **10.04s** to return (5 × 2s busy-loop, one execution per scanned document) — confirming the server-side JS body actually ran once per document, not just parsed.

**2. `aggregate` with `$expr.$function` inside an *allowed* stage (`$match` passes the stage-name allow-list; its body is never inspected):**

```json
{
  "connection": "<any configured mongodb connection>",
  "command": {
    "aggregate": "users",
    "pipeline": [
      { "$match": { "$expr": { "$function": {
        "body": "function(){ var s = new Date(); while(new Date() - s < 1500) {}; return true; }",
        "args": [],
        "lang": "js"
      } } } }
    ],
    "cursor": {}
  }
}
```

Result: **7.51s** for the same 5-document collection — confirming the `$function` body executed per document, and that `ensureNoNestedWriteInAggregation()`'s allow-list check (which only validates the stage *name*, `match`) does not stop it.

Both commands would be accepted as-is by `DatabaseQuery::handle()` for any of the four permitted top-level operations; nothing in the class rejects `$where`/`$expr`/`$function`/`$accumulator` at any point.

Reproduction environment: `mongod --dbpath ... --port 27117` (local, no auth, for isolated testing only), driven via `pymongo`'s `db.command(...)` to send the identical MQL documents the PHP tool would issue through `MongoDB\Database::command()`. No PHP/Composer environment was needed for this half of the proof since the vulnerable PHP code path was already fully confirmed by direct source reading (`handleMql()`/`ensureNoNestedWriteInAggregation()` shown above never touch filter/stage-body content) — the mongod test isolates and confirms the server-side consequence of that gap.

## Impact

- **Denial of service**: an attacker-controlled `$where`/`$function`/`$accumulator` body can loop indefinitely or perform heavy computation per scanned document, tying up a database connection/thread and, at scale (large collections, concurrent calls), degrading or hanging the MongoDB server for all tenants of that connection.
- **Breaks the tool's explicit security contract in the exact context that matters most.** The `#[IsReadOnly]` annotation and "Only read commands are allowed" description exist so MCP-based agent frameworks can safely auto-approve this tool without per-call human confirmation — that is the entire value proposition of marking a tool read-only in an agentic-AI context. A prompt-injected AI agent (fed malicious instructions via an untrusted webpage, issue, file, or other content it processes) that has this tool available can be induced to invoke it with a `$where`/`$function` payload, executing attacker-chosen code inside the developer's/organization's MongoDB server with zero human awareness — precisely the scenario the read-only marking is supposed to make safe.
- Not a full data-write or OS-level RCE: MongoDB's server-side JS sandbox for `$where`/`$function`/`$accumulator` does not expose document-write primitives to the script body in current server versions, so this is scoped to code-execution-for-DoS (and any future MongoDB-engine-level JS sandbox vulnerability would be reachable through this same path) rather than data tampering.

## Suggested fix

Apply the same allow-list discipline already used for aggregation stage *names* to filter/stage *content*: reject any `$where` key in a `find`/`count`/`distinct` filter, and recursively reject `$function`/`$accumulator`/`$where` operators anywhere inside an aggregation stage body (not just at the top level), in addition to the existing write-stage-name check. Given the tool already walks the pipeline recursively for nested-write detection, the same recursive walk can check every key in every stage body against a denylist of JS-execution operators (`$where`, `$function`, `$accumulator`), independent of which stage they're nested under.

## Affected versions

Confirmed present in `mongodb/laravel-mongodb` `5.9.0` through the current `5.x` HEAD (tested at commit `0634653`, identical to tag `5.11.0`). Introduced in commit `1bf7f53` (PHPLARA-251).
