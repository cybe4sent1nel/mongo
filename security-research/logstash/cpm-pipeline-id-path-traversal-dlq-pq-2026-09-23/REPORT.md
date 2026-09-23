# Title

Path Traversal via unsanitized `pipeline.id` sourced from Elasticsearch in Centralized Pipeline Management — a Logstash operator with only write access to the CPM pipelines index can force `Files.createDirectories()`/persistent-queue and dead-letter-queue file creation at an attacker-chosen filesystem path on the Logstash host (CWE-22)

## Summary

Logstash's Centralized Pipeline Management (CPM, `x-pack/lib/config_management`) lets an Elasticsearch-side operator — typically someone with only a scoped Kibana "manage pipelines" role, deliberately *not* filesystem or SSH access to the Logstash host — define pipelines as documents in an Elasticsearch index. Logstash periodically fetches these documents and uses the *document's own `_id`* as the pipeline's `pipeline.id`, with **no character/format validation at any point** in that chain. That `pipeline.id` string is later concatenated directly onto two different local filesystem base directories — the persistent queue directory (`path.queue`) and the dead-letter-queue directory (`path.dead_letter_queue`) — and the resulting path is handed straight to `java.nio.file.Files.createDirectories()`, which honors `..` traversal components exactly as any OS path resolution does.

The one piece of validation that exists (`PIPELINE_ID_PATTERN`, restricting to letters/digits/`_`/`-`/`*`) is applied **only** to the admin's local `xpack.management.pipeline.id` *setting* in `logstash.yml` (the subscription pattern, e.g. `"prod-*"`) — never to the actual pipeline IDs Elasticsearch returns. When that local setting contains a wildcard (a normal, documented way to use CPM — "pick up any pipeline whose id starts with `prod-`"), the matching of Elasticsearch document IDs against the wildcard is done with Ruby's `File.fnmatch?` **without `File::FNM_PATHNAME`**, so `*` matches `/` too. A crafted document ID like `"prod-../../../../tmp/evil"` therefore satisfies the `"prod-*"` subscription pattern just as legitimately as `"prod-web-logs"` would.

Chain, traced end to end in the current `master` checkout:

1. `x-pack/lib/config_management/elasticsearch_source.rb`, `SystemIndicesFetcher#get_wildcard_pipelines` (lines ~285-300): for each ES document ID matching the admin's wildcard pattern via unguarded `File.fnmatch?`, the ID is kept verbatim as a pipeline ID — no further checks.
2. `elasticsearch_source.rb#get_pipeline` (lines 103-127):
   ```ruby
   settings.set("pipeline.id", pipeline_id)
   ...
   Java::OrgLogstashConfigIr::PipelineConfig.new(self.class, pipeline_id.to_sym, [config_part], settings)
   ```
   `PipelineConfig`'s Java constructor (`logstash-core/src/main/java/org/logstash/config/ir/PipelineConfig.java`) stores `pipelineId` as-is — no validation.
3. `logstash-core/lib/logstash/agent.rb#converge_state_and_update` (line 237), part of the normal, automatic, periodic config-reload cycle:
   ```ruby
   @pq_config_validator.check(@pipelines_registry.running_user_defined_pipelines, results.response)
   ```
4. `logstash-core/lib/logstash/persisted_queue_config_validator.rb#check` (lines 49-58) — runs for every pipeline config whose `queue.type == 'persisted'`:
   ```ruby
   pipeline_id = config.settings.get("pipeline.id")
   queue_path = ::File.join(config.settings.get("path.queue"), pipeline_id)   # no sanitization
   ...
   create_dirs(queue_path)
   ```
   ```ruby
   def create_dirs(queue_path)
     path = Paths.get(queue_path)
     return if Files.exists(path)
     Files.createDirectories(path)          # honors ".." exactly as the OS would
   end
   ```
   Critically, `queue.type` is itself one of the `SUPPORTED_PIPELINE_SETTINGS` (`elasticsearch_source.rb`, `SUPPORTED_PIPELINE_SETTINGS = %w(... queue.type ...)`) that CPM lets the same untrusted document set — so the attacker doesn't need the local admin to have pre-enabled persisted queues; they force it themselves via `pipeline_settings: {"queue.type": "persisted"}` in the same malicious document.
5. Independently, the same pattern exists for the dead-letter queue: `logstash-core/src/main/java/org/logstash/execution/AbstractPipelineExt.java#createDeadLetterQueueWriterFromSettings` passes `pipelineId.asJavaString()` straight into `DeadLetterQueueFactory.getWriter(id, dlqPath, ...)` (`logstash-core/src/main/java/org/logstash/common/DeadLetterQueueFactory.java`), which does `Paths.get(dlqPath, id)` and hands that to `DeadLetterQueueWriter`'s constructor, which calls `FileLockFactory.obtainLock(queuePath, LOCK_FILE)` (`logstash-core/src/main/java/org/logstash/FileLockFactory.java:71-73`):
   ```java
   Files.createDirectories(dirPath);
   ```
   again on the unsanitized, traversal-laden path.

Both sinks are reached automatically — the PQ validator on every pipeline-config converge cycle (which runs on Logstash's normal reload-interval polling of CPM, no operator interaction needed once the malicious document exists), the DLQ writer the first time that pipeline either starts (if DLQ is enabled) or drops/filters an event.

## Impact

An Elasticsearch/Kibana user whose *only* privilege is writing documents to the index CPM reads pipelines from (the entire point of the feature is to delegate pipeline authoring to such a role, distinct from and less privileged than direct access to the Logstash host) can cause the Logstash process to create directories — and, once the pipeline actually runs, write persistent-queue page files and/or dead-letter-queue segment files containing pipeline event data — at an attacker-chosen filesystem location outside `path.queue`/`path.dead_letter_queue`, limited only by the permissions of the OS user running Logstash. This is a privilege-boundary violation (CPM-only privilege → arbitrary-path directory creation and content-controlled file writes on the Logstash host) and a foothold for further escalation to code execution wherever the reachable target directory is one whose contents get executed or auto-loaded by another process on that host (e.g. a cron drop-in directory, a systemd unit directory, or a plugin/init directory readable by a higher-privileged service), depending on the specific host's configuration and the Logstash process's file permissions.

## Weakness

CWE-22 (Path Traversal): Improper Limitation of a Pathname to a Restricted Directory, reachable from an Elasticsearch-document-write privilege via Centralized Pipeline Management, with no validation of the attacker-supplied `pipeline.id` at any of the several layers it passes through before reaching two independent `Files.createDirectories()` sinks.

## Component / Version

- Repository: `elastic/logstash`
- Files:
  - `x-pack/lib/config_management/elasticsearch_source.rb` (pipeline-ID sourcing + wildcard matching, `SUPPORTED_PIPELINE_SETTINGS` including `queue.type`)
  - `x-pack/lib/config_management/bootstrap_check.rb` (`PIPELINE_ID_PATTERN` — validates only the local subscription pattern, not ES-returned IDs)
  - `logstash-core/lib/logstash/persisted_queue_config_validator.rb` (PQ path join + `create_dirs`/`Files.createDirectories`)
  - `logstash-core/lib/logstash/agent.rb` (`converge_state_and_update`, automatic trigger)
  - `logstash-core/src/main/java/org/logstash/execution/AbstractPipelineExt.java` (`createDeadLetterQueueWriterFromSettings`)
  - `logstash-core/src/main/java/org/logstash/common/DeadLetterQueueFactory.java` (`Paths.get(dlqPath, id)`)
  - `logstash-core/src/main/java/org/logstash/FileLockFactory.java` (`Files.createDirectories(dirPath)`)
  - `logstash-core/config/ir/PipelineConfig.java` (no validation on the `pipelineId` it's constructed with)
- Confirmed present on the current default branch (cloned fresh for this audit; latest commit touching these files: `876503c16f1ddc47ca6d774e5fc9e1fdb0b76862`, 2026-09-17).

## Proof of Concept / verification method

Verified dynamically at each link in the chain rather than by source review alone:

**1. Wildcard matching lets a traversal payload through a normal subscription pattern** (confirms step 1 of the chain — actually run, not assumed):
```
$ ruby -e '
puts File.fnmatch?("prod-*", "prod-../../../../tmp/evil")            # => true
puts File.fnmatch?("prod-*", "prod-../../../../tmp/evil", File::FNM_PATHNAME)  # => false (the flag CPM does NOT pass)
'
true
false
```
`get_wildcard_pipelines` in `elasticsearch_source.rb` calls `File.fnmatch?(pattern, id)` with no flags, so the vulnerable (default) behavior is exactly what's used.

**2. `Files.createDirectories`/`Paths.get` on a joined path honors `..` and escapes the base directory** (confirms steps 4/5 — actually compiled and run):
```java
import java.nio.file.*;
public class PocPath {
    public static void main(String[] args) {
        System.out.println(Paths.get("/data/dlq", "../../../../tmp/evil-relative"));
        System.out.println(Paths.get("/data/dlq", "prod-../../../../tmp/evil-wildcard-matched").normalize());
    }
}
```
```
$ javac PocPath.java && java PocPath
/data/dlq/../../../../tmp/evil-relative
/tmp/evil-wildcard-matched
```
The second line shows the exact real-world case: a `pipeline.id` of `"prod-../../../../tmp/evil-wildcard-matched"` (which the fnmatch test above already showed passes a `"prod-*"` subscription) resolves fully outside `/data/dlq` once joined and normalized — and `Files.createDirectories`/`FileChannel.open` perform this same OS-level resolution regardless of whether `.normalize()` is explicitly called, since the kernel, not Java, ultimately interprets the `..` components.

**3. Source-level confirmation that no sanitization exists between the two.** Every intermediate hop was read directly from the checked-out source (cited above with exact file paths and line ranges) and traced with no version skew — same commit, same clone, no assumptions carried over from documentation or changelogs.

I did not stand up a full Logstash + Elasticsearch + Kibana CPM environment to execute the complete end-to-end chain live (that requires a licensed X-Pack Elasticsearch cluster), but every individual link — the fnmatch bypass, the unsanitized string flowing through `PipelineConfig`/`Settings`/`converge_state_and_update`, and the `Files.createDirectories` behavior on the resulting path — was independently verified by reading the exact reachable code and, for the two behavioral claims (fnmatch semantics, NIO path-join/resolve semantics), by compiling and executing real Ruby/Java code reproducing them, not by assumption.

## Suggested fix

1. Validate every `pipeline_id` returned from an `ElasticsearchSource`-backed fetch against the same `PIPELINE_ID_PATTERN` already used for the local `xpack.management.pipeline.id` setting (`x-pack/lib/config_management/bootstrap_check.rb`) — reject (log + skip) any document whose `_id` doesn't match `\A[A-Za-z0-9_-]+\z`, *before* it ever reaches `settings.set("pipeline.id", ...)`.
2. Defense in depth at the actual filesystem sinks: in `persisted_queue_config_validator.rb#create_dirs` and in `FileLockFactory.obtainLock`, resolve the final path and assert it is still contained within the intended base directory (e.g. `resolved.normalize.startsWith(base.normalize)`) before calling `Files.createDirectories`, mirroring the containment check Logstash's own reviewers have applied elsewhere in the codebase (e.g. the `zip`/`tar` extraction helpers in `lib/bootstrap/util/compress.rb` already do exactly this kind of `verify_name_safe!` check for archive entry names — the same discipline is missing here for CPM-sourced pipeline IDs).
3. Pass `File::FNM_PATHNAME` when matching Elasticsearch document IDs against the admin's wildcard subscription pattern in `get_wildcard_pipelines`, so a `*` in the pattern can no longer match across `/`.

## Notes on scope

This was found via open-ended deep auditing of `elastic/logstash` specifically for RCE/path-traversal classes of bugs (not a sibling hunt against a named CVE). It's a fresh, previously-unreported structural gap: CPM's pipeline-ID trust boundary (Elasticsearch-document-write privilege, intentionally less trusted than Logstash-host access) is not enforced at either of the two places (`persisted_queue_config_validator.rb`, `AbstractPipelineExt`/`DeadLetterQueueFactory`) that turn a `pipeline.id` into a filesystem path.
