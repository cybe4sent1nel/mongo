# Title

Mongoid — a model whose only encrypted fields live on an `embeds_many` association is silently excluded from the encryption schema and the new `NoEncryptionSchema` safety net alike, so `field :x, encrypt: true` inside an `embeds_many` relation is written in plaintext forever with zero error or warning — gap left by the CVE-2026-93763/93764 fix in `v9.1.1`

## Status note / scope

Continuation of sibling-hunting the same CVE batch (93758, 93759, 93760, 93762, 93763, 93764, 93765) via fix commit `91cc55dacfb68339b50628b489626f8319fd21b1`, after the atomic-operation `send(field)` finding (see sibling report `mongoid-atomic-pop-pull-push-method-dispatch-2026-09-20/REPORT.md`) and after auditing the CVE-93758 nested-attributes fix (which looks solid — see "CVE-93758 audit" below). This one is about the encryption-schema-generation fix for CVE-2026-93763/93764.

## Summary

The fix commit adds `Encryptable#requires_encryption_schema?` and `#embeds_encrypted?` (`lib/mongoid/encryptable.rb`) to make sure a *parent* model gets an encryption-schema entry even when the encrypted fields actually live on an `embeds_one` child:

```ruby
# lib/mongoid/encryptable.rb:370-374
def requires_encryption_schema?
  return @requires_encryption_schema if defined?(@requires_encryption_schema)
  @requires_encryption_schema = encrypted? || embeds_encrypted?([ self ])
end

# lib/mongoid/encryptable.rb:388-400
def embeds_encrypted?(path)
  relations.each_value.any? do |relation|
    next false unless relation.is_a?(Association::Embedded::EmbedsOne)   # <-- embeds_many excluded, by design
    ...
    klass.encrypted? || klass.embeds_encrypted?(path + [ klass ])
  end
end
```

The `embeds_many is not considered` comment right above it explains why: libmongocrypt's automatic-encryption JSON Schema has no way to target a field inside array items, so there is genuinely no schema Mongoid could emit that would make libmongocrypt encrypt a field on a document embedded via `embeds_many`. That much is a real backend limitation, not a Mongoid bug, and I'm not filing "please support it" — that would be the "unrealistic scenario" mistake of asking for something the underlying dependency cannot do.

**What's missing is the other half of what this exact commit otherwise does everywhere else: fail loudly instead of writing plaintext silently.** The same commit adds a brand-new `Errors::NoEncryptionSchema` and wires it into `PersistenceContext#verify_encryption_schema!` specifically so that "no schema for this model → refuse the write" replaces "no schema for this model → silently store plaintext" (their own comment on the callable-database case: *"Writes are refused later, by PersistenceContext, rather than silently going out unencrypted."*). That safety net is never reached for the `embeds_many` case, because it is gated by the exact same `requires_encryption_schema?` predicate that `embeds_encrypted?` was written to under-report for this relation type:

```ruby
# lib/mongoid/persistence_context.rb (new in this commit)
def verify_encryption_schema!(client)
  klass = @object.is_a?(Class) ? @object : @object.class
  return unless klass.respond_to?(:requires_encryption_schema?) && klass.requires_encryption_schema?
  ...
  raise Errors::NoEncryptionSchema.new(klass, namespace, client_name)
end
```

If `Patient` only reaches its encryption via `embeds_many :notes` (where `Note#content` is `encrypt: true`), `Patient.requires_encryption_schema?` is `false` — so this method returns on the first line, no matter what. Nothing else in the codebase checks `embeds_many` relations for encrypted content, either directly or indirectly.

Net effect: a developer declares `field :content, type: String, encrypt: { deterministic: true }` on `Note`, `Note.encrypted?` correctly and truthfully reports `true` (nothing about that predicate looks at how `Note` is embedded), and yet if `Note` is only ever used through `embeds_many` on some parent, that field is written to MongoDB **in plaintext, unconditionally, forever**, with no exception raised, no warning logged, and no indication anywhere in the API that this particular field never actually got encrypted. `Model.encrypted?` returning `true` is the exact API a developer would check to convince themselves this is handled — and it lies for this case.

## Live PoC — executed, not traced

Same repo checkout as the sibling report (`v9.1.1`, `bundle install` already done, no MongoDB/mongocryptd needed — this only exercises schema-generation logic, not an actual encrypted write):

```ruby
require 'mongoid'

# Same shape as the gem's own Crypt::Patient/Crypt::Insurance test fixture
# (spec/support/crypt/models.rb), except the embedded relation is
# embeds_many instead of embeds_one -- an entirely ordinary modeling choice
# (a patient has many notes, not just one).
class Patient
  include Mongoid::Document
  field :code, type: String
  embeds_many :notes, class_name: 'Note'
end

class Note
  include Mongoid::Document
  field :content, type: String, encrypt: { deterministic: true }
  embedded_in :patient
end

puts "Mongoid::VERSION = #{Mongoid::VERSION}"
puts
puts "Note.encrypted?                    = #{Note.encrypted?}"
puts "Note.requires_encryption_schema?   = #{Note.requires_encryption_schema?}"
puts "Patient.encrypted?                 = #{Patient.encrypted?}"
puts "Patient.requires_encryption_schema?= #{Patient.requires_encryption_schema?}"
puts

map = Mongoid::Config::Encryption.encryption_schema_map('appdb', [Patient, Note])
puts "encryption_schema_map('appdb', [Patient, Note]) = #{map.inspect}"
```

**Actual, complete, unedited output:**
```
Mongoid::VERSION = 9.1.1

Note.encrypted?                    = true
Note.requires_encryption_schema?   = true
Patient.encrypted?                 = false
Patient.requires_encryption_schema?= false

encryption_schema_map('appdb', [Patient, Note]) = {}
```

`Note.encrypted?` is `true` (correctly reflecting the declared field), but `Patient` — the model whose collection the field actually lands in — never gets a schema entry, and (traced statically, since exercising this requires a real `auto_encryption_options` client + mongocryptd, which this sandbox doesn't have) `Patient.requires_encryption_schema?` being `false` means `verify_encryption_schema!` returns on its first line and never raises. A real deployment with `notes.content` declared encrypted this way persists that field as plain UTF-8 text in every document, indefinitely, with the application team having every reason to believe (from `Note.encrypted?` and from the field declaration itself) that it is not.

## Impact

- Same impact class as CVE-93763/93764 (plaintext storage of a field the developer explicitly declared encrypted), scoped to the `embeds_many` case the fix commit deliberately, but silently, carved out.
- No exploitation step is needed beyond ordinary application use — this isn't attacker-triggered, it's a silent correctness/confidentiality gap that fires on every write, for every application that encrypts a field on a model embedded via `embeds_many`. That's a different risk shape than the other CVEs in this batch (no untrusted input involved), but the same "sensitive field stored in plaintext against the developer's explicit intent" outcome CVE-93763/93764 were filed for.
- Whether this rises to a CVE of its own or is better handled as a documentation/warning issue is a judgment call for the triager — I'd lean toward at least a `Mongoid::Warnings` deprecation-style warning at model-load time (mirroring how `allow_reparenting_via_nested_attributes` already gets one) plus a `NoEncryptionSchema`-style raise on first persist, since the commit's own stated design principle ("refuse the write rather than silently go out unencrypted") already covers this case in spirit — it just isn't wired up for it.

## CVE-93758 audit (no further sibling found)

Also checked the `MONGOID-5992` fix for CVE-93758 (nested-attributes cross-principal IDOR) in `lib/mongoid/association/nested/many.rb` and `nested_buildable.rb`. It:
- Uniformly gates the "reparent an existing document by id" branch behind `Mongoid.allow_reparenting_via_nested_attributes?` (now `default: false` in `lib/mongoid/config.rb:148`) for every association type, closing the specific bug where HABTM associations reached the dangerous `unscoped.find` branch unconditionally regardless of the flag.
- Rejects non-scalar ids (`Hash`/`Array`) in `convert_id`, closing the operator-injection variant (`{"$gt" => ""}` surviving into an id query).
- Ignores a destroy of a document not in the association for every association type, not just when the flag is on.

I checked `Nested::One` (the builder used for `has_one`/`embeds_one` nested attributes) for the same class of bug and it isn't exposed: it only ever compares the submitted id against `existing._id` (the parent's own already-loaded association target) and never performs an external `klass.find`/`unscoped.find` lookup by id, so there is no cross-principal document to substitute in the first place. I also confirmed `lib/mongoid/association/nested/many.rb:202` is the only `.unscoped.find` call in the entire `lib/` tree, so there's no equivalent unscoped-lookup-then-mass-assign pattern hiding elsewhere. I don't have a fresh sibling to report for 93758.

## Weakness

CWE-311 (Missing Encryption of Sensitive Data) / CWE-703 (Improper Check or Handling of Exceptional Conditions) — the model's own encryption declaration is silently unenforced instead of raising, for one specific, common relation shape.

## Component / Version

- Repository: `mongodb/mongoid`
- Confirmed present on `v9.1.1` (commit `381d954edf3812f138e53b940123126619713a03`)
- Files: `lib/mongoid/encryptable.rb:376-400` (`embeds_encrypted?`, `EmbedsOne`-only by design), `lib/mongoid/config/encryption.rb:149-177` (`properties_for_relations`, same `EmbedsOne`-only walk), `lib/mongoid/persistence_context.rb` (`verify_encryption_schema!`, gated by the same predicate)

## Suggested fix

Not "support embeds_many encryption" (not feasible per libmongocrypt's own constraints, per the vendor's own comment). Instead, detect the case and fail loudly at the same point the commit already fails loudly for the callable-database case:

- At class-definition time (when `embeds_many` is declared, or lazily on first `encrypted?`/`requires_encryption_schema?` check), if any `EmbedsMany`-related class declares encrypted fields, raise or warn (`Mongoid::Warnings`-style) that those fields cannot be covered by an automatic-encryption schema.
- Alternatively, extend `verify_encryption_schema!` to check `EmbedsMany` relations for encrypted content specifically so it can raise `NoEncryptionSchema` (or a new, more precisely-worded error) instead of returning silently.

Either keeps the commit's own stated principle — refuse instead of silently persisting plaintext — consistent across every relation shape, not just the ones it happened to test.

## Notes on scope

Found and confirmed via the gem's real code (`bundle exec ruby`), no MongoDB/mongocryptd required since this only exercises schema-generation and predicate logic, not an actual encrypted write. I have not attempted to stand up a real `auto_encryption_options` client + mongocryptd/KMS to observe the plaintext write happen end-to-end in a live database — the schema-map/predicate results shown above are sufficient to establish the gap deterministically without that, and I did not fabricate or extrapolate any numbers beyond what's printed above.
