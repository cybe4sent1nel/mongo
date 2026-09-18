# Title

`MongoCryptImpl` still has the exact check-then-act native-handle race that `MongoCryptContextLifetime` (commit `be53a3e117`) was written to eliminate — unpatched sibling one level up the object graph, on the native `mongocrypt_t` handle instead of the `mongocrypt_ctx_t` handle the fix covers

## Summary

Commit `be53a3e117` fixed a real native heap use-after-free: `MongoCryptContextImpl` and `MongoKeyDecryptorImpl` each wrap a native libmongocrypt handle (`mongocrypt_ctx_t` / `mongocrypt_kms_ctx_t`) behind a `closed` flag, but the flag was checked once at the top of each method (`isTrue("open", !closed)`) and not held for the duration of the native call that followed — a classic check-then-act TOCTOU. If `close()` ran on another thread between the check and the native call (the fix's own description: *"cancellation races a KMS credential fetch in reactive encryption"* — i.e. a `Mono`/`Flux` subscriber cancellation calling `close()` concurrently with an in-flight KMS callback still using the context), the native call would dereference memory `mongocrypt_ctx_destroy` had already freed. The fix introduces `MongoCryptContextLifetime`, a `ReentrantLock`-backed wrapper whose `guarded()` method holds the lock for the *entire* native call, and whose `close()` takes the same lock — making the check-and-call atomic with respect to destruction.

**`MongoCryptImpl` — the class one level up, which owns the top-level `mongocrypt_t` handle and is what actually constructs every `MongoCryptContextImpl` the fix protects — has the identical pattern, untouched by the fix:**

```java
// mongodb-crypt/src/main/com/mongodb/internal/crypt/capi/MongoCryptImpl.java (current, on latest tag r5.12.0)
class MongoCryptImpl implements MongoCrypt {
    private final mongocrypt_t wrapped;
    private final AtomicBoolean closed;

    @Override
    public MongoCryptContext createEncryptionContext(final String database, final BsonDocument commandDocument) {
        isTrue("open", !closed.get());                 // <-- check
        notNull("database", database);
        notNull("commandDocument", commandDocument);
        return createMongoCryptContext(commandDocument, createNewMongoCryptContext(),   // <-- act, not guarded
                (context, binary) -> mongocrypt_ctx_encrypt_init(context, new cstring(database), -1, binary));
    }

    // same isTrue(...) then act pattern in:
    //   createDecryptionContext, createDataKeyContext, createExplicitEncryptionContext,
    //   createEncryptExpressionContext, createExplicitDecryptionContext,
    //   createRewrapManyDatakeyContext

    private mongocrypt_ctx_t createNewMongoCryptContext() {
        mongocrypt_ctx_t context = mongocrypt_ctx_new(wrapped);   // <-- native call on `wrapped`, unguarded
        ...
    }

    @Override
    public void close() {
        if (!closed.getAndSet(true)) {
            mongocrypt_destroy(wrapped);                // <-- frees `wrapped`, no lock held with the calls above
        }
    }
}
```

Every one of `createEncryptionContext`, `createDecryptionContext`, `createDataKeyContext`, `createExplicitEncryptionContext`, `createEncryptExpressionContext`, `createExplicitDecryptionContext`, and `createRewrapManyDatakeyContext` checks `closed.get()` (an `AtomicBoolean`, so the check itself is atomic — but nothing else is) and then, entirely outside any lock, goes on to call `mongocrypt_ctx_new(wrapped)` and a chain of `mongocrypt_ctx_setopt_*`/`mongocrypt_ctx_*_init` calls, all against `wrapped`. If another thread's `close()` interleaves between the `isTrue` check and any of those native calls — the same interleaving the original fix's own description identifies as reachable via reactive-driver cancellation — `mongocrypt_destroy(wrapped)` has already freed the native `mongocrypt_t`, and the in-flight thread dereferences it: the same native heap use-after-free class as the parent CVE, one object up the ownership chain.

`getCryptSharedLibVersionString()` is worse still — it has **no `closed` check of any kind**:
```java
@Override
public String getCryptSharedLibVersionString() {
    cstring versionString = mongocrypt_crypt_shared_lib_version_string(wrapped, null);   // no isTrue(), no lock
    return versionString == null ? null : versionString.toString();
}
```

## Why this matters as much as the fixed bug

`MongoCryptImpl` is the object that *hands out* every `MongoCryptContextImpl` the parent fix protects (`createMongoCryptContext(...)` at the end of each `create*Context` method constructs `new MongoCryptContextImpl(context)`). It sits directly upstream in the same reactive Client-Side Field Level Encryption / Queryable Encryption call path the fix's own commit message names as the trigger for the original bug (KMS credential fetch racing cancellation). A `MongoCryptImpl` is typically held for the lifetime of a `ClientEncryption`/auto-encryption-enabled client and `close()`d on client shutdown or explicit `ClientEncryption.close()` — exactly the kind of call that can legitimately race in-flight reactive operations still calling `createEncryptionContext`/`createDecryptionContext`/etc. from an event-loop thread when a subscriber cancels or a client is closed mid-operation.

## Weakness

CWE-416 (Use After Free) via CWE-367 (TOCTOU race condition) on a native resource — identical classification to the parent-fixed bug (CVE-2026-88032 was reported against this exact `closed` boolean pattern one class down).

## Component / Version

- Repository: `mongodb/mongo-java-driver`
- Confirmed present in `mongodb-crypt/src/main/com/mongodb/internal/crypt/capi/MongoCryptImpl.java` on the latest tagged release `r5.12.0` — the very same tag containing the `MongoCryptContextLifetime` fix this is a sibling of.

## Suggested fix

Apply the same `MongoCryptContextLifetime`-style guard (a `ReentrantLock` held for the full duration of each native call, including `close()`) to `MongoCryptImpl`'s `wrapped: mongocrypt_t` handle — the class already exists and is `final class MongoCryptContextLifetime` in the same package, so this is a direct reuse:

```java
class MongoCryptImpl implements MongoCrypt {
    private final mongocrypt_t wrapped;
    private final MongoCryptContextLifetime lifetime = new MongoCryptContextLifetime();

    @Override
    public MongoCryptContext createEncryptionContext(final String database, final BsonDocument commandDocument) {
        notNull("database", database);
        notNull("commandDocument", commandDocument);
        return lifetime.guarded(() -> createMongoCryptContext(commandDocument, createNewMongoCryptContext(),
                (context, binary) -> mongocrypt_ctx_encrypt_init(context, new cstring(database), -1, binary)));
    }
    ...
    @Override
    public void close() {
        lifetime.close(() -> mongocrypt_destroy(wrapped));
    }
}
```
(and add the missing `closed`/guard check to `getCryptSharedLibVersionString()`, which currently has none at all).

## Suggested repro (static analysis only — not executed against a live server in this environment)

1. Using the CSFLE/QE reactive streams driver, start an auto-encryption operation (e.g. an encrypted `insertOne`) that reaches `MongoCryptImpl.createEncryptionContext` on a reactor event-loop thread, and arrange for the underlying `Mono`/`Flux` to be slow enough to hold in `createNewMongoCryptContext()`/`mongocrypt_ctx_encrypt_init(...)` (e.g. via a test hook or a deliberately slow KMS mock, mirroring how the original bug's own regression tests simulate the credential-fetch race).
2. From a second thread, call `close()` on the owning `ClientEncryption`/ `MongoCryptImpl` while step 1 is still inside the window between its `isTrue("open", !closed.get())` check and the native `mongocrypt_ctx_*` calls that follow.
3. Expect a native crash (segfault) or corrupted native heap state from the encryption-thread's call touching the just-freed `mongocrypt_t`, matching the parent bug's own reported impact one object down.

## Notes on scope

Found while directly sibling-hunting the Java driver's own `be53a3e117` (`MongoCryptContextLifetime`) fix, on the theory that a hand-rolled `closed`-flag guard fixed in one wrapper class is worth checking in every sibling class wrapping a native libmongocrypt handle in the same package — `MongoKeyDecryptorImpl` was already covered by the fix (it now shares the same `MongoCryptContextLifetime` instance as its owning context); `MongoCryptImpl`, one level further out, was not. Fresh finding, not part of the originally reviewed CVE list, not yet reported upstream.
