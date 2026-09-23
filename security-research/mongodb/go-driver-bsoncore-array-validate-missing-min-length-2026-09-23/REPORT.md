# Title

`bsoncore.Array.Validate()` is missing the `length < 5` lower-bound check that `bsoncore.Document.Validate()` has — unpatched sibling of CVE-2026-93395 (libbson `bson_new_from_buffer()` integer underflow), causing a negative-index panic (crash/DoS) reachable via the public `bson.RawArray.Validate()` API

## Summary

CVE-2026-93395 (fixed in libbson/libmongoc 1.30.11) was an integer underflow in the C driver's `bson_new_from_buffer()`: the function read a 32-bit little-endian length prefix off raw bytes and used it directly to index `data[length - 1]` (a null-terminator check) without first validating `length >= 5` (the minimum possible BSON document size: 4-byte length + 1-byte terminator). A crafted zero/near-zero length caused `length - 1` to underflow, producing a heap out-of-bounds read that crashed the process.

The Go driver's own from-scratch BSON implementation (`x/bsonx/bsoncore`) has the identical guard on its document-validation path but is missing it on the parallel array-validation path:

```go
// x/bsonx/bsoncore/document.go:400-434 — Document.Validate() — CORRECT
length, rem, ok := ReadLength(d)
...
if int(length) > len(d) { return NewDocumentLengthError(...) }
if length < 5 { return ErrInvalidLength }        // lower-bound check present
if d[length-1] != 0x00 { return ErrMissingNull }
```

```go
// x/bsonx/bsoncore/array.go:168-178 — Array.Validate() — MISSING THE SAME CHECK
func (a Array) Validate() error {
	length, rem, ok := ReadLength(a)
	if !ok { return NewInsufficientBytesError(a, rem) }
	if int(length) > len(a) { return NewArrayLengthError(int(length), len(a)) }
	if a[length-1] != 0x00 { return ErrMissingNull }   // <-- no `length < 5` guard first
	...
```

`ReadLength` only rejects `length < 0`. A 4-byte input of `0x00 0x00 0x00 0x00` (declared length = 0) passes `ReadLength` (0 is not negative) and passes `int(length) > len(a)` (`0 > 4` is false), then reaches `a[length-1]` = `a[-1]`, an out-of-range slice index. Go's bounds-checked slices turn this into a runtime panic rather than silent memory corruption, but it is the exact same missing-lower-bound root cause (CWE-191/CWE-125-adjacent) as the CVE, in the sibling function that the CVE's own fix pass evidently didn't reach.

## Impact

Any caller that validates or parses an attacker-influenced BSON array through this path — most directly the public `bson.RawArray.Validate()` API (`bson/raw_array.go:71-73`, a thin wrapper: `return bsoncore.Array(a).Validate()`) — will panic and crash the process on a 4-byte array payload of all zero bytes. `RawArray` is the driver's "parse raw bytes into an array" entry point, reachable from application code that receives raw BSON bytes from an untrusted source (a document field, a message from another service, a file) and validates it via the driver before further use. An unrecovered panic in a Go server terminates the goroutine/process, i.e. a denial-of-service condition — the same severity class MongoDB itself assigned to CVE-2026-93395 (CVSS 6.9, DoS via crash).

## Weakness

CWE-191 (Integer Underflow) leading to CWE-125-class out-of-bounds access, downgraded from memory-unsafe (C) to a bounds-checked panic (Go) — same root cause as CVE-2026-93395, missing sibling guard.

## Component / Version

- Repository: `mongodb/mongo-go-driver`
- File: `x/bsonx/bsoncore/array.go`, `Array.Validate()`
- Confirmed present, byte-identical, on both the default branch `master` (commit `77d80c7`) and the latest release tag `v2.9.1` (commit `f6f67b9`) — `git show v2.9.1:x/bsonx/bsoncore/array.go` was diffed against `master` and the relevant lines are unchanged.
- Note: `Array.DebugString()`/`Array.StringN()` in the same file already guard with `len(a) < 5` (lines 53, 94) — only `Validate()` lacks the check, suggesting a straightforward oversight rather than a deliberate omission.

## Proof of Concept

Verified by actually building and running the code (not source review alone), via a `go.mod replace` pointing at the checked-out repository.

```go
package main

import (
	"fmt"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

func main() {
	data := []byte{0x00, 0x00, 0x00, 0x00} // 4-byte length prefix = 0

	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("PANIC RECOVERED (bsoncore.Array.Validate):", r)
			}
		}()
		err := bsoncore.Array(data).Validate()
		fmt.Println("no panic, err:", err)
	}()

	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("PANIC RECOVERED via bson.RawArray.Validate():", r)
			}
		}()
		err := bson.RawArray(data).Validate()
		fmt.Println("no panic, err:", err)
	}()
}
```

Output:
```
PANIC RECOVERED (bsoncore.Array.Validate): runtime error: index out of range [-1]
PANIC RECOVERED via bson.RawArray.Validate(): runtime error: index out of range [-1]
```

Both the low-level `bsoncore.Array` type and the public `bson.RawArray` wrapper crash on this 4-byte input, confirming the finding is reachable through the driver's public API surface, not just an internal helper.

## Suggested fix

Add the missing lower-bound check to `Array.Validate()`, mirroring `Document.Validate()`:

```go
func (a Array) Validate() error {
	length, rem, ok := ReadLength(a)
	if !ok {
		return NewInsufficientBytesError(a, rem)
	}
	if int(length) > len(a) {
		return NewArrayLengthError(int(length), len(a))
	}
	if length < 5 {
		return ErrInvalidLength
	}
	if a[length-1] != 0x00 {
		return ErrMissingNull
	}
	...
```

## Notes on scope

Found while sibling-hunting CVE-2026-93395 (libbson integer underflow in `bson_new_from_buffer()`) across all official MongoDB driver BSON implementations. libbson itself (mongo-c-driver, `src/libbson/src/bson/bson.c` and `bson-iter.c`/`bson-reader.c`) was audited first and found clean — every length-prefix read site there already carries the correct `length < 5` guard, consistent with a thorough upstream fix. This Go driver finding is a genuinely independent, unpatched sibling in a different codebase that implements the same BSON format from scratch. Not part of the originally published CVE, not yet reported upstream.
