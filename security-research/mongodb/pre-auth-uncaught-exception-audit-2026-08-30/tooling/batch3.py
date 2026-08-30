#!/usr/bin/env python3
import sys
sys.path.insert(0, "/tmp/claude-0/-home-user-mongo/88417634-60f9-5bda-b080-646aad79e105/scratchpad")
import pymongo
from pymongo.errors import PyMongoError
from bson import Binary, Int64
from bson.decimal128 import Decimal128

HOST, PORT = "127.0.0.1", 27118


def is_alive():
    try:
        pymongo.MongoClient(HOST, PORT, serverSelectionTimeoutMS=2000).admin.command("ping")
        return True
    except Exception as e:
        print("Server appears DOWN:", repr(e))
        return False


unauth = pymongo.MongoClient(HOST, PORT, serverSelectionTimeoutMS=5000)

tests = [
    # hello/isMaster field fuzzing -- explicitly allowed pre-auth by design
    ("hello with malformed client metadata (empty driver name)",
     {"hello": 1, "client": {"driver": {"name": "", "version": ""}, "os": {"type": "x"}}}),
    ("hello with saslSupportedMechs malformed UserName (no dot)",
     {"hello": 1, "saslSupportedMechs": "not_a_valid_username_format"}),
    ("hello with saslSupportedMechs empty string",
     {"hello": 1, "saslSupportedMechs": ""}),
    ("hello with saslSupportedMechs huge string",
     {"hello": 1, "saslSupportedMechs": "a" * 1000000 + "." + "b" * 1000000}),
    ("hello with internalClient huge version numbers",
     {"hello": 1, "internalClient": {"minWireVersion": -999999999999, "maxWireVersion": 999999999999}}),
    ("hello with maxAwaitTimeMS Decimal128 max",
     {"hello": 1, "topologyVersion": {"processId": Binary(bytes(12), 4), "counter": Int64(1)},
      "maxAwaitTimeMS": Decimal128("9.999999999999999999999999999999999E+6144")}),
    ("hello with compression malformed array",
     {"hello": 1, "compression": [1, 2, {"a": "b"}, None, 10**30]}),
    # saslStart / saslContinue -- inherently pre-auth
    ("saslStart with garbage mechanism + malformed payload binary subtype",
     {"saslStart": 1, "mechanism": "GSSAPI\x00\xff", "payload": Binary(b"\x00\x01\x02", 0)}),
    ("saslStart with mechanism huge string",
     {"saslStart": 1, "mechanism": "A" * 1000000, "payload": Binary(b"", 0)}),
    ("saslStart with autoAuthorize weird type",
     {"saslStart": 1, "mechanism": "SCRAM-SHA-256", "payload": Binary(b"n,,n=,r=", 0),
      "autoAuthorize": Decimal128("9.999999999999999999999999999999999E+6144")}),
    ("saslContinue without prior saslStart, huge conversationId",
     {"saslContinue": 1, "conversationId": 2**62, "payload": Binary(b"c=biws,r=xx", 0)}),
    ("saslContinue conversationId negative huge",
     {"saslContinue": 1, "conversationId": -(2**62), "payload": Binary(b"", 0)}),
    # buildInfo / ping / whatsmyuri / getLog with generic-arg extremes (pre-auth allowed commands)
    ("buildInfo w/ writeConcern extreme (already covered under ping, re-check on buildInfo)",
     {"buildInfo": 1, "writeConcern": {"w": {"tag1": 10**18, "tag2": -(10**18)}}}),
    ("whatsmyuri baseline (should just work, sanity)",
     {"whatsmyuri": 1}),
    ("getLog global",
     {"getLog": "global"}),
]

for label, cmd in tests:
    if not is_alive():
        print("!!! server already down, skipping:", label)
        continue
    try:
        r = unauth.admin.command(cmd)
        print(f"[{label}] OK: {str(r)[:200]}")
    except PyMongoError as e:
        print(f"[{label}] PyMongoError (no crash): {repr(e)[:250]}")
    except Exception as e:
        print(f"[{label}] UNEXPECTED/CONNECTION ERROR: {repr(e)}")
    alive = is_alive()
    print("  -> alive after:", alive)
    if not alive:
        print(f"*** CRASH CONFIRMED (fully unauthenticated): {label} ***")
        break
