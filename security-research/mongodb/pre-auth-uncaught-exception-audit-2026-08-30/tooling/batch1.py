#!/usr/bin/env python3
import sys, decimal
sys.path.insert(0, "/tmp/claude-0/-home-user-mongo/88417634-60f9-5bda-b080-646aad79e105/scratchpad")
from harness import run, is_alive
from bson.decimal128 import Decimal128
from bson import Int64

tests = [
    ("generic writeConcern.w huge number", {"ping": 1, "writeConcern": {"w": 10**30}}),
    ("generic writeConcern.w Decimal128 max", {"ping": 1, "writeConcern": {"w": Decimal128("9.999999999999999999999999999999999E+6144")}}),
    ("generic writeConcern.w NaN decimal", {"ping": 1, "writeConcern": {"w": Decimal128("NaN")}}),
    ("generic writeConcern.wtimeout Decimal128 max", {"ping": 1, "writeConcern": {"wtimeout": Decimal128("9.999999999999999999999999999999999E+6144")}}),
    ("generic writeConcern.wtimeout NaN", {"ping": 1, "writeConcern": {"wtimeout": Decimal128("NaN")}}),
    ("generic maxTimeMS Decimal128 max", {"ping": 1, "maxTimeMS": Decimal128("9.999999999999999999999999999999999E+6144")}),
    ("generic maxTimeMS float huge", {"ping": 1, "maxTimeMS": 1e308}),
    ("generic readConcern.afterClusterTime bad", {"ping": 1, "readConcern": {"afterClusterTime": Decimal128("9.999999999999999999999999999999999E+6144")}}),
    ("generic lsid.uid malformed length (short binary)", {"ping": 1, "lsid": {"id": __import__("bson").Binary(bytes(16), 4), "uid": __import__("bson").Binary(b"\x01\x02\x03", 0)}}),
    ("generic txnNumber huge decimal", {"ping": 1, "lsid": {"id": __import__("bson").Binary(bytes(16), 4)}, "txnNumber": Decimal128("9.999999999999999999999999999999999E+6144"), "autocommit": False}),
]

for label, cmd in tests:
    if not is_alive():
        print("!!! Server already down before test, skipping:", label)
        continue
    ok = run(cmd, label=label)
    alive = is_alive()
    print("  -> alive after:", alive)
    if not alive:
        print(f"*** CRASH CANDIDATE CONFIRMED: {label} ***")
        break
