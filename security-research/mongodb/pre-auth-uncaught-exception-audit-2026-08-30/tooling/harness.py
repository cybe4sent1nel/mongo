#!/usr/bin/env python3
"""Small reusable harness for pre-auth crash candidate testing against a local mongod."""
import sys
import pymongo
from pymongo.errors import PyMongoError

HOST = "127.0.0.1"
PORT = 27117


def run(cmd, db="admin", label=""):
    print(f"--- {label or cmd} ---")
    try:
        client = pymongo.MongoClient(HOST, PORT, serverSelectionTimeoutMS=3000)
        result = client[db].command(cmd)
        print("OK:", result)
        client.close()
        return True
    except PyMongoError as e:
        print("PyMongoError (server responded with an error, not a crash):", repr(e))
        return True
    except Exception as e:
        print("UNEXPECTED / CONNECTION-LEVEL ERROR:", repr(e))
        return False


def is_alive():
    try:
        client = pymongo.MongoClient(HOST, PORT, serverSelectionTimeoutMS=2000)
        client.admin.command("ping")
        client.close()
        return True
    except Exception as e:
        print("Server appears DOWN:", repr(e))
        return False


if __name__ == "__main__":
    print("alive before:", is_alive())
