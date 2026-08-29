#!/usr/bin/env python3
"""
Round 16: type-confusion fuzzer for WordPress core's XML-RPC server
(wp-includes/class-wp-xmlrpc-server.php), informed by two very recent
upstream commits fixing exactly this bug class:

  - 1ef9d70aea "XML-RPC: Validate the attachment data in mw_newMediaObject()."
    (an unauthenticated struct-type-confusion crash reachable before login())
  - 67c01d5705 "XML-RPC: Require the $fields argument to be an array."
    (ten wp.* methods crashed on a non-array $fields arg)

Both already-fixed instances were confirmed complete (no sibling within their
own narrow scope) by code reading. This fuzzer looks for a THIRD, not-yet-fixed
instance of the same shape by sending malformed struct/array arguments to
every wp.*/mw.*/blogger.* XML-RPC method that takes a content-struct-like
argument, and diffing wp-content/debug.log for a new uncaught PHP error.
"""
import xmlrpc.client
import http.client
import os
import time
import json

HOST = "127.0.0.1"
PORT = 8890
DEBUG_LOG = "/home/user/wp-site/wordpress/wp-content/debug.log"
RESULTS_PATH = "/tmp/claude-0/-home-user-mongo/88417634-60f9-5bda-b080-646aad79e105/scratchpad/xmlrpc_fuzz_results.jsonl"

ADMIN_USER = "admin"
ADMIN_PASS = "AdminTest_Pass_2026!"


def raw_call(xml_body):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=10)
    try:
        conn.request("POST", "/xmlrpc.php", body=xml_body, headers={"Content-Type": "text/xml"})
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, body
    except Exception as e:
        return None, str(e).encode()
    finally:
        conn.close()


def log_size():
    try:
        return os.path.getsize(DEBUG_LOG)
    except FileNotFoundError:
        return 0


def log_tail_since(offset):
    try:
        with open(DEBUG_LOG, "rb") as f:
            f.seek(offset)
            return f.read().decode(errors="replace")
    except FileNotFoundError:
        return ""


# "bad" values to try in place of a normal struct/scalar argument.
BAD_STRUCT_VALUES = [
    ("string-for-struct", "not-a-struct"),
    ("int-for-struct", 12345),
    ("array-for-struct", ["a", "b"]),
]

BAD_SCALAR_MEMBER_VALUES = [
    ("array-for-member", ["nested", "array"]),
    ("struct-for-member", {"nested": "struct"}),
]

# method -> (positional args template, index of the "interesting" struct arg or None,
#            list of member names inside that struct worth mutating individually)
METHODS = {
    "wp.newPost": ([0, ADMIN_USER, ADMIN_PASS, {"post_title": "t", "post_content": "c", "post_status": "draft"}], 3,
                   ["post_title", "post_content", "post_status", "post_type", "post_date", "terms_names", "custom_fields"]),
    "wp.editPost": ([0, ADMIN_USER, ADMIN_PASS, 1, {"post_title": "t"}], 4, ["post_title", "post_content", "terms_names", "custom_fields"]),
    "wp.editProfile": ([0, ADMIN_USER, ADMIN_PASS, {"first_name": "a"}], 3, ["first_name", "last_name", "url", "bio"]),
    "wp.setOptions": ([0, ADMIN_USER, ADMIN_PASS, {"blog_title": "x"}], 3, ["blog_title"]),
    "wp.newTerm": ([0, ADMIN_USER, ADMIN_PASS, {"name": "t", "taxonomy": "category"}], 3, ["name", "taxonomy", "description", "parent"]),
    "wp.editTerm": ([0, ADMIN_USER, ADMIN_PASS, 1, {"name": "t"}], 4, ["name", "description"]),
    "wp.newComment": ([0, ADMIN_USER, ADMIN_PASS, 1, {"content": "hi"}], 4, ["content", "author", "author_email", "author_url", "comment_parent", "status"]),
    "wp.editComment": ([0, ADMIN_USER, ADMIN_PASS, 1, {"content": "hi"}], 4, ["content", "author", "status"]),
    "wp.newCategory": ([0, ADMIN_USER, ADMIN_PASS, {"name": "c"}], 3, ["name", "slug", "parent_id", "description"]),
    "wp.suggestCategories": ([0, ADMIN_USER, ADMIN_PASS, "cat", 5], None, []),
    "metaWeblog.newPost": ([0, ADMIN_USER, ADMIN_PASS, {"title": "t", "description": "d"}, 0], 3, ["title", "description", "categories", "post_type", "wp_page_template", "wp_slug", "wp_password", "wp_page_parent_id", "wp_post_format", "custom_fields"]),
    "metaWeblog.editPost": ([0, 1, ADMIN_USER, ADMIN_PASS, {"title": "t"}, 0], 4, ["title", "description", "categories", "wp_post_format"]),
    "blogger.newPost": ([0, 1, ADMIN_USER, ADMIN_PASS, "content", 0], None, []),
    "blogger.editPost": ([0, 1, ADMIN_USER, ADMIN_PASS, "content", 0], None, []),
    "mt.setPostCategories": ([0, 1, ADMIN_USER, ADMIN_PASS, [{"categoryId": 1}]], 4, []),
    "wp.uploadFile": ([0, ADMIN_USER, ADMIN_PASS, {"name": "a.txt", "type": "text/plain", "bits": "aGVsbG8="}], 3, ["name", "type", "bits", "overwrite", "post_id"]),
}


def mutate(args, struct_index, member_names):
    """Yield (label, mutated_args) pairs."""
    args = list(args)

    # 1. Replace the whole struct with a non-struct value.
    if struct_index is not None:
        for label, bad_val in BAD_STRUCT_VALUES:
            mutated = list(args)
            mutated[struct_index] = bad_val
            yield (f"whole_struct:{label}", mutated)

        # 2. Replace individual members inside the struct with a bad-typed value.
        for member in member_names:
            for label, bad_val in BAD_SCALAR_MEMBER_VALUES:
                mutated = list(args)
                struct_copy = dict(mutated[struct_index])
                struct_copy[member] = bad_val
                mutated[struct_index] = struct_copy
                yield (f"member:{member}:{label}", mutated)


def main():
    results = []
    tested = 0

    with open(RESULTS_PATH, "w") as outf:
        for method, (base_args, struct_index, member_names) in METHODS.items():
            for label, mutated_args in mutate(base_args, struct_index, member_names):
                tested += 1
                try:
                    body = xmlrpc.client.dumps(tuple(mutated_args), methodname=method)
                except Exception as e:
                    # Some mutations (e.g. dict as a top-level list element for arrays
                    # marshalled as XML-RPC <array>) may fail to marshal client-side;
                    # skip those, they're not a valid transport-layer attack anyway.
                    continue

                before = log_size()
                status, resp_body = raw_call(body)
                time.sleep(0.02)
                new_log = log_tail_since(before)
                resp_snippet = resp_body[:300].decode(errors="replace") if isinstance(resp_body, bytes) else str(resp_body)[:300]

                interesting = bool(new_log.strip()) or (status not in (200,) and status is not None)

                record = {
                    "method": method, "label": label, "status": status,
                    "new_log": new_log.strip(), "resp_snippet": resp_snippet,
                }
                if interesting:
                    results.append(record)
                    outf.write(json.dumps(record) + "\n")
                    outf.flush()

    print(f"Tested {tested} (method, mutation) combinations.")
    print(f"Interesting: {len(results)}")
    for r in results[:80]:
        print("----")
        print(r["method"], r["label"], "status=", r["status"])
        if r["new_log"]:
            print("LOG:", r["new_log"][:500])
        else:
            print("RESP:", r["resp_snippet"][:200])


if __name__ == "__main__":
    main()
