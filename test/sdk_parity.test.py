#!/usr/bin/env python3
"""
The Python SDK and the server must hash payloads identically.

DarkMatter's claim is that the payload is hashed on the client before
transmission and the server verifies it. That only works if both sides compute
the same hash from the same payload. They did not.

The SDK sorted object keys with Python's sorted(), which orders by code point.
The server sorts with JavaScript's Array.prototype.sort, which orders by UTF-16
code unit, as RFC 8785 3.2.3 requires. Those agree across the whole BMP and
disagree above it: U+1F600 encodes to the surrogate pair D83D DE00, sorting
below U+FF01 in UTF-16 and above it by code point.

So a payload with an emoji key hashed one way in the SDK and another on the
server, and the commit was flagged as a hash mismatch. Nothing caught it
because every test payload had ASCII keys.

Run: python test/sdk_parity.test.py     (requires node on PATH)
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# The SDK that actually ships, which lives in its own repository beside this
# one. This used to import ROOT/sdk/python, a stale copy bundled here. The
# UTF-16 key-order fix was applied to that copy, this test went green, and the
# published package kept sorting by code point - so the test proving the SDK
# and the server agree was proving it about software nobody installs.
# Walk up rather than assuming a sibling: inside a git worktree, ROOT/.. is
# the worktrees directory, so a plain sibling path silently misses and the
# check skips without anyone noticing.
def _find_sdk(start):
    d = os.path.abspath(start)
    while True:
        cand = os.path.join(d, "darkmatter-sdk-python")
        if os.path.isdir(cand):
            return cand
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent

SDK = os.environ.get("DARKMATTER_SDK_PY") or _find_sdk(ROOT)
if not SDK or not os.path.isdir(SDK):
    print("")
    print("  - darkmatter-sdk-python not checked out beside this repo;")
    print("    SDK parity not verified. Clone it to run this.")
    sys.exit(0)
sys.path.insert(0, SDK)

from darkmatter.client import hash_payload as sdk_hash   # noqa: E402

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        print("  ok   " + label)
        passed += 1
    else:
        print("  FAIL " + label + ("\n       " + detail if detail else ""))
        failed += 1


def server_hash(payload):
    """Hash the same payload with src/integrity.js, the server's implementation."""
    script = (
        "const {hashPayload}=require('./src/integrity');"
        "let s='';process.stdin.on('data',d=>s+=d)"
        ".on('end',()=>process.stdout.write(hashPayload(JSON.parse(s))));"
    )
    r = subprocess.run([node_bin(), "-e", script], input=json.dumps(payload),
                       capture_output=True, text=True, cwd=ROOT, encoding="utf-8")
    if r.returncode != 0:
        raise RuntimeError("node failed: " + (r.stderr or "")[:300])
    return r.stdout.strip()


def node_bin():
    return "node"


# Each case is a payload whose keys exercise a different part of the ordering
# rule. The astral ones are the whole point: with ASCII-only keys the two
# implementations agree even when one of them is wrong.
CASES = [
    ("ascii keys only", {"b": 2, "a": 1, "c": {"z": 1, "y": 2}}),
    ("latin-1 and CJK keys (BMP)", {"é": 1, "中": 2, "a": 3}),
    ("astral key beside a BMP key",
     {"a": 1, "\U0001F600": "astral", "！": "bmp"}),
    ("astral keys nested",
     {"outer": {"\U0001F680": 1, "�": 2, "m": 3}, "\U0001F600": 4}),
    ("astral in values only, which must also agree",
     {"note": "café \U0001F600", "n": 284}),
    ("numbers and nulls alongside astral keys",
     {"\U0001F600": 1.5, "z": None, "a": [1, 2, {"！": True}]}),
]

print("\nPython SDK vs server hashing")

try:
    server_hash({"probe": 1})
except Exception as e:
    print("  - node unavailable, parity check skipped:", str(e)[:120])
    sys.exit(0)

for label, payload in CASES:
    s = sdk_hash(payload)
    j = server_hash(payload)
    check(label, s == j, "sdk %s\n       srv %s" % (s, j))

# Key order in the input must not change the hash, in either implementation.
a = {"a": 1, "\U0001F600": "x", "！": "y"}
b = {"！": "y", "\U0001F600": "x", "a": 1}
check("input key order does not affect the SDK hash", sdk_hash(a) == sdk_hash(b))
check("input key order does not affect the server hash", server_hash(a) == server_hash(b))

if failed:
    print("")
    print("  The published SDK disagrees with the server on these payloads, so a")
    print("  commit carrying one is flagged as a hash mismatch by the service that")
    print("  told the client to compute it. The fix is darkmatter-sdk-python PR #1,")
    print("  which sorts keys by UTF-16 code unit. This stays red until it merges.")
print("\nPassed: %d  Failed: %d" % (passed, failed))
sys.exit(1 if failed else 0)
