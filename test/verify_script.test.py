#!/usr/bin/env python3
"""
Tests examples/verify_darkmatter_chain.py, the script five public pages and the
demo's proof bundle tell readers to run.

This exists because that script was broken for a long time in the worst way for
a product built on "check it yourself": it was never served over HTTP at all,
and when run against DarkMatter's own demo bundle it died with a KeyError
because it expected a shape nothing emits. Nothing caught it, because nothing
ran it.

Run: python test/verify_script.test.py
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT = os.path.join(ROOT, "examples", "verify_darkmatter_chain.py")

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        print("  ok   " + label)
        passed += 1
    else:
        print("  FAIL " + label + ("\n      " + detail if detail else ""))
        failed += 1


def run(bundle):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                     encoding="utf-8") as f:
        json.dump(bundle, f)
        path = f.name
    try:
        r = subprocess.run([sys.executable, SCRIPT, path],
                           capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr
    finally:
        os.unlink(path)


# Import the script's own canonicaliser so fixtures carry real hashes rather
# than values copied from whatever the code currently produces.
sys.path.insert(0, os.path.join(ROOT, "examples"))
import importlib.util
spec = importlib.util.spec_from_file_location("vdc", SCRIPT)
vdc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vdc)


def legacy_bundle():
    payload = {"input": "Approve refund #84721?", "output": "Approve", "amount": 284}
    return {
        "darkmatter_proof_bundle": True,
        "version": "1.0",
        "commits": [{
            "id": "ctx_1_aaa",
            "payload": payload,
            "integrity": {
                "payload_hash": vdc.payload_hash(payload),
                "parent_hash": "root",
            },
        }],
    }


def v2_bundle(n=2):
    records, parent = [], None
    for i in range(n):
        payload = {"step": i, "note": "café \U0001F600"}   # non-ASCII and astral
        ph = vdc.payload_hash(payload)
        ih = vdc.integrity_hash(ph, parent)
        records.append({
            "id": "ctx_%d" % i,
            "parent_id": ("ctx_%d" % (i - 1)) if i else None,
            "payload": payload,
            "integrity": {"payload_hash": ph, "parent_hash": parent,
                          "integrity_hash": ih},
        })
        parent = ih
    return {"format": "context-passport-bundle", "passports": records}


print("\nverify_darkmatter_chain.py")

code, out = run(legacy_bundle())
check("accepts the legacy commits[] bundle the website demo hands out",
      code == 0, out.strip()[:300])

code, out = run(v2_bundle())
check("accepts the conformant passports[] bundle from /r/?format=json",
      code == 0, out.strip()[:300])

# Tampering must be caught in both shapes, and must be caught by recomputing
# the hash rather than by trusting a chain_intact flag in the file.
b = legacy_bundle()
b["commits"][0]["payload"]["output"] = "Deny"
code, out = run(b)
check("rejects an edited payload in a legacy bundle",
      code == 1 and "does not match" in out, out.strip()[:300])

b = v2_bundle()
b["passports"][1]["payload"]["step"] = 99
code, out = run(b)
check("rejects an edited payload in a v2 bundle",
      code == 1, out.strip()[:300])

b = v2_bundle()
b["passports"][1]["integrity"]["parent_hash"] = "sha256:" + "0" * 64
code, out = run(b)
check("rejects a broken chain link", code == 1, out.strip()[:300])

b = v2_bundle()
b["passports"].reverse()
code, out = run(b)
check("rejects reordered records", code == 1, out.strip()[:300])

# A bundle can assert its own integrity. The verifier must ignore that and
# check for itself, or it proves nothing at all.
b = legacy_bundle()
b["chain_intact"] = True
b["commits"][0]["integrity"]["chain_intact"] = True
b["commits"][0]["payload"]["amount"] = 999999
code, out = run(b)
check("ignores a self-asserted chain_intact flag on tampered data",
      code == 1, out.strip()[:300])

code, out = run({"nothing": "useful"})
check("rejects an unrecognised bundle rather than passing it",
      code != 0, out.strip()[:200])

# The standalone canonicaliser must agree with the published reference SDK,
# since the whole point is that a third party can reproduce our hashes.
try:
    from context_passport import payload_hash as ref_hash
    # The keys matter more than the values. RFC 8785 orders keys by UTF-16 code
    # unit, not code point, and the two disagree only when a key lies outside
    # the BMP: an astral character encodes to a surrogate pair beginning 0xD83D,
    # which sorts below a BMP character such as 0xFF01, while by code point it
    # sorts above. The earlier payload here put non-ASCII in values only, so
    # removing the UTF-16 sort from the canonicaliser changed nothing this test
    # looked at and it kept passing.
    tricky = {"z": 1.5, "a": None, "s": "café 中文 😀",
              "n": 284, "nested": {"b": [1, 2, {"c": True}]},
              "😀": "astral key", "！": "bmp key"}
    check("standalone JCS matches the context-passport reference SDK",
          vdc.payload_hash(tricky) == ref_hash(tricky),
          "%s vs %s" % (vdc.payload_hash(tricky), ref_hash(tricky)))
except ImportError:
    print("  - reference SDK not installed, cross-check skipped")

print("\nPassed: %d  Failed: %d" % (passed, failed))
sys.exit(1 if failed else 0)
