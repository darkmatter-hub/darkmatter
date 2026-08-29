#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 DarkMatter
"""
verify_darkmatter_chain.py
Independent verification of a DarkMatter proof bundle. No SDK, no account, no
network. Recomputes every hash from the payload and checks the chain links.

Usage:
    python verify_darkmatter_chain.py bundle.json
    curl -s "https://darkmatterhub.ai/r/<id>?format=json" | python verify_darkmatter_chain.py

Exit status is 0 when the bundle verifies and 1 when it does not, so this is
safe to use in CI.

What this checks:
  * payload_hash really is the SHA-256 of the RFC 8785 (JCS) canonical payload
  * integrity_hash really is derived from payload_hash and the parent hash
  * each record names the record before it, in order

What it cannot check, and no verifier can: whether records were left out. A
hash chain proves that what you were given is unaltered, not that you were
given everything. See SPEC.md section 5.4.

The previous version of this file expected a shape the product never emitted,
so it crashed with a KeyError on DarkMatter's own demo bundle. It also used
json.dumps(sort_keys=True) as "canonical JSON", which is not RFC 8785 and
disagrees with the reference implementations on non-ASCII payloads. Both are
fixed here, and the JCS implementation below is deliberately self-contained so
that the "no SDK required" claim is actually true.
"""

import hashlib
import json
import sys

HASH_PREFIX = "sha256:"


# ── RFC 8785 (JCS) canonicalisation ──────────────────────────────────────────

def _canon_number(n):
    """
    Serialise a number the way ECMAScript does, which is what RFC 8785 requires.

    Integers are emitted without a decimal point. Floats go through repr, which
    in Python 3 produces the shortest round-tripping form, matching JavaScript
    for every value either language can represent exactly. Values JSON cannot
    represent are rejected rather than silently coerced.
    """
    if isinstance(n, bool):                       # bool is a subclass of int
        raise TypeError("bool is not a number")
    if isinstance(n, int):
        return str(n)
    if n != n or n in (float("inf"), float("-inf")):
        raise ValueError("NaN and Infinity are not valid JSON")
    if n == int(n) and abs(n) < 1e21:
        return str(int(n))
    return repr(n)


def _canon_string(s):
    """Minimal JSON escaping, no \\u escaping of non-ASCII. json handles this."""
    return json.dumps(s, ensure_ascii=False, separators=(",", ":"))


def canonicalize(obj):
    """RFC 8785 canonical JSON, as a string."""
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, str):
        return _canon_string(obj)
    if isinstance(obj, (int, float)):
        return _canon_number(obj)
    if isinstance(obj, list):
        return "[" + ",".join(canonicalize(v) for v in obj) + "]"
    if isinstance(obj, dict):
        # JCS sorts by UTF-16 code unit, which for Python strings means sorting
        # the UTF-16 encoding rather than the code points. They differ only
        # outside the BMP, but a payload containing an emoji is enough.
        items = sorted(obj.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(
            _canon_string(k) + ":" + canonicalize(v) for k, v in items
        ) + "}"
    raise TypeError("cannot canonicalise %r" % type(obj).__name__)


def payload_hash(payload):
    return HASH_PREFIX + hashlib.sha256(
        canonicalize(payload).encode("utf-8")
    ).hexdigest()


def integrity_hash(pay_hash, parent):
    """
    sha256 over payload_hash concatenated with the parent's integrity hash, or
    the literal "root" for the first record. Both operands carry the sha256:
    prefix; dropping it on either side produces a different, wrong digest.
    """
    parent_part = parent if parent else "root"
    return HASH_PREFIX + hashlib.sha256(
        (pay_hash + parent_part).encode("utf-8")
    ).hexdigest()


# ── Bundle shapes ────────────────────────────────────────────────────────────

def extract_records(data):
    """
    Normalise the shapes DarkMatter emits into a list of dicts with the fields
    this verifier needs. Returns (records, shape_name).

    Two shapes exist in the wild and both are accepted, because a verifier that
    only handles the format its author had in front of them is how the previous
    version of this script ended up crashing on the product's own demo output.
    """
    # Conformant Context Passport bundle: /r/<id>?format=json
    if isinstance(data.get("passports"), list) and data["passports"]:
        out = []
        for p in data["passports"]:
            integ = p.get("integrity", {})
            out.append({
                "id": p.get("id"),
                "parent_id": p.get("parent_id"),
                "payload": p.get("payload"),
                "payload_hash": integ.get("payload_hash"),
                "parent_hash": integ.get("parent_hash"),
                "integrity_hash": integ.get("integrity_hash"),
            })
        return out, "context-passport bundle (passports[])"

    # Legacy proof bundle, including the one the website demo hands out.
    if isinstance(data.get("commits"), list) and data["commits"]:
        out = []
        for c in data["commits"]:
            integ = c.get("integrity", {})
            parent = integ.get("parent_hash")
            if parent == "root":
                parent = None
            out.append({
                "id": c.get("id") or c.get("ctx_id"),
                "parent_id": c.get("parent_id") or c.get("parent_ctx_id"),
                "payload": c.get("payload"),
                "payload_hash": integ.get("payload_hash") or c.get("payload_hash"),
                "parent_hash": parent,
                "integrity_hash": integ.get("integrity_hash"),
            })
        return out, "legacy proof bundle (commits[])"

    # A single bare record.
    if "integrity" in data and "payload" in data:
        integ = data["integrity"]
        return [{
            "id": data.get("id"),
            "parent_id": data.get("parent_id"),
            "payload": data.get("payload"),
            "payload_hash": integ.get("payload_hash"),
            "parent_hash": integ.get("parent_hash"),
            "integrity_hash": integ.get("integrity_hash"),
        }], "single record"

    raise SystemExit(
        "Unrecognised bundle. Expected a 'passports' array, a 'commits' array, "
        "or a single record with 'payload' and 'integrity'."
    )


def verify(records):
    errors = []
    prev_integrity = None
    prev_id = None

    for i, r in enumerate(records):
        where = "record %d (%s)" % (i, r.get("id") or "no id")

        # 1. The payload hash must be the hash of the payload it ships with.
        #    This is the check that actually catches an edited record, and the
        #    one the previous version of this script never performed.
        if r["payload"] is None:
            errors.append("%s: no payload, cannot recompute its hash" % where)
        elif r["payload_hash"]:
            got = payload_hash(r["payload"])
            if got != r["payload_hash"]:
                errors.append(
                    "%s: payload does not match payload_hash\n"
                    "        claimed  %s\n"
                    "        computed %s" % (where, r["payload_hash"], got)
                )
        else:
            errors.append("%s: no payload_hash to check" % where)

        # 2. The record must name the one before it.
        if i == 0:
            if r["parent_hash"]:
                errors.append("%s: first record should have no parent hash" % where)
        else:
            if r["parent_hash"] != prev_integrity:
                errors.append(
                    "%s: parent hash does not match the previous record\n"
                    "        claimed  %s\n"
                    "        previous %s" % (where, r["parent_hash"], prev_integrity)
                )
            if r["parent_id"] and prev_id and r["parent_id"] != prev_id:
                errors.append("%s: parent_id %s is not the previous record %s"
                              % (where, r["parent_id"], prev_id))

        # 3. The integrity hash must follow from the two above. Only checked
        #    when the bundle carries one; the legacy demo bundle does not.
        if r["integrity_hash"] and r["payload_hash"]:
            want = integrity_hash(r["payload_hash"], r["parent_hash"])
            if want != r["integrity_hash"]:
                errors.append(
                    "%s: integrity_hash is not derived from payload and parent\n"
                    "        claimed  %s\n"
                    "        computed %s" % (where, r["integrity_hash"], want)
                )
            prev_integrity = r["integrity_hash"]
        else:
            prev_integrity = r["payload_hash"]

        prev_id = r["id"]

    return errors


def main(argv):
    if len(argv) > 1:
        with open(argv[1], encoding="utf-8") as f:
            data = json.load(f)
    else:
        if sys.stdin.isatty():
            print(__doc__.strip())
            return 2
        data = json.load(sys.stdin)

    records, shape = extract_records(data)
    errors = verify(records)

    print("  bundle    %s" % shape)
    print("  records   %d" % len(records))
    for r in records:
        print("            %s" % (r.get("id") or "(no id)"))
    print()

    if errors:
        print("  FAILED. This bundle has been altered, or was not produced the")
        print("  way it claims:\n")
        for e in errors:
            print("      %s" % e)
        print()
        return 1

    print("  VERIFIED. Every payload hashes to the value recorded with it, and")
    print("  each record names the one before it.")
    print()
    print("  Note: this proves the records you have were not altered. It cannot")
    print("  prove none were withheld. See SPEC.md 5.4.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
