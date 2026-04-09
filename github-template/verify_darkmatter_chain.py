#!/usr/bin/env python3
"""
DarkMatter Offline Chain Verifier v2
======================================
Verify a DarkMatter chain export with ZERO network calls.

Usage:
    python verify_darkmatter_chain.py chain.json
    python verify_darkmatter_chain.py chain.json --verbose
    python verify_darkmatter_chain.py chain.json --checkpoint cp.json --pubkey dm_server.pub.pem
    python verify_darkmatter_chain.py chain.json --legacy    # allow missing hashes (old exports)
    python verify_darkmatter_chain.py chain.json --json      # machine-readable output

Exit codes: 0 = all required checks passed  1 = failed  2 = malformed input

Requirements: Python 3.10+  |  pip install cryptography
"""

import sys, json, hashlib, math, argparse, re
from pathlib import Path

try:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.exceptions import InvalidSignature
    CRYPTO = True
except ImportError:
    CRYPTO = False

SCHEMA_VERSION = '2'

# ─── Canonical serialization (must match integrity.js exactly) ────────────────

def canonicalize(value) -> str:
    if value is None:               return 'null'
    if isinstance(value, bool):     return 'true' if value else 'false'
    if isinstance(value, int):      return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError(f'non-finite number rejected: {value}')
        s = format(value, '.17g')
        if '.' not in s and 'e' not in s: s += '.0'
        elif '.' in s and 'e' not in s:
            s = s.rstrip('0')
            if s.endswith('.'): s += '0'
        return s
    if isinstance(value, str):      return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):     return '[' + ','.join(canonicalize(item) for item in value) + ']'
    if isinstance(value, dict):
        pairs = [json.dumps(k, ensure_ascii=False) + ':' + canonicalize(value[k])
                 for k in sorted(value.keys())]
        return '{' + ','.join(pairs) + '}'
    raise TypeError(f'unsupported type: {type(value).__name__}')

def hash_payload(payload: dict) -> str:
    return hashlib.sha256(canonicalize(payload).encode()).hexdigest()

def build_envelope(payload_hash, parent_ih, agent_id, key_id, timestamp) -> dict:
    ts = re.sub(r'\.\d+Z?$', '', timestamp or '')
    if not ts.endswith('Z'): ts += 'Z'
    return {
        'schema_version':       SCHEMA_VERSION,
        'agent_id':             agent_id or '',
        'key_id':               key_id or 'default',
        'timestamp':            ts,
        'payload_hash':         payload_hash,
        'parent_integrity_hash': parent_ih or 'root',
    }

def hash_envelope(envelope: dict) -> str:
    return hashlib.sha256(canonicalize(envelope).encode()).hexdigest()

def strip(h): return (h or '').removeprefix('sha256:') or None

# ─── Signature verification ────────────────────────────────────────────────────

def verify_sig(envelope: dict, sig_hex: str, pubkey_pem: str) -> bool:
    if not CRYPTO: return None
    try:
        msg = canonicalize(envelope).encode()
        sig = bytes.fromhex(sig_hex)
        load_pem_public_key(pubkey_pem.encode()).verify(sig, msg)
        return True
    except (InvalidSignature, Exception): return False

def verify_checkpoint_sig(cp: dict, pubkey_pem: str) -> bool:
    if not CRYPTO: return None
    try:
        msg = canonicalize({'log_root': cp['log_root'], 'position': cp['position'], 'timestamp': cp['timestamp']}).encode()
        sig = bytes.fromhex(cp['server_sig'])
        load_pem_public_key(pubkey_pem.encode()).verify(sig, msg)
        return True
    except Exception: return False

# ─── Test vectors ─────────────────────────────────────────────────────────────

def build_leaf_envelope(commit_id: str, integrity_hash: str,
                         log_position: int, accepted_at: str) -> dict:
    """Canonical leaf envelope — keys sorted: accepted_at, commit_id, integrity_hash, log_position"""
    ts = re.sub(r'\.\d+Z?$', '', accepted_at or '').rstrip('Z') + 'Z'
    return {
        'accepted_at':    ts,
        'commit_id':      commit_id,
        'integrity_hash': (integrity_hash or '')[7:] if (integrity_hash or '').startswith('sha256:') else (integrity_hash or ''),
        'log_position':   log_position,
    }

def leaf_hash_from_commit(commit_id: str, integrity_hash: str,
                           log_position: int, accepted_at: str) -> str:
    """RFC 6962 leaf hash: SHA256(0x00 || UTF8(canonical(leaf_envelope)))"""
    env = build_leaf_envelope(commit_id, integrity_hash, log_position, accepted_at)
    canonical = canonicalize(env)
    buf = b'\x00' + canonical.encode('utf-8')
    return hashlib.sha256(buf).hexdigest()

def node_hash_fn(left: str, right: str) -> str:
    """RFC 6962 internal node hash"""
    buf = b'\x01' + bytes.fromhex(left) + bytes.fromhex(right)
    return hashlib.sha256(buf).hexdigest()

def verify_inclusion_proof(leaf_h: str, proof: dict, expected_root: str) -> bool:
    """Verify a Merkle inclusion proof. proof = {proof: [{hash, direction}]}"""
    try:
        current = leaf_h
        for step in proof.get('proof', []):
            if step['direction'] == 'right':
                current = node_hash_fn(current, step['hash'])
            else:
                current = node_hash_fn(step['hash'], current)
        return current == expected_root
    except Exception:
        return False

def compute_root_from_leaves(leaves: list) -> str:
    if not leaves: return hashlib.sha256(b'\x00').hexdigest()
    if len(leaves) == 1: return leaves[0]
    nodes = list(leaves)
    while len(nodes) > 1:
        nxt = []
        for i in range(0, len(nodes), 2):
            nxt.append(node_hash_fn(nodes[i], nodes[i+1]) if i+1 < len(nodes) else nodes[i])
        nodes = nxt
    return nodes[0]

def run_merkle_vectors(vectors_path: str) -> bool:
    """Run Merkle test vectors. Returns True if all pass."""
    vecs = json.loads(Path(vectors_path).read_text())
    ok = True
    for vec in vecs.get('leaf_vectors', []):
        got = leaf_hash_from_commit(vec['commit_id'], vec['integrity_hash'],
                                     vec['log_position'], vec['accepted_at'])
        passed = got == vec['expected_leaf_hash']
        if not passed: ok = False
        print(f'  {"PASS" if passed else "FAIL"} {vec["id"]}: {vec["desc"]}')
        if not passed: print(f'    exp={vec["expected_leaf_hash"][:24]}...\n    got={got[:24]}...')
    for vec in vecs.get('root_vectors', []):
        got = compute_root_from_leaves(vec['leaf_hashes'])
        passed = got == vec['expected_root']
        if not passed: ok = False
        print(f'  {"PASS" if passed else "FAIL"} {vec["id"]}: {vec["desc"]}')
    for vec in vecs.get('proof_vectors', []):
        got = verify_inclusion_proof(vec['leaf_hash'], {'proof': vec['proof']}, vec['tree_root'])
        passed = got == vec['expected_valid']
        if not passed: ok = False
        print(f'  {"PASS" if passed else "FAIL"} {vec["id"]}: {vec["desc"]}')
    return ok

def run_test_vectors(vectors_path: str) -> bool:
    v = json.loads(Path(vectors_path).read_text())
    ok = True
    for vec in v.get('canonicalize_vectors', []):
        try:
            got = canonicalize(vec['input'])
            if got != vec['expected']:
                print(f'  FAIL {vec["id"]}: expected {vec["expected"]!r} got {got!r}')
                ok = False
            else:
                print(f'  PASS {vec["id"]}: {vec["desc"]}')
        except Exception as e:
            print(f'  ERROR {vec["id"]}: {e}')
            ok = False
    return ok

# ─── Phase 1: chain structure ──────────────────────────────────────────────────

def check_structure(commits, strict, verbose):
    broken   = None
    prev_ih  = None
    steps    = []

    for i, c in enumerate(commits):
        cid       = c.get('id', f'[{i}]')
        payload   = c.get('payload') or c.get('context') or {}
        agent_id  = c.get('agent_id') or (c.get('agent_info') or {}).get('id') or ''
        key_id    = c.get('key_id')   or (c.get('agent_info') or {}).get('key_id') or 'default'
        timestamp = c.get('timestamp') or ''

        s_ph = strip(c.get('payload_hash'))
        s_ih = strip(c.get('integrity_hash'))

        if strict and (not s_ph or not s_ih):
            s = {'id': cid, 'payload_ok': False, 'integrity_ok': False, 'link_ok': False, 'reason': 'missing_hashes'}
            steps.append(s)
            if not broken: broken = cid
            if verbose: print(f'  [{i:4d}] {cid[:28]:<28} ✗ missing_hashes')
            continue

        ph          = hash_payload(payload)
        env         = build_envelope(ph, prev_ih, agent_id, key_id, timestamp)
        ih          = hash_envelope(env)
        payload_ok  = not s_ph or ph == s_ph
        integr_ok   = not s_ih or ih == s_ih
        link_ok     = payload_ok and integr_ok

        steps.append({'id': cid, 'payload_ok': payload_ok, 'integrity_ok': integr_ok, 'link_ok': link_ok, '_env': env, '_ih': ih})
        if not link_ok and not broken: broken = cid
        if verbose:
            p = '✓' if payload_ok else '✗'
            g = '✓' if integr_ok  else '✗'
            print(f'  [{i:4d}] {cid[:28]:<28} payload={p} chain={g}')
        prev_ih = ih

    return {'ok': broken is None, 'broken_at': broken, 'steps': steps}

# ─── Phase 2: agent signatures ────────────────────────────────────────────────

def check_signatures(commits, steps, pubkeys: dict, verbose):
    """
    pubkeys: {agent_id: pem_string}
    Checks signature on every commit that has agent_signature field.
    """
    results  = []
    missing  = 0
    failures = 0

    for i, (c, s) in enumerate(zip(commits, steps)):
        sig      = c.get('agent_signature')
        agent_id = c.get('agent_id') or (c.get('agent_info') or {}).get('id') or ''
        env      = s.get('_env')
        cid      = c.get('id', f'[{i}]')

        if not sig:
            results.append({'id': cid, 'ok': None, 'reason': 'no_signature'})
            missing += 1
            if verbose: print(f'  [{i:4d}] {cid[:28]:<28} ~ no signature')
            continue

        pubkey = pubkeys.get(agent_id)
        if not pubkey:
            results.append({'id': cid, 'ok': None, 'reason': 'no_pubkey'})
            missing += 1
            if verbose: print(f'  [{i:4d}] {cid[:28]:<28} ~ no pubkey for {agent_id}')
            continue

        if not env:
            results.append({'id': cid, 'ok': False, 'reason': 'no_envelope_in_step'})
            failures += 1
            continue

        ok = verify_sig(env, sig, pubkey)
        results.append({'id': cid, 'ok': ok, 'reason': 'verified' if ok else 'sig_invalid'})
        if not ok: failures += 1
        if verbose:
            mark = ('✓' if ok else ('?' if ok is None else '✗'))
            print(f'  [{i:4d}] {cid[:28]:<28} {mark} signature')

    verified = sum(1 for r in results if r['ok'] is True)
    return {
        'ok':       failures == 0,
        'verified': verified,
        'missing':  missing,
        'failures': failures,
        'results':  results,
    }

# ─── Phase 2: checkpoint ──────────────────────────────────────────────────────

def check_checkpoint(cp_path, pubkey_pem, verbose):
    cp  = json.loads(Path(cp_path).read_text())
    ok  = None
    if pubkey_pem and CRYPTO:
        ok = verify_checkpoint_sig(cp, pubkey_pem)
    if verbose:
        mark = '✓' if ok else ('?' if ok is None else '✗')
        print(f'  position={cp.get("position")} root={cp.get("log_root","")[:16]}... {mark}')
    return {'ok': ok, 'position': cp.get('position'), 'log_root': cp.get('log_root'), 'timestamp': cp.get('timestamp')}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def c(ok):
    if ok is True:  return '\033[32m✓ PASS\033[0m'
    if ok is False: return '\033[31m✗ FAIL\033[0m'
    return '\033[33m~ SKIP\033[0m'

def main():
    ap = argparse.ArgumentParser(description='DarkMatter offline chain verifier v2')
    ap.add_argument('export_file')
    ap.add_argument('--verbose',     action='store_true')
    ap.add_argument('--legacy',      action='store_true', help='Allow missing hashes (old exports)')
    ap.add_argument('--checkpoint',  help='Checkpoint JSON for Phase 2 log verification')
    ap.add_argument('--pubkey',      help='Server public key PEM for checkpoint sig verification')
    ap.add_argument('--agent-keys',  help='JSON file mapping {agent_id: pubkey_pem} for signature verification')
    ap.add_argument('--test-vectors',       help='Run canonicalization test vectors and exit')
    ap.add_argument('--test-vectors-merkle',help='Run Merkle test vectors and exit')
    ap.add_argument('--skip-proof',  action='store_true', help='Skip Merkle inclusion check')
    ap.add_argument('--json',        action='store_true')
    args = ap.parse_args()

    # Test vectors mode
    if args.test_vectors:
        ok = run_test_vectors(args.test_vectors)
        sys.exit(0 if ok else 1)
    if getattr(args, 'test_vectors_merkle', None):
        ok = run_merkle_vectors(args.test_vectors_merkle)
        sys.exit(0 if ok else 1)
    if hasattr(args, 'test_vectors_merkle') and args.test_vectors_merkle:
        ok = run_merkle_vectors(args.test_vectors_merkle)
        sys.exit(0 if ok else 1)
    if args.test_vectors_merkle:
        ok = run_merkle_vectors(args.test_vectors_merkle)
        sys.exit(0 if ok else 1)

    if not CRYPTO:
        print('\033[33m⚠ pip install cryptography — signature verification unavailable\033[0m\n')

    # Load export
    try:
        raw = json.loads(Path(args.export_file).read_text())
    except Exception as e:
        print(f'\033[31mCannot read export: {e}\033[0m', file=sys.stderr); sys.exit(2)

    commits = raw if isinstance(raw, list) else (raw.get('commits') or raw.get('replay') or [])
    if not commits:
        print('\033[31mNo commits found\033[0m', file=sys.stderr); sys.exit(2)

    meta = raw if isinstance(raw, dict) else {}

    print(f'\nDarkMatter Chain Verifier v2')
    print(f'────────────────────────────────────────────')
    print(f'File:        {args.export_file}')
    print(f'Commits:     {len(commits)}')
    if meta.get('trace_id'): print(f'Trace ID:    {meta["trace_id"]}')
    print(f'Strict mode: {"off (--legacy)" if args.legacy else "on"}')
    print()

    # ── Phase 1: Structure ────────────────────────────────────────────────────
    if args.verbose: print('Structure checks:')
    struct = check_structure(commits, strict=not args.legacy, verbose=args.verbose)
    if args.verbose: print()
    print(f'Phase 1 — Chain structure:    {c(struct["ok"])}')
    if struct['broken_at']: print(f'            Broken at:        {struct["broken_at"]}')

    # ── Phase 2a: Agent signatures ────────────────────────────────────────────
    pubkeys = {}
    if args.agent_keys:
        try: pubkeys = json.loads(Path(args.agent_keys).read_text())
        except Exception as e: print(f'            agent-keys error: {e}')

    if args.verbose and pubkeys: print('Signature checks:')
    sigs = check_signatures(commits, struct['steps'], pubkeys, verbose=args.verbose and bool(pubkeys))
    if pubkeys:
        print(f'Phase 2a— Agent signatures:   {c(sigs["ok"] if sigs["failures"]==0 else False)}  ({sigs["verified"]} verified, {sigs["missing"]} skipped, {sigs["failures"]} failed)')
    else:
        print(f'Phase 2a— Agent signatures:   {c(None)}  (pass --agent-keys {{agent_id: pubkey_pem}} to verify)')

    # ── Phase 2b: Checkpoint ──────────────────────────────────────────────────
    cp_result = None
    if args.checkpoint:
        pubkey_pem = Path(args.pubkey).read_text() if args.pubkey else None
        if args.verbose: print('Checkpoint:')
        cp_result = check_checkpoint(args.checkpoint, pubkey_pem, verbose=args.verbose)
        print(f'Phase 2b— Log checkpoint:     {c(cp_result["ok"])}  position={cp_result["position"]}')
    else:
        print(f'Phase 2b— Log checkpoint:     {c(None)}  (pass --checkpoint path/to/checkpoint.json)')

    # ── Phase 3: Merkle inclusion proofs ────────────────────────
    phase3_ok = None
    if not (hasattr(args, 'skip_proof') and args.skip_proof):
        proofs_found = proofs_valid = proofs_failed = 0
        tree_root_from_cp = None
        if cp_result:
            raw = cp_result.get('tree_root') or ''
            tree_root_from_cp = raw[7:] if raw.startswith('sha256:') else (raw or None)

        for i, commit in enumerate(commits):
            pr = commit.get('_proof') or commit.get('proof_receipt')
            if not pr: continue
            proofs_found += 1
            cid        = commit.get('id', f'[{i}]')
            lh_stored  = pr.get('leaf_hash')
            incl_proof = pr.get('inclusion_proof') or {}
            raw_tr     = pr.get('tree_root', '')
            tree_root  = (raw_tr[7:] if raw_tr.startswith('sha256:') else raw_tr) or tree_root_from_cp
            ih         = commit.get('integrity_hash', '')
            ih_bare    = ih[7:] if ih.startswith('sha256:') else ih
            log_pos    = pr.get('log_position')
            accepted   = commit.get('timestamp', '')

            # Recompute leaf hash to confirm it matches stored value
            if lh_stored and ih_bare and log_pos is not None:
                recomp = leaf_hash_from_commit(cid, ih_bare, log_pos, accepted)
                lh_ok  = recomp == lh_stored
            else:
                lh_ok = True  # can't verify without data

            # Verify inclusion proof against tree root
            proof_ok = verify_inclusion_proof(lh_stored or '', incl_proof, tree_root or '') if (lh_stored and tree_root) else False
            ok_both  = lh_ok and proof_ok
            if ok_both: proofs_valid += 1
            else:       proofs_failed += 1

            if args.verbose:
                mark = '✓' if ok_both else ('✗ leaf_mismatch' if not lh_ok else '✗ proof_invalid')
                print(f'  [{i:4d}] {cid[:28]:<28} {mark}')

        if proofs_found > 0:
            phase3_ok = (proofs_failed == 0)
            print(f'Phase 3 — Merkle inclusion:   {c(phase3_ok)}  ({proofs_valid}/{proofs_found} proofs valid)')
        else:
            print(f'Phase 3 — Merkle inclusion:   {c(None)}  (no _proof receipts in export)')
    else:
        print(f'Phase 3 — Merkle inclusion:   {c(None)}  (skipped via --skip-proof)')

    # ── Phase 3.5: Checkpoint consistency ───────────────────────
    consistency_ok = None
    if args.checkpoint and getattr(args, 'checkpoint_b', None):
        try:
            cp_a = json.loads(Path(args.checkpoint).read_text())
            cp_b = json.loads(Path(args.checkpoint_b).read_text())

            def compute_root_local(leaves):
                if not leaves: return hashlib.sha256(b'\x00').hexdigest()
                if len(leaves) == 1: return leaves[0]
                nodes = list(leaves)
                while len(nodes) > 1:
                    nxt = []
                    for i in range(0, len(nodes), 2):
                        nxt.append(node_hash_fn(nodes[i], nodes[i+1]) if i+1 < len(nodes) else nodes[i])
                    nodes = nxt
                return nodes[0]

            # Verify both checkpoint signatures
            pubkey_pem = Path(args.pubkey).read_text() if args.pubkey else None
            sig_a = verify_checkpoint_sig(cp_a, pubkey_pem) if pubkey_pem else None
            sig_b = verify_checkpoint_sig(cp_b, pubkey_pem) if pubkey_pem else None

            # Verify chain linkage
            linked = cp_b.get('previous_cp_id') == cp_a.get('checkpoint_id') or \
                     cp_b.get('previous_tree_root') == cp_a.get('tree_root')

            print(f'Phase 3.5— Checkpoint consistency:')
            print(f'            Checkpoint A: {cp_a.get("checkpoint_id","?")[:24]}  tree_size={cp_a.get("tree_size")}')
            print(f'            Checkpoint B: {cp_b.get("checkpoint_id","?")[:24]}  tree_size={cp_b.get("tree_size")}')
            print(f'            Sig A:        {c(sig_a)}')
            print(f'            Sig B:        {c(sig_b)}')
            print(f'            Chain linked: {c(linked if linked else False)}')
            consistency_ok = (sig_a is None or sig_a) and (sig_b is None or sig_b) and linked
            print(f'            Result:       {c(consistency_ok)}')
        except Exception as e:
            print(f'Phase 3.5— Checkpoint consistency:   {c(False)}  ({e})')
            consistency_ok = False
    else:
        print(f'Phase 3.5— Checkpoint consistency:   {c(None)}  (pass --checkpoint A --checkpoint-b B)')

    # ── Summary ───────────────────────────────────────────────────────────────
    required_ok = struct['ok']
    sig_ok      = sigs['ok'] if pubkeys else None
    chk_ok      = cp_result['ok'] if cp_result else None
    all_ok      = required_ok and (sig_ok is None or sig_ok) and (chk_ok is None or chk_ok) and (phase3_ok is None or phase3_ok) and (consistency_ok is None or consistency_ok)

    print()
    print('────────────────────────────────────────────')
    if all_ok:
        print('\033[32m✓ VERIFIED\033[0m')
        print()
        print('  • Every payload hash matches the stored record')
        print('  • Every chain link is cryptographically sound')
        if sig_ok is True:  print('  • All agent signatures are valid')
        if chk_ok is True:  print('  • Log checkpoint signature is valid')
    else:
        print('\033[31m✗ VERIFICATION FAILED\033[0m')
        if not struct['ok']:        print(f'  Chain broken at: {struct["broken_at"]}')
        if sig_ok is False:         print(f'  Signature failures: {sigs["failures"]}')
        if chk_ok is False:         print('  Checkpoint signature invalid')
    print()

    if args.json:
        print(json.dumps({
            'verified':   all_ok,
            'structure':  {'ok': struct['ok'], 'broken_at': struct['broken_at'], 'length': struct['length']},
            'signatures': {'ok': sig_ok, 'verified': sigs['verified'], 'failures': sigs['failures']},
            'merkle':     {'ok': phase3_ok, 'valid': proofs_valid if proofs_found else 0, 'total': proofs_found if 'proofs_found' in dir() else 0},
            'checkpoint': {'ok': chk_ok},
        }, indent=2))

    sys.exit(0 if all_ok else 1)

if __name__ == '__main__':
    main()
