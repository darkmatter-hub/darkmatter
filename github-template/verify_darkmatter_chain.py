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
    if isinstance(value, list):     return '[' + ','.join(canonicalize(v) for v in value) + ']'
    if isinstance(value, dict):
        pairs = [json.dumps(k, ensure_ascii=False) + ':' + canonicalize(v)
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
    ap.add_argument('--test-vectors',help='Run canonical serialization test vectors and exit')
    ap.add_argument('--json',        action='store_true')
    args = ap.parse_args()

    # Test vectors mode
    if args.test_vectors:
        ok = run_test_vectors(args.test_vectors)
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

    # ── Summary ───────────────────────────────────────────────────────────────
    required_ok = struct['ok']  # structure is always required
    sig_ok      = sigs['ok'] if pubkeys else None
    chk_ok      = cp_result['ok'] if cp_result else None
    all_ok      = required_ok and (sig_ok is None or sig_ok) and (chk_ok is None or chk_ok)

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
            'signatures': {'ok': sig_ok,  'verified': sigs['verified'], 'failures': sigs['failures']},
            'checkpoint': {'ok': chk_ok},
        }, indent=2))

    sys.exit(0 if all_ok else 1)

if __name__ == '__main__':
    main()
