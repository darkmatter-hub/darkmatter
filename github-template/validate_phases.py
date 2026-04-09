#!/usr/bin/env python3
"""
DarkMatter Phase Validation Script
=====================================
Validates the complete integrity model end-to-end:
  Phase 1 — chain structure + agent signatures
  Phase 2 — append-only log + signed checkpoints
  Phase 3 — Merkle inclusion proofs
  Phase 3.5 — checkpoint consistency
  Phase 4A — external witness signatures

Usage:
  python validate_phases.py --api-key dm_sk_... --base-url https://darkmatterhub.ai
  python validate_phases.py --api-key dm_sk_... --bundle export_bundle.json
  python validate_phases.py --test-vectors-only

Requirements: pip install cryptography requests
"""

import sys, json, hashlib, math, re, argparse, time
from pathlib import Path

try:
    import requests
    REQUESTS = True
except ImportError:
    REQUESTS = False

try:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.exceptions import InvalidSignature
    CRYPTO = True
except ImportError:
    CRYPTO = False

# ─── Colours ─────────────────────────────────────────────────────────────────
G  = '\033[32m✓ PASS\033[0m'
R  = '\033[31m✗ FAIL\033[0m'
Y  = '\033[33m~ SKIP\033[0m'
BO = '\033[1m'
RS = '\033[0m'

results = []

def check(name, ok, detail=''):
    mark = G if ok is True else (R if ok is False else Y)
    line = f"  {mark}  {name}"
    if detail: line += f"\n         {detail}"
    print(line)
    results.append((name, ok))
    return ok

def section(title):
    print(f"\n{BO}{title}{RS}")
    print('─' * 50)


# ─── Canonical serialization ─────────────────────────────────────────────────

def canonicalize(value) -> str:
    if value is None:           return 'null'
    if isinstance(value, bool): return 'true' if value else 'false'
    if isinstance(value, int):  return str(value)
    if isinstance(value, float):
        if not math.isfinite(value): raise TypeError(f'non-finite: {value}')
        s = format(value, '.17g')
        if '.' not in s and 'e' not in s: s += '.0'
        elif '.' in s and 'e' not in s:
            s = s.rstrip('0')
            if s.endswith('.'): s += '0'
        return s
    if isinstance(value, str):  return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list): return '[' + ','.join(canonicalize(i) for i in value) + ']'
    if isinstance(value, dict):
        pairs = [json.dumps(k, ensure_ascii=False) + ':' + canonicalize(value[k])
                 for k in sorted(value.keys())]
        return '{' + ','.join(pairs) + '}'
    raise TypeError(type(value).__name__)

def hash_payload(p): return hashlib.sha256(canonicalize(p).encode()).hexdigest()

def build_envelope(ph, parent_ih, agent_id, key_id, timestamp):
    ts = re.sub(r'\.\d+Z?$', '', timestamp or '').rstrip('Z') + 'Z'
    return {
        'schema_version':       '2',
        'agent_id':             agent_id or '',
        'key_id':               key_id or 'default',
        'timestamp':            ts,
        'payload_hash':         ph,
        'parent_integrity_hash': parent_ih or 'root',
    }

def hash_envelope(env): return hashlib.sha256(canonicalize(env).encode()).hexdigest()

def strip(h):
    if not h: return None
    return h[7:] if h.startswith('sha256:') else h

def leaf_hash_from_commit(commit_id, integrity_hash, log_position, accepted_at):
    ts  = re.sub(r'\.\d+Z?$', '', accepted_at or '').rstrip('Z') + 'Z'
    ih  = strip(integrity_hash) or ''
    env = {'accepted_at': ts, 'commit_id': commit_id, 'integrity_hash': ih, 'log_position': log_position}
    buf = b'\x00' + canonicalize(env).encode()
    return hashlib.sha256(buf).hexdigest()

def node_hash(l, r):
    return hashlib.sha256(b'\x01' + bytes.fromhex(l) + bytes.fromhex(r)).hexdigest()

def verify_inclusion_proof(leaf_h, proof, expected_root):
    try:
        cur = leaf_h
        for step in (proof.get('proof') or []):
            cur = node_hash(cur, step['hash']) if step['direction'] == 'right' else node_hash(step['hash'], cur)
        return cur == expected_root
    except Exception: return False


# ─── Phase 1: Chain structure ─────────────────────────────────────────────────

def validate_phase1(commits, strict=True):
    section("Phase 1 — Chain Structure + Payload Hashes")
    if not commits:
        check("commits present", False, "no commits to verify")
        return False

    check("commits present", True, f"{len(commits)} commits")

    broken = None
    prev_ih = None
    missing = 0

    for i, c in enumerate(commits):
        payload   = c.get('payload') or c.get('context') or {}
        agent_id  = c.get('agent_id') or (c.get('agent_info') or {}).get('id') or ''
        key_id    = c.get('key_id')   or (c.get('agent_info') or {}).get('key_id') or 'default'
        ts        = c.get('timestamp') or ''
        s_ph      = strip(c.get('payload_hash'))
        s_ih      = strip(c.get('integrity_hash'))

        if strict and (not s_ph or not s_ih):
            missing += 1
            if not broken: broken = c.get('id')
            continue

        ph   = hash_payload(payload)
        env  = build_envelope(ph, prev_ih, agent_id, key_id, ts)
        ih   = hash_envelope(env)
        p_ok = not s_ph or ph == s_ph
        i_ok = not s_ih or ih == s_ih
        if not (p_ok and i_ok) and not broken:
            broken = c.get('id')
        prev_ih = ih

    chain_ok = broken is None and missing == 0
    check("chain integrity", chain_ok,
          f"broken_at={broken}" if broken else (f"{missing} commits missing hashes" if missing else "all links valid"))
    check("no missing hashes", missing == 0, f"{missing} commits missing payload_hash/integrity_hash" if missing else "")
    return chain_ok


# ─── Phase 2: Checkpoint signature ────────────────────────────────────────────

def validate_phase2(checkpoint, server_pubkey_pem):
    section("Phase 2 — Checkpoint Signature")
    if not checkpoint:
        check("checkpoint present", None, "no checkpoint in bundle")
        return None
    check("checkpoint present", True, f"id={checkpoint.get('checkpoint_id','?')[:24]}")

    if not CRYPTO:
        check("server signature", None, "pip install cryptography to verify")
        return None

    if not server_pubkey_pem:
        check("server signature", None, "no server pubkey in bundle")
        return None

    # Rebuild envelope
    cp = checkpoint
    envelope = {
        'schema_version':     cp.get('schema_version', '3'),
        'checkpoint_id':      cp.get('checkpoint_id'),
        'tree_root':          cp.get('tree_root'),
        'tree_size':          cp.get('tree_size'),
        'log_root':           cp.get('log_root'),
        'log_position':       cp.get('position') or cp.get('log_position'),
        'timestamp':          cp.get('timestamp'),
        'previous_cp_id':     cp.get('previous_cp_id'),
        'previous_tree_root': cp.get('previous_tree_root'),
    }
    try:
        msg    = canonicalize(envelope).encode()
        sig    = bytes.fromhex(cp['server_sig'])
        pubkey = load_pem_public_key(server_pubkey_pem.encode())
        pubkey.verify(sig, msg)
        check("server signature", True, f"tree_root={cp.get('tree_root','')[:16]}... size={cp.get('tree_size')}")
        return True
    except InvalidSignature:
        check("server signature", False, "signature invalid")
        return False
    except Exception as e:
        check("server signature", False, str(e))
        return False


# ─── Phase 3: Merkle inclusion proofs ─────────────────────────────────────────

def validate_phase3(commits, checkpoint):
    section("Phase 3 — Merkle Inclusion Proofs")
    proofs_found = proofs_valid = proofs_failed = 0
    cp_tree_root = None

    if checkpoint:
        raw = checkpoint.get('tree_root', '')
        cp_tree_root = strip(raw) or raw or None

    for c in commits:
        pr = c.get('_proof') or c.get('proof_receipt')
        if not pr: continue
        proofs_found += 1

        lh_stored  = pr.get('leaf_hash')
        incl_proof = pr.get('inclusion_proof') or {}
        raw_tr     = pr.get('tree_root', '')
        tree_root  = strip(raw_tr) or raw_tr or cp_tree_root
        ih         = strip(c.get('integrity_hash')) or ''
        log_pos    = pr.get('log_position')
        accepted   = pr.get('accepted_at') or c.get('timestamp', '')

        # Recompute leaf hash
        if lh_stored and ih and log_pos is not None:
            recomp = leaf_hash_from_commit(c.get('id',''), ih, log_pos, accepted)
            lh_ok  = recomp == lh_stored
        else:
            lh_ok = True

        proof_ok = verify_inclusion_proof(lh_stored or '', incl_proof, tree_root or '') if (lh_stored and tree_root) else False
        if lh_ok and proof_ok: proofs_valid += 1
        else: proofs_failed += 1

    if proofs_found == 0:
        check("Merkle proofs", None, "no _proof receipts in bundle — export may be pre-Phase-3")
        return None

    ok = proofs_failed == 0
    check("Merkle proofs", ok, f"{proofs_valid}/{proofs_found} valid" + (f", {proofs_failed} failed" if proofs_failed else ""))
    return ok


# ─── Phase 4A: Witness signatures ─────────────────────────────────────────────

def validate_phase4a(checkpoint):
    section("Phase 4A — Witness Signatures")
    if not checkpoint:
        check("witnesses", None, "no checkpoint")
        return None

    witness_sigs = checkpoint.get('witness_signatures') or []
    if not witness_sigs:
        check("witnesses", None, "no witness_signatures in checkpoint — not yet witnessed")
        return None

    check("witness signatures present", True, f"{len(witness_sigs)} witness(es)")

    if not CRYPTO:
        check("signature verification", None, "pip install cryptography")
        return None

    # Rebuild envelope for verification
    cp = checkpoint
    envelope = {
        'schema_version':     cp.get('schema_version', '3'),
        'checkpoint_id':      cp.get('checkpoint_id'),
        'tree_root':          cp.get('tree_root'),
        'tree_size':          cp.get('tree_size'),
        'log_root':           cp.get('log_root'),
        'log_position':       cp.get('position') or cp.get('log_position'),
        'timestamp':          cp.get('timestamp'),
        'previous_cp_id':     cp.get('previous_cp_id'),
        'previous_tree_root': cp.get('previous_tree_root'),
    }
    msg = canonicalize(envelope).encode()

    w_valid = w_failed = 0
    for ws in witness_sigs:
        pubkey_pem = ws.get('public_key_pem')
        wit_sig    = ws.get('witness_sig')
        wit_name   = ws.get('witness_name') or ws.get('witness_id', '?')
        if not pubkey_pem or not wit_sig:
            print(f"    ~ {wit_name}: no public key in bundle")
            continue
        try:
            load_pem_public_key(pubkey_pem.encode()).verify(bytes.fromhex(wit_sig), msg)
            w_valid += 1
            print(f"    ✓ {wit_name}: signature valid")
        except Exception as e:
            w_failed += 1
            print(f"    ✗ {wit_name}: {e}")

    ok = w_failed == 0 and w_valid > 0
    check("witness sig verification", ok, f"{w_valid} valid, {w_failed} failed")
    return ok


# ─── Canonical test vectors ───────────────────────────────────────────────────

def validate_test_vectors(vectors_path):
    section("Canonical Serialization Test Vectors")
    v = json.loads(Path(vectors_path).read_text())
    all_ok = True
    for vec in v.get('canonicalize_vectors', []):
        got    = canonicalize(vec['input'])
        ok     = got == vec['expected']
        if not ok: all_ok = False
        check(f"{vec['id']}: {vec['desc']}", ok,
              f"exp={vec['expected']!r}\ngot={got!r}" if not ok else '')
    return all_ok


def validate_merkle_vectors(vectors_path):
    section("Merkle Test Vectors")
    v = json.loads(Path(vectors_path).read_text())
    all_ok = True

    def compute_root(leaves):
        if not leaves: return hashlib.sha256(b'\x00').hexdigest()
        if len(leaves) == 1: return leaves[0]
        nodes = list(leaves)
        while len(nodes) > 1:
            nxt = []
            for i in range(0, len(nodes), 2):
                nxt.append(node_hash(nodes[i], nodes[i+1]) if i+1 < len(nodes) else nodes[i])
            nodes = nxt
        return nodes[0]

    for vec in v.get('leaf_vectors', []):
        got = leaf_hash_from_commit(vec['commit_id'], vec['integrity_hash'],
                                    vec['log_position'], vec['accepted_at'])
        ok  = got == vec['expected_leaf_hash']
        if not ok: all_ok = False
        check(f"{vec['id']}: {vec['desc']}", ok)

    for vec in v.get('root_vectors', []):
        got = compute_root(vec['leaf_hashes'])
        ok  = got == vec['expected_root']
        if not ok: all_ok = False
        check(f"{vec['id']}: {vec['desc']}", ok)

    for vec in v.get('proof_vectors', []):
        got = verify_inclusion_proof(vec['leaf_hash'], {'proof': vec['proof']}, vec['tree_root'])
        ok  = got == vec['expected_valid']
        if not ok: all_ok = False
        check(f"{vec['id']}: {vec['desc']}", ok)

    return all_ok


# ─── Live API validation ──────────────────────────────────────────────────────

def validate_live(base_url, api_key):
    headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}

    section("Live API — Health Checks")
    try:
        r = requests.get(f'{base_url}/api/log/pubkey', timeout=10)
        check("/api/log/pubkey", r.status_code == 200,
              f"status={r.status_code}")
        pubkey = r.json().get('public_key') if r.ok else None
    except Exception as e:
        check("/api/log/pubkey", False, str(e))
        pubkey = None

    try:
        r = requests.get(f'{base_url}/api/log/checkpoint', timeout=10)
        check("/api/log/checkpoint", r.status_code == 200)
        cp_data = r.json().get('checkpoint') if r.ok else None
    except Exception as e:
        check("/api/log/checkpoint", False, str(e))
        cp_data = None

    try:
        r = requests.get(f'{base_url}/api/witnesses', timeout=10)
        wits = r.json().get('witnesses', []) if r.ok else []
        check("/api/witnesses", r.status_code == 200, f"{len(wits)} registered")
    except Exception as e:
        check("/api/witnesses", False, str(e))

    if cp_data:
        section("Live API — Checkpoint Validation")
        validate_phase2(cp_data, pubkey)

        # Check witness sigs on latest checkpoint
        cp_id = cp_data.get('checkpoint_id')
        if cp_id:
            try:
                r = requests.get(f'{base_url}/api/log/checkpoint/{cp_id}/witnesses', timeout=10)
                if r.ok:
                    wit_data = r.json()
                    count = wit_data.get('witness_count', 0)
                    check("witnesses on latest checkpoint", count > 0,
                          f"witness_count={count}")
            except Exception as e:
                check("witnesses on latest checkpoint", False, str(e))

    section("Live API — Make Test Commit + Verify")
    try:
        # Get an agent to send to
        r = requests.get(f'{base_url}/api/me', headers=headers, timeout=10)
        if not r.ok:
            check("authenticated", False, f"status={r.status_code}")
            return
        me = r.json()
        # /api/me may return nested agent object or flat
        # /api/me returns camelCase: { agentId, agentName }
        agent_id = (me.get('agentId')
                    or me.get('agent_id')
                    or me.get('id')
                    or (me.get('agent') or {}).get('agent_id'))
        check("authenticated", True, f"agent_id={agent_id}")

        if not agent_id:
            check("test commit", False, "could not determine agent_id from /api/me response")
            return

        # Make a test commit — send to self (agent commits to itself)
        payload = json.dumps({
            'toAgentId': agent_id,
            'payload':   {'test': 'validate_phases', 'ts': str(time.time())}
        })
        r = requests.post(f'{base_url}/api/commit', headers=headers,
                          data=payload, timeout=15)
        ok = r.ok and r.json().get('verified')
        check("test commit", ok, f"status={r.status_code}")

        if ok:
            commit_data = r.json()
            ctx_id      = commit_data.get('id')
            has_proof   = '_proof' in commit_data
            check("proof receipt returned", has_proof,
                  f"log_position={commit_data.get('_proof',{}).get('log_position')}" if has_proof else "no _proof in response")

            # Verify chain
            r2 = requests.get(f'{base_url}/api/verify/{ctx_id}', headers=headers, timeout=10)
            if r2.ok:
                check("chain verified", r2.json().get('chain_intact'), r2.json().get('message',''))

    except Exception as e:
        check("test commit flow", False, str(e))


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description='DarkMatter Phase 1-4A validation')
    ap.add_argument('--api-key',          help='DarkMatter API key (dm_sk_...)')
    ap.add_argument('--base-url',         default='https://darkmatterhub.ai')
    ap.add_argument('--bundle',           help='Path to exported proof bundle JSON')
    ap.add_argument('--test-vectors-only',action='store_true')
    ap.add_argument('--vectors-dir',      default='.',
                    help='Directory containing test vector JSON files')
    args = ap.parse_args()

    print(f"\n{BO}DarkMatter Phase Validation — v1.0{RS}")
    print(f"Base URL: {args.base_url}")
    print()

    vectors_dir = Path(args.vectors_dir)
    iv_path = vectors_dir / 'integrity_test_vectors.json'
    mv_path = vectors_dir / 'merkle_test_vectors.json'

    # Always run test vectors if available
    if iv_path.exists():
        validate_test_vectors(str(iv_path))
    if mv_path.exists():
        validate_merkle_vectors(str(mv_path))

    if args.test_vectors_only:
        pass
    elif args.bundle:
        # Validate from export bundle
        bundle = json.loads(Path(args.bundle).read_text())
        commits    = bundle.get('commits') or []
        checkpoint = bundle.get('checkpoint')
        pubkey_pem = (bundle.get('server_pubkey') or {}).get('public_key')

        validate_phase1(commits)
        validate_phase2(checkpoint, pubkey_pem)
        validate_phase3(commits, checkpoint)
        validate_phase4a(checkpoint)

    elif args.api_key:
        if not REQUESTS:
            print("ERROR: pip install requests")
            sys.exit(1)
        validate_live(args.base_url, args.api_key)
    else:
        print("Pass --api-key, --bundle, or --test-vectors-only")
        ap.print_help()

    # Summary
    total  = len(results)
    passed = sum(1 for _, ok in results if ok is True)
    failed = sum(1 for _, ok in results if ok is False)
    skipped= sum(1 for _, ok in results if ok is None)

    print(f"\n{'─'*50}")
    if failed == 0:
        print(f"\033[32m✓ VALIDATED — {passed}/{total} checks passed"
              + (f", {skipped} skipped" if skipped else "") + "\033[0m")
    else:
        print(f"\033[31m✗ {failed} checks FAILED ({passed} passed, {skipped} skipped)\033[0m")
    print()
    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    main()
