#!/usr/bin/env python3
"""
DarkMatter Witness Server — Railway deployment
===============================================
Reads private key from WITNESS_PRIVATE_KEY environment variable.
Set this in Railway dashboard → Variables.
"""

import sys
import os
import json
import hashlib
import math
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("ERROR: cryptography not installed. Run: pip install cryptography")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [witness] %(message)s'
)
log = logging.getLogger('witness')


# ─── Canonical serialization (DarkMatter Spec v1.0) ──────────────────────────

def canonicalize(value) -> str:
    if value is None:           return 'null'
    if isinstance(value, bool): return 'true' if value else 'false'
    if isinstance(value, int):  return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError(f'non-finite number rejected: {value}')
        s = format(value, '.17g')
        if '.' not in s and 'e' not in s:
            s += '.0'
        elif '.' in s and 'e' not in s:
            s = s.rstrip('0')
            if s.endswith('.'): s += '0'
        return s
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return '[' + ','.join(canonicalize(item) for item in value) + ']'
    if isinstance(value, dict):
        pairs = [
            json.dumps(k, ensure_ascii=False) + ':' + canonicalize(value[k])
            for k in sorted(value.keys())
        ]
        return '{' + ','.join(pairs) + '}'
    raise TypeError(f'Cannot canonicalize: {type(value).__name__}')


# ─── Checkpoint processing ────────────────────────────────────────────────────

def build_checkpoint_envelope(cp: dict) -> dict:
    """
    Build the exact canonical envelope that DarkMatter signed.
    Key order matches DarkMatter Spec v1.0 checkpoint format.
    """
    return {
        'schema_version':     cp.get('schema_version', '3'),
        'checkpoint_id':      cp['checkpoint_id'],
        'tree_root':          cp['tree_root'],
        'tree_size':          cp['tree_size'],
        'log_root':           cp['log_root'],
        'log_position':       cp.get('position') or cp.get('log_position'),
        'timestamp':          cp['timestamp'],
        'previous_cp_id':     cp.get('previous_cp_id'),
        'previous_tree_root': cp.get('previous_tree_root'),
    }


def process_checkpoint(body: dict, private_key_pem: bytes, witness_log_path: Path) -> dict:
    """
    Core witness logic:
    1. Verify DarkMatter's signature on the checkpoint
    2. Sign the same envelope with our witness key
    3. Log locally
    4. Return signature to DarkMatter
    """
    checkpoint    = body.get('checkpoint', {})
    dm_pubkey_pem = body.get('darkmatter_pubkey', '')

    # Validate required fields
    required = ['checkpoint_id', 'tree_root', 'tree_size', 'log_root', 'timestamp', 'server_sig']
    missing  = [f for f in required if not checkpoint.get(f)]
    if missing:
        return {'error': f'Missing required fields: {missing}'}

    # Build canonical envelope — this is what gets signed
    envelope = build_checkpoint_envelope(checkpoint)
    msg      = canonicalize(envelope).encode('utf-8')

    # Step 1: Verify DarkMatter's server signature
    try:
        dm_pub  = load_pem_public_key(dm_pubkey_pem.encode())
        dm_sig  = bytes.fromhex(checkpoint['server_sig'])
        dm_pub.verify(dm_sig, msg)
        log.info(f"DarkMatter sig verified: {checkpoint['checkpoint_id']}")
    except InvalidSignature:
        log.warning(f"DarkMatter sig INVALID: {checkpoint['checkpoint_id']}")
        return {'error': 'DarkMatter server signature is invalid — refusing to co-sign'}
    except Exception as e:
        log.error(f"Sig verification error: {e}")
        return {'error': f'Signature verification failed: {e}'}

    # Step 2: Sign with our witness private key
    priv_key     = load_pem_private_key(private_key_pem, password=None)
    witnessed_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    witness_sig  = priv_key.sign(msg).hex()

    # Derive witness_id from our public key (deterministic)
    pub_der    = priv_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    witness_id = 'wit_' + hashlib.sha256(pub_der).hexdigest()[:16]

    log.info(f"Signed checkpoint {checkpoint['checkpoint_id']} "
             f"tree_size={checkpoint['tree_size']} "
             f"tree_root={checkpoint['tree_root'][:12]}...")

    # Step 3: Append to local witness log (JSONL — one line per checkpoint)
    log_entry = {
        'checkpoint_id':  checkpoint['checkpoint_id'],
        'tree_root':      checkpoint['tree_root'],
        'tree_size':      checkpoint['tree_size'],
        'log_position':   envelope['log_position'],
        'timestamp':      checkpoint['timestamp'],
        'dm_sig_valid':   True,
        'witness_sig':    witness_sig,
        'witnessed_at':   witnessed_at,
        'witness_id':     witness_id,
    }
    try:
        with open(witness_log_path, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        log.error(f"Failed to write witness log: {e}")

    # Step 4: Return signature to DarkMatter
    return {
        'witness_id':     witness_id,
        'checkpoint_id':  checkpoint['checkpoint_id'],
        'tree_root':      checkpoint['tree_root'],
        'tree_size':      checkpoint['tree_size'],
        'witness_sig':    witness_sig,
        'witnessed_at':   witnessed_at,
    }


# ─── HTTP handler ─────────────────────────────────────────────────────────────

def make_handler(private_key_pem: bytes, witness_log_path: Path, witness_id: str):
    class WitnessHandler(BaseHTTPRequestHandler):

        def log_message(self, fmt, *args):
            log.info(f"{self.client_address[0]} — {fmt % args}")

        def do_GET(self):
            if self.path in ('/', '/health'):
                self._json(200, {
                    'status':      'ok',
                    'role':        'darkmatter_witness',
                    'witness_id':  witness_id,
                    'spec':        'https://darkmatterhub.ai/docs#integrity-spec',
                })
            else:
                self._json(404, {'error': 'not found'})

        def do_POST(self):
            if self.path not in ('/witness', '/witness/'):
                return self._json(404, {'error': 'not found — use POST /witness'})

            try:
                length = int(self.headers.get('Content-Length', 0))
                if length == 0:
                    return self._json(400, {'error': 'empty body'})
                body   = json.loads(self.rfile.read(length))
            except Exception as e:
                return self._json(400, {'error': f'invalid JSON: {e}'})

            result = process_checkpoint(body, private_key_pem, witness_log_path)
            status = 200 if 'witness_sig' in result else 400
            self._json(status, result)

        def _json(self, status: int, body: dict):
            data = json.dumps(body, indent=2).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(data))
            self.end_headers()
            self.wfile.write(data)

    return WitnessHandler


# ─── Startup ──────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description='DarkMatter witness server')
    ap.add_argument('--port',       type=int, default=8080)
    ap.add_argument('--log-file',   default='witness_log.jsonl')
    ap.add_argument('--private-key', help='Path to private key PEM file (alternative to env var)')
    args = ap.parse_args()

    # Load private key — env var takes priority over file
    key_env = os.environ.get('WITNESS_PRIVATE_KEY', '').strip()
    if key_env:
        # Railway env var: replace literal \n with actual newlines
        private_key_pem = key_env.replace('\\n', '\n').encode()
        log.info("Private key loaded from WITNESS_PRIVATE_KEY environment variable")
    elif args.private_key:
        private_key_pem = Path(args.private_key).read_bytes()
        log.info(f"Private key loaded from {args.private_key}")
    else:
        log.error("No private key found. Set WITNESS_PRIVATE_KEY env var or pass --private-key")
        sys.exit(1)

    # Validate key and derive witness_id
    try:
        priv    = load_pem_private_key(private_key_pem, password=None)
        pub_der = priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        witness_id = 'wit_' + hashlib.sha256(pub_der).hexdigest()[:16]
    except Exception as e:
        log.error(f"Invalid private key: {e}")
        sys.exit(1)

    log.info(f"Witness ID:  {witness_id}")
    log.info(f"Witness log: {args.log_file}")
    log.info(f"Port:        {args.port}")
    log.info(f"Public key (register this with DarkMatter):")
    for line in pub_pem.strip().split('\n'):
        log.info(f"  {line}")

    witness_log = Path(args.log_file)
    handler     = make_handler(private_key_pem, witness_log, witness_id)

    server = HTTPServer(('0.0.0.0', args.port), handler)
    log.info(f"Witness server ready — POST /witness to submit checkpoints")
    server.serve_forever()


if __name__ == '__main__':
    main()
