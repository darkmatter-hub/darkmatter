#!/usr/bin/env python3
"""
DarkMatter Reference Witness Server
=====================================
A standalone HTTP server that acts as an external witness for DarkMatter checkpoints.

This is what an independent auditing organisation (Deloitte, E&Y, university,
independent researcher) would run to co-sign DarkMatter checkpoints.

What it does:
  1. Receives checkpoint delivery from DarkMatter (POST /witness)
  2. Verifies DarkMatter's own server signature on the checkpoint
  3. Verifies the checkpoint is structurally valid (correct fields, no missing data)
  4. Signs the same canonical checkpoint envelope with the witness's own Ed25519 key
  5. Returns the witness signature to DarkMatter
  6. Stores a local log of all witnessed checkpoints for independent audit

What the witness server needs:
  - Its own Ed25519 keypair (private key stays on witness server only)
  - The witness's public key must be registered with DarkMatter
  - An HTTPS endpoint DarkMatter can reach

What this proves:
  "At timestamp T, [witness organisation] independently confirmed that the
   DarkMatter log had Merkle tree root R at tree size N, and that DarkMatter's
   server signature on this checkpoint is valid."

Witness servers are entirely independent. They cannot be pressured to produce
a false signature because they have nothing to gain from lying — their
professional reputation is the thing they're staking.

Usage:
  # 1. Generate witness keypair
  python darkmatter_witness_server.py --generate-keys --name "My Organisation"

  # 2. Register public key with DarkMatter
  #    POST https://darkmatterhub.ai/api/admin/witnesses
  #    { "name": "My Organisation", "publicKey": "<pem>", "endpointUrl": "https://..." }

  # 3. Run the witness server
  python darkmatter_witness_server.py --private-key witness.private.pem --port 8080

Requirements:
  pip install cryptography
"""

import sys
import json
import hashlib
import math
import re
import argparse
import logging
from datetime import datetime, timezone
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
    from cryptography.exceptions import InvalidSignature
    CRYPTO = True
except ImportError:
    print('ERROR: pip install cryptography')
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s [witness] %(message)s')
log = logging.getLogger('witness')


# ─── Canonical serialization (must match DarkMatter spec v1 exactly) ──────────

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
    if isinstance(value, list): return '[' + ','.join(canonicalize(item) for item in value) + ']'
    if isinstance(value, dict):
        pairs = [json.dumps(k, ensure_ascii=False) + ':' + canonicalize(value[k])
                 for k in sorted(value.keys())]
        return '{' + ','.join(pairs) + '}'
    raise TypeError(type(value).__name__)


# ─── Key generation ───────────────────────────────────────────────────────────

def generate_keypair(name: str, output_dir: str = '.') -> dict:
    private_key = Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    pub_bytes  = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    witness_id = 'wit_' + hashlib.sha256(pub_bytes).hexdigest()[:16]

    safe = name.lower().replace(' ', '-')
    out  = Path(output_dir)
    priv = out / f'{safe}.witness.private.pem'
    pub  = out / f'{safe}.witness.public.pem'

    priv.write_bytes(private_pem)
    priv.chmod(0o600)
    pub.write_bytes(public_pem)

    print(f'✓ Witness keypair generated')
    print(f'  Witness ID:  {witness_id}')
    print(f'  Private key: {priv}  ← keep secret, never share')
    print(f'  Public key:  {pub}   ← register this with DarkMatter')
    print(f'')
    print(f'  Register with DarkMatter:')
    print(f'  POST https://darkmatterhub.ai/api/admin/witnesses')
    print(f'  {{')
    print(f'    "name": "{name}",')
    print(f'    "publicKey": "<contents of {pub}>",')
    print(f'    "endpointUrl": "https://your-witness-server.example.com/witness"')
    print(f'  }}')
    return {'witness_id': witness_id, 'private_key_path': str(priv), 'public_key_path': str(pub)}


# ─── Checkpoint verification and signing ──────────────────────────────────────

def build_checkpoint_envelope(checkpoint: dict) -> dict:
    """Extract the canonical envelope from a checkpoint for signing/verification."""
    return {
        'schema_version':     checkpoint.get('schema_version', '3'),
        'checkpoint_id':      checkpoint['checkpoint_id'],
        'tree_root':          checkpoint['tree_root'],
        'tree_size':          checkpoint['tree_size'],
        'log_root':           checkpoint['log_root'],
        'log_position':       checkpoint.get('position') or checkpoint.get('log_position'),
        'timestamp':          checkpoint['timestamp'],
        'previous_cp_id':     checkpoint.get('previous_cp_id'),
        'previous_tree_root': checkpoint.get('previous_tree_root'),
    }


def process_checkpoint(body: dict, private_key_pem: bytes, witness_log_path: Path) -> dict:
    """
    Core witness logic: verify DarkMatter's signature then sign the checkpoint.
    Returns the response dict to send back to DarkMatter.
    """
    checkpoint     = body.get('checkpoint', {})
    dm_pubkey_pem  = body.get('darkmatter_pubkey', '')

    # Validate required fields
    required = ['checkpoint_id', 'tree_root', 'tree_size', 'log_root', 'timestamp', 'server_sig']
    missing  = [f for f in required if not checkpoint.get(f)]
    if missing:
        return {'error': f'Missing required checkpoint fields: {missing}'}

    # Build canonical envelope
    envelope = build_checkpoint_envelope(checkpoint)
    msg      = canonicalize(envelope).encode('utf-8')

    # 1. Verify DarkMatter's server signature
    try:
        dm_pub = load_pem_public_key(dm_pubkey_pem.encode())
        sig    = bytes.fromhex(checkpoint['server_sig'])
        dm_pub.verify(sig, msg)
        log.info(f'DarkMatter sig verified for {checkpoint["checkpoint_id"]}')
    except (InvalidSignature, Exception) as e:
        log.warning(f'DarkMatter sig INVALID for {checkpoint["checkpoint_id"]}: {e}')
        return {'error': f'DarkMatter server signature invalid: {e}'}

    # 2. Sign with witness private key
    priv_key     = load_pem_private_key(private_key_pem, password=None)
    witnessed_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    witness_sig  = priv_key.sign(msg).hex()

    # Derive witness ID from our public key
    pub_bytes  = priv_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    witness_id = 'wit_' + hashlib.sha256(pub_bytes).hexdigest()[:16]

    log.info(f'Signed checkpoint {checkpoint["checkpoint_id"]} tree_size={checkpoint["tree_size"]}')

    # 3. Append to local witness log
    log_entry = {
        'checkpoint_id': checkpoint['checkpoint_id'],
        'tree_root':     checkpoint['tree_root'],
        'tree_size':     checkpoint['tree_size'],
        'dm_sig_valid':  True,
        'witness_sig':   witness_sig,
        'witnessed_at':  witnessed_at,
    }
    with open(witness_log_path, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')

    return {
        'witness_id':    witness_id,
        'checkpoint_id': checkpoint['checkpoint_id'],
        'tree_root':     checkpoint['tree_root'],
        'tree_size':     checkpoint['tree_size'],
        'witness_sig':   witness_sig,
        'witnessed_at':  witnessed_at,
    }


# ─── HTTP server ──────────────────────────────────────────────────────────────

def make_handler(private_key_pem: bytes, witness_log_path: Path):
    class WitnessHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            log.info(f'{self.client_address[0]} - {format % args}')

        def do_GET(self):
            if self.path == '/health':
                self._respond(200, {'status': 'ok', 'role': 'darkmatter_witness'})
            else:
                self._respond(404, {'error': 'not found'})

        def do_POST(self):
            if self.path not in ('/witness', '/witness/'):
                return self._respond(404, {'error': 'not found'})

            length = int(self.headers.get('Content-Length', 0))
            body   = json.loads(self.rfile.read(length))
            result = process_checkpoint(body, private_key_pem, witness_log_path)

            status = 200 if 'witness_sig' in result else 400
            self._respond(status, result)

        def _respond(self, status: int, body: dict):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(data))
            self.end_headers()
            self.wfile.write(data)

    return WitnessHandler


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description='DarkMatter reference witness server')
    ap.add_argument('--generate-keys', action='store_true', help='Generate a new witness keypair and exit')
    ap.add_argument('--name',        default='DarkMatter Witness', help='Organisation name (for key generation)')
    ap.add_argument('--private-key', help='Path to witness Ed25519 private key PEM')
    ap.add_argument('--port',        type=int, default=8080, help='Port to listen on (default: 8080)')
    ap.add_argument('--log-file',    default='witness_log.jsonl', help='Path to local witness log')
    args = ap.parse_args()

    if args.generate_keys:
        generate_keypair(args.name)
        sys.exit(0)

    if not args.private_key:
        print('Error: --private-key required (or use --generate-keys to create one)')
        sys.exit(1)

    private_key_pem  = Path(args.private_key).read_bytes()
    witness_log_path = Path(args.log_file)

    # Derive and display witness ID on startup
    priv    = load_pem_private_key(private_key_pem, password=None)
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    witness_id = 'wit_' + hashlib.sha256(pub_der).hexdigest()[:16]

    log.info(f'Witness ID:  {witness_id}')
    log.info(f'Witness log: {witness_log_path}')
    log.info(f'Listening on port {args.port}')
    log.info(f'Endpoint to register: http://your-host:{args.port}/witness')

    server = HTTPServer(('0.0.0.0', args.port), make_handler(private_key_pem, witness_log_path))
    server.serve_forever()


if __name__ == '__main__':
    main()
