#!/usr/bin/env python3
"""
DarkMatter Witness Server v2 — Railway deployment
===================================================
Phase 4A: external witness that co-signs DarkMatter checkpoints.

Security hardening (per Phase 4A checklist):
  - Pins DarkMatter public key from env var (DARKMATTER_PUBKEY)
    Rejects requests where incoming darkmatter_pubkey doesn't match.
    Prevents: attacker sends fake checkpoint + their own pubkey → witness signs it.
  - Replay protection: refuses to sign checkpoint_id <= last signed
  - Rate limiting: max 10 requests per minute per IP
  - Local append-only witness log (never overwritten)
  - Health endpoint returns witness_id

Environment variables:
  WITNESS_PRIVATE_KEY   — Ed25519 private key PEM (required)
  DARKMATTER_PUBKEY     — DarkMatter server public key PEM (required — pin this)
  PORT                  — port to listen on (default 8080)
"""

import sys
import os
import json
import hashlib
import math
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import defaultdict

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("ERROR: pip install cryptography")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s [witness] %(message)s')
log = logging.getLogger('witness')


# ─── Canonical serialization — DarkMatter Spec v1.0 ──────────────────────────

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


# ─── Checkpoint envelope ──────────────────────────────────────────────────────

def build_checkpoint_envelope(cp: dict) -> dict:
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


# ─── State ────────────────────────────────────────────────────────────────────

class WitnessState:
    def __init__(self, private_key_pem: bytes, pinned_dm_pubkey_pem: str,
                 witness_log_path: Path):
        # Load and validate private key
        self.private_key = load_pem_private_key(private_key_pem, password=None)
        pub_der = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        self.witness_id  = 'wit_' + hashlib.sha256(pub_der).hexdigest()[:16]
        self.public_key_pem = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()

        # Pin the DarkMatter public key — loaded from env, never from request
        self.pinned_dm_pubkey_pem = pinned_dm_pubkey_pem.strip()
        self.pinned_dm_pubkey     = load_pem_public_key(pinned_dm_pubkey_pem.encode())

        # Replay protection — track last signed checkpoint_id (sequential by position)
        self.last_signed_position = -1
        self.signed_checkpoint_ids = set()

        # Rate limiting — requests per IP per minute
        self.request_times = defaultdict(list)
        self.rate_limit    = 10  # max per minute per IP

        # Local witness log
        self.log_path = witness_log_path
        self._load_last_position()

    def _load_last_position(self):
        """Load last signed position from local log for replay protection across restarts."""
        if not self.log_path.exists():
            return
        try:
            lines = self.log_path.read_text().strip().split('\n')
            for line in reversed(lines):
                if line.strip():
                    entry = json.loads(line)
                    pos = entry.get('log_position', -1)
                    if pos > self.last_signed_position:
                        self.last_signed_position = pos
                    self.signed_checkpoint_ids.add(entry.get('checkpoint_id', ''))
            log.info(f"Loaded witness log: last position={self.last_signed_position}")
        except Exception as e:
            log.warning(f"Could not load witness log: {e}")

    def check_rate_limit(self, ip: str) -> bool:
        now = time.time()
        self.request_times[ip] = [t for t in self.request_times[ip] if now - t < 60]
        if len(self.request_times[ip]) >= self.rate_limit:
            return False
        self.request_times[ip].append(now)
        return True

    def process(self, body: dict, client_ip: str) -> tuple[int, dict]:
        checkpoint    = body.get('checkpoint', {})
        incoming_pem  = (body.get('darkmatter_pubkey') or '').strip()

        # Rate limit
        if not self.check_rate_limit(client_ip):
            log.warning(f"Rate limit hit from {client_ip}")
            return 429, {'error': 'Rate limit exceeded — max 10 requests per minute'}

        # Validate required fields
        required = ['checkpoint_id', 'tree_root', 'tree_size', 'log_root',
                    'timestamp', 'server_sig']
        missing = [f for f in required if not checkpoint.get(f)]
        if missing:
            return 400, {'error': f'Missing required checkpoint fields: {missing}'}

        # ── CRITICAL: Pin DarkMatter public key ──────────────────────────────
        # Reject if incoming pubkey doesn't match our pinned key.
        # Prevents: attacker submits fake checkpoint + their own pubkey.
        if incoming_pem and incoming_pem != self.pinned_dm_pubkey_pem:
            log.warning(f"Pubkey mismatch! Rejecting checkpoint {checkpoint['checkpoint_id']}")
            return 403, {'error': 'DarkMatter public key does not match pinned key — request rejected'}

        # ── Replay protection ─────────────────────────────────────────────────
        cp_id  = checkpoint['checkpoint_id']
        cp_pos = checkpoint.get('log_position') or checkpoint.get('position') or 0

        if cp_id in self.signed_checkpoint_ids:
            log.info(f"Already signed {cp_id} — returning cached acceptance")
            return 200, {'error': 'already_signed', 'checkpoint_id': cp_id,
                         'witness_id': self.witness_id}

        if cp_pos <= self.last_signed_position:
            log.warning(f"Replay attempt: pos={cp_pos} <= last={self.last_signed_position}")
            return 400, {'error': f'Replay rejected: position {cp_pos} <= last signed {self.last_signed_position}'}

        # ── Verify DarkMatter server signature ───────────────────────────────
        envelope = build_checkpoint_envelope(checkpoint)
        msg      = canonicalize(envelope).encode('utf-8')

        try:
            dm_sig = bytes.fromhex(checkpoint['server_sig'])
            self.pinned_dm_pubkey.verify(dm_sig, msg)
            log.info(f"DM sig verified: {cp_id}")
        except InvalidSignature:
            log.warning(f"DM sig INVALID: {cp_id}")
            return 400, {'error': 'DarkMatter server signature is invalid — refusing to co-sign'}
        except Exception as e:
            return 400, {'error': f'Signature verification error: {e}'}

        # ── Sign with witness key ─────────────────────────────────────────────
        witnessed_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        witness_sig  = self.private_key.sign(msg).hex()

        log.info(f"Signed {cp_id} tree_size={checkpoint['tree_size']} "
                 f"tree_root={checkpoint['tree_root'][:12]}...")

        # ── Update state ──────────────────────────────────────────────────────
        self.last_signed_position = cp_pos
        self.signed_checkpoint_ids.add(cp_id)

        # ── Write to append-only local log ───────────────────────────────────
        entry = {
            'checkpoint_id':  cp_id,
            'tree_root':      checkpoint['tree_root'],
            'tree_size':      checkpoint['tree_size'],
            'log_position':   cp_pos,
            'timestamp':      checkpoint['timestamp'],
            'dm_sig_valid':   True,
            'witness_sig':    witness_sig,
            'witnessed_at':   witnessed_at,
            'witness_id':     self.witness_id,
        }
        try:
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception as e:
            log.error(f"Failed to write witness log: {e}")

        return 200, {
            'witness_id':    self.witness_id,
            'checkpoint_id': cp_id,
            'tree_root':     checkpoint['tree_root'],
            'tree_size':     checkpoint['tree_size'],
            'witness_sig':   witness_sig,
            'witnessed_at':  witnessed_at,
        }


# ─── HTTP handler ─────────────────────────────────────────────────────────────

def make_handler(state: WitnessState):
    class Handler(BaseHTTPRequestHandler):

        def log_message(self, fmt, *args):
            log.info(f"{self.client_address[0]} — {fmt % args}")

        def do_GET(self):
            if self.path in ('/', '/health'):
                self._json(200, {
                    'status':        'ok',
                    'role':          'darkmatter_witness',
                    'witness_id':    state.witness_id,
                    'last_position': state.last_signed_position,
                    'spec':          'https://darkmatterhub.ai/docs#integrity-spec',
                    'version':       '2.0',
                })
            else:
                self._json(404, {'error': 'not found'})

        def do_POST(self):
            if self.path not in ('/witness', '/witness/'):
                return self._json(404, {'error': 'use POST /witness'})
            try:
                length = int(self.headers.get('Content-Length', 0))
                body   = json.loads(self.rfile.read(length))
            except Exception as e:
                return self._json(400, {'error': f'invalid JSON: {e}'})

            ip             = self.client_address[0]
            status, result = state.process(body, ip)
            self._json(status, result)

        def _json(self, status: int, body: dict):
            data = json.dumps(body, indent=2).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(data))
            self.end_headers()
            self.wfile.write(data)

    return Handler


# ─── Startup ──────────────────────────────────────────────────────────────────

def main():
    port = int(os.environ.get('PORT', 8080))

    # Load private key from env (Railway secret)
    key_env = os.environ.get('WITNESS_PRIVATE_KEY', '').strip().replace('\\n', '\n')
    if not key_env:
        log.error("WITNESS_PRIVATE_KEY env var not set")
        sys.exit(1)
    private_key_pem = key_env.encode()

    # Load pinned DarkMatter pubkey from env (CRITICAL security property)
    dm_pubkey_env = os.environ.get('DARKMATTER_PUBKEY', '').strip().replace('\\n', '\n')
    if not dm_pubkey_env:
        log.warning("DARKMATTER_PUBKEY not set — pubkey pinning disabled (NOT for production)")
        # Fall back to accepting any pubkey if not configured (dev mode only)
        dm_pubkey_env = None

    witness_log = Path(os.environ.get('WITNESS_LOG', '/app/witness_log.jsonl'))

    try:
        if dm_pubkey_env:
            state = WitnessState(private_key_pem, dm_pubkey_env, witness_log)
        else:
            # Dev mode: no pinning — log a big warning
            class DevState(WitnessState):
                def __init__(self, pk, log_path):
                    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                    dummy_key = Ed25519PrivateKey.generate()
                    dummy_pem = dummy_key.public_key().public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                    super().__init__(pk, dummy_pem, log_path)
                    self.pinned_dm_pubkey_pem = None
                    self.pinned_dm_pubkey     = None

                def process(self, body, ip):
                    if self.pinned_dm_pubkey is None:
                        body['darkmatter_pubkey'] = body.get('darkmatter_pubkey', '')
                        checkpoint = body.get('checkpoint', {})
                        if not body.get('darkmatter_pubkey'):
                            return 400, {'error': 'darkmatter_pubkey required'}
                        # Skip pin check in dev mode
                        self.pinned_dm_pubkey     = load_pem_public_key(body['darkmatter_pubkey'].encode())
                        self.pinned_dm_pubkey_pem = body['darkmatter_pubkey'].strip()
                    return super().process(body, ip)
            state = DevState(private_key_pem, witness_log)
            log.warning("⚠ DARKMATTER_PUBKEY not pinned — dev mode only")
    except Exception as e:
        log.error(f"Startup failed: {e}")
        sys.exit(1)

    log.info(f"Witness ID:       {state.witness_id}")
    log.info(f"Pubkey pinned:    {'YES' if dm_pubkey_env else 'NO (dev mode)'}")
    log.info(f"Last position:    {state.last_signed_position}")
    log.info(f"Witness log:      {witness_log}")
    log.info(f"Port:             {port}")
    log.info(f"Ready — POST /witness to submit checkpoints")

    server = HTTPServer(('0.0.0.0', port), make_handler(state))
    server.serve_forever()


if __name__ == '__main__':
    main()
