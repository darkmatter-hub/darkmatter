"""
DarkMatter Python SDK v1.3 — L3 Non-repudiation
============================
Phase 1: client-side hashing + envelope signatures
Phase 2: append-only log + signed checkpoints

Spec: https://darkmatterhub.ai/docs#integrity-model
Test vectors: /github-template/integrity_test_vectors.json

Install: pip install cryptography requests
"""

import json
import hashlib
import math
import os
import sys
from pathlib import Path
from typing import Optional

import requests

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

SCHEMA_VERSION = '2'


# ─────────────────────────────────────────────────────────────────────────────
# CANONICAL SERIALIZATION v1
#
# Must be byte-for-byte identical to integrity.js canonicalize().
# Validated by integrity_test_vectors.json.
#
# Critical fixes vs v1:
#   - null values in dicts are KEPT (not dropped — null != undefined)
#   - floats: non-finite rejected; toPrecision(17)-equivalent + strip trailing zeros
#   - test vectors must pass before any release
# ─────────────────────────────────────────────────────────────────────────────

def canonicalize(value) -> str:
    """
    Deterministic JSON serialization matching integrity.js canonicalize() exactly.
    See test vectors in integrity_test_vectors.json for cross-language validation.
    """
    if value is None:
        return 'null'

    if isinstance(value, bool):
        # bool must come before int (bool is subclass of int in Python)
        return 'true' if value else 'false'

    if isinstance(value, int):
        return str(value)

    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError(f'canonicalize: non-finite number rejected: {value}')
        # Match JS toPrecision(17): 17 significant digits, strip trailing zeros
        # but keep at least one decimal digit
        s = format(value, '.17g')
        # If no decimal point and no exponent, it was formatted as integer — add .0
        if '.' not in s and 'e' not in s:
            s += '.0'
        elif '.' in s and 'e' not in s:
            # Strip trailing zeros but keep at least one after decimal
            s = s.rstrip('0')
            if s.endswith('.'):
                s += '0'
        return s

    if isinstance(value, str):
        # Delegate to json.dumps for correct escape sequences
        return json.dumps(value, ensure_ascii=False)

    if isinstance(value, list):
        return '[' + ','.join(canonicalize(v) for v in value) + ']'

    if isinstance(value, dict):
        pairs = []
        for k in sorted(value.keys()):
            v = value[k]
            # Keep None (null) — drop nothing
            # (In Python there is no 'undefined' — only None which maps to JSON null)
            pairs.append(json.dumps(k, ensure_ascii=False) + ':' + canonicalize(v))
        return '{' + ','.join(pairs) + '}'

    raise TypeError(f'canonicalize: unsupported type {type(value).__name__}')


def hash_payload(payload: dict) -> str:
    """SHA-256( canonical(payload) ) → lowercase hex, no prefix."""
    c = canonicalize(payload)
    return hashlib.sha256(c.encode('utf-8')).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# COMMIT ENVELOPE
#
# The envelope is what gets hashed (integrity_hash) and signed by the agent.
# Signing the envelope — not just the payload — means:
#   - parent linkage is authenticated
#   - agent identity is authenticated
#   - timestamp is authenticated
#   - schema version is authenticated
# ─────────────────────────────────────────────────────────────────────────────

def build_envelope(
    payload_hash: str,
    parent_integrity_hash: Optional[str],
    agent_id: str,
    key_id: str,
    timestamp: str,
) -> dict:
    """
    Build the canonical commit envelope.
    Strip milliseconds from timestamp (seconds precision only).
    parent_integrity_hash=None → 'root' in envelope.
    """
    import re
    # Normalize: strip milliseconds, ensure Z suffix
    ts = re.sub(r'\.\d+Z?$', '', timestamp)
    if not ts.endswith('Z'):
        ts += 'Z'

    return {
        'schema_version':       SCHEMA_VERSION,
        'agent_id':             agent_id,
        'key_id':               key_id,
        'timestamp':            ts,
        'payload_hash':         payload_hash,
        'parent_integrity_hash': parent_integrity_hash or 'root',
    }


def hash_envelope(envelope: dict) -> str:
    """SHA-256( canonical(envelope) ) → lowercase hex."""
    return hashlib.sha256(canonicalize(envelope).encode('utf-8')).hexdigest()


def compute_integrity_hash(
    payload_hash: str,
    parent_integrity_hash: Optional[str],
    agent_id: str,
    key_id: str,
    timestamp: str,
) -> tuple[str, dict]:
    """Returns (integrity_hash, envelope)."""
    envelope = build_envelope(payload_hash, parent_integrity_hash, agent_id, key_id, timestamp)
    return hash_envelope(envelope), envelope


# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

_config: dict = {
    'api_key':          None,
    'agent_id':         None,
    'key_id':           'default',
    'host':             'https://darkmatterhub.ai',
    'private_key':      None,   # DM-provisioned signing key (Phase 1)
    'customer_key':     None,   # Customer-held signing key (Phase 2) — DM never sees this
    'customer_key_id':  None,   # Stable identifier for the customer key (rotation-safe)
    'customer_pubkey':  None,   # Public key PEM — sent on every commit so anyone can verify
    '_signing_config':  None,   # SigningConfig instance for L3
    'last_ctx_id':      None,
    'last_integrity':   None,
}


def configure(
    api_key:            Optional[str] = None,
    agent_id:           Optional[str] = None,
    key_id:             Optional[str] = None,
    host:               Optional[str] = None,
    private_key_path:   Optional[str] = None,
    customer_key_path:  Optional[str] = None,
    customer_key_id:    Optional[str] = None,
    signing:            Optional['SigningConfig'] = None,
):
    """
    Configure the DarkMatter SDK.

    Phase 1 (now):
      api_key, private_key_path — standard setup, DM-provisioned key optional.

    Phase 2 (customer keys — set now to be forward-compatible):
      customer_key_path   path to your Ed25519 private key PEM
      customer_key_id     stable label for this key (used in envelope + rotation)

      When set, every commit is signed with YOUR key. DarkMatter stores only
      the public key. DarkMatter cannot forge your signatures.
      No API change required — the envelope already carries key_id and
      agent_public_key fields. Setting this today makes your commits
      forward-compatible with Phase 2 verification without any code change later.

    Env vars: DARKMATTER_API_KEY, DARKMATTER_AGENT_ID,
              DARKMATTER_PRIVATE_KEY_PATH,
              DARKMATTER_CUSTOMER_KEY_PATH, DARKMATTER_CUSTOMER_KEY_ID
    """
    _config['api_key']  = api_key  or os.getenv('DARKMATTER_API_KEY')
    _config['agent_id'] = agent_id or os.getenv('DARKMATTER_AGENT_ID')
    if key_id: _config['key_id'] = key_id
    if host:   _config['host']   = host.rstrip('/')

    # Phase 1 — DM-provisioned key
    pk = private_key_path or os.getenv('DARKMATTER_PRIVATE_KEY_PATH')
    if pk and CRYPTO_AVAILABLE:
        pem = Path(pk).read_bytes()
        _config['private_key'] = serialization.load_pem_private_key(pem, password=None)

    # Phase 2 — customer-held key (no-op today, active when Phase 2 verifier ships)
    ck    = customer_key_path or os.getenv('DARKMATTER_CUSTOMER_KEY_PATH')
    ck_id = customer_key_id   or os.getenv('DARKMATTER_CUSTOMER_KEY_ID')
    if ck and CRYPTO_AVAILABLE:
        pem     = Path(ck).read_bytes()
        priv    = serialization.load_pem_private_key(pem, password=None)
        pub     = priv.public_key()
        pub_pem = pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')
        _config['customer_key']    = priv
        _config['customer_key_id'] = ck_id or 'customer-default'
        _config['customer_pubkey'] = pub_pem

    # L3 — SigningConfig object (preferred over customer_key_path)
    if signing is not None:
        _config['_signing_config'] = signing


def _cfg():
    if not _config['api_key']:
        _config['api_key']  = os.getenv('DARKMATTER_API_KEY')
    if not _config['agent_id']:
        _config['agent_id'] = os.getenv('DARKMATTER_AGENT_ID')
    if not _config['api_key']:
        raise RuntimeError('No API key. Call configure(api_key=...) or set DARKMATTER_API_KEY.')
    return _config


def _headers():
    return {
        'Authorization': f'Bearer {_cfg()["api_key"]}',
        'Content-Type':  'application/json',
        'User-Agent':    'darkmatter-python/1.2',
    }



# ─────────────────────────────────────────────────────────────────────────────
# L3 — SIGNING CONFIG & ENVELOPE V1
#
# Implements ENVELOPE_SPEC_V1 — must be byte-for-byte compatible with
# server-side attestation.js and pass all 3 test vectors.
#
# Env vars:
#   DARKMATTER_SIGNING_MODE        = customer  (or omit for L1/L2)
#   DARKMATTER_SIGNING_KEY_ID      = my-key-name
#   DARKMATTER_SIGNING_KEY_PATH    = /path/to/ed25519.pem
#   DARKMATTER_SIGNING_KEY_PEM     = (alternative: inline PEM string)
# ─────────────────────────────────────────────────────────────────────────────

import base64
from dataclasses import dataclass, field


def _canonical_json_l3(obj) -> str:
    """
    Canonical JSON per ENVELOPE_SPEC_V1:
    - keys sorted recursively ascending Unicode code point order
    - no whitespace
    - UTF-8, non-ASCII NOT escaped
    Equivalent to: json.dumps(obj, sort_keys=True, separators=(',',':'), ensure_ascii=False)
    """
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _sha256_hex_l3(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest()


def _hash_field_l3(obj) -> Optional[str]:
    if obj is None:
        return None
    return 'sha256:' + _sha256_hex_l3(_canonical_json_l3(obj))


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


@dataclass
class SigningConfig:
    """
    Customer-held signing key configuration for L3 non-repudiation.

    One-time setup — configure once, commit() works identically:

        client = dm.Client(
            api_key="dm_sk_...",
            signing=dm.SigningConfig.from_env()
        )

    Or via env vars (recommended for production):
        DARKMATTER_SIGNING_MODE=customer
        DARKMATTER_SIGNING_KEY_ID=my-key-name
        DARKMATTER_SIGNING_KEY_PATH=/path/to/key.pem

    Key must be an Ed25519 private key in PEM format.
    Generate with: darkmatter keys generate --name my-key
    Register with: darkmatter keys register --key-id my-key --public-key my-key.pub
    """
    mode: str = 'customer'                    # always 'customer' for L3
    key_id: str = ''                          # stable key identifier
    private_key_path: Optional[str] = None   # path to PEM file
    private_key_pem: Optional[str] = None    # inline PEM string (alternative)
    _private_key: object = field(default=None, repr=False, init=False)
    _public_key_b64: str = field(default='', repr=False, init=False)

    def __post_init__(self):
        self._load_key()

    def _load_key(self):
        if not CRYPTO_AVAILABLE:
            raise ImportError(
                'cryptography package required for L3 signing.\n'
                'Install: pip install cryptography'
            )
        pem_bytes = None
        if self.private_key_path:
            pem_bytes = Path(self.private_key_path).expanduser().read_bytes()
        elif self.private_key_pem:
            pem_bytes = self.private_key_pem.encode('utf-8')
        if pem_bytes is None:
            raise ValueError('SigningConfig requires private_key_path or private_key_pem')

        from cryptography.hazmat.primitives import serialization as _ser
        priv = _ser.load_pem_private_key(pem_bytes, password=None)
        if not isinstance(priv, Ed25519PrivateKey):
            raise ValueError('Key must be an Ed25519 private key. Use: darkmatter keys generate')
        self._private_key = priv
        pub_raw = priv.public_key().public_bytes(
            _ser.Encoding.Raw, _ser.PublicFormat.Raw
        )
        self._public_key_b64 = _b64url(pub_raw)

    @classmethod
    def from_env(cls) -> Optional['SigningConfig']:
        """
        Load SigningConfig from environment variables.
        Returns None if DARKMATTER_SIGNING_MODE is not 'customer'.
        """
        mode = os.getenv('DARKMATTER_SIGNING_MODE', '').strip().lower()
        if mode != 'customer':
            return None
        key_id   = os.getenv('DARKMATTER_SIGNING_KEY_ID', 'default')
        key_path = os.getenv('DARKMATTER_SIGNING_KEY_PATH')
        key_pem  = os.getenv('DARKMATTER_SIGNING_KEY_PEM')
        if not key_path and not key_pem:
            raise ValueError(
                'DARKMATTER_SIGNING_MODE=customer requires '
                'DARKMATTER_SIGNING_KEY_PATH or DARKMATTER_SIGNING_KEY_PEM'
            )
        return cls(mode='customer', key_id=key_id,
                   private_key_path=key_path, private_key_pem=key_pem)

    def build_attestation(
        self,
        payload: dict,
        agent_id: str,
        parent_id: Optional[str] = None,
        metadata: Optional[dict] = None,
        client_timestamp: Optional[str] = None,
        completeness_claim: Optional[bool] = None,
    ) -> dict:
        """
        Build a client_attestation object per ENVELOPE_SPEC_V1.
        Signs the canonical envelope with the customer private key.
        This is the core L3 operation — DarkMatter never sees the private key.

        completeness_claim: when True, the agent asserts nothing was omitted.
        This claim is included in the signed envelope — it cannot be altered.
        """
        from datetime import datetime, timezone
        ts = client_timestamp or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.') + \
             f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"

        envelope = {
            'version':          'dm-envelope-v1',
            'algorithm':        'Ed25519',
            'agent_id':         agent_id,
            'client_timestamp': ts,
            'key_id':           self.key_id,
            'metadata_hash':    _hash_field_l3(metadata),
            'parent_id':        parent_id,
            'payload_hash':     _hash_field_l3(payload),
        }

        # completeness_claim is part of the signed surface when set.
        # canonical_json sorts keys — it will be between 'algorithm' and 'agent_id'.
        if completeness_claim is not None:
            envelope['completeness_claim'] = completeness_claim

        canonical   = _canonical_json_l3(envelope)
        env_hash    = 'sha256:' + _sha256_hex_l3(canonical)
        sig_bytes   = self._private_key.sign(canonical.encode('utf-8'))

        attestation = {
            'version':          envelope['version'],
            'algorithm':        envelope['algorithm'],
            'key_id':           self.key_id,
            'public_key':       self._public_key_b64,
            'client_timestamp': ts,
            'agent_id':         agent_id,
            'payload_hash':     envelope['payload_hash'],
            'metadata_hash':    envelope['metadata_hash'],
            'parent_id':        parent_id,
            'envelope_hash':    env_hash,
            'signature':        _b64url(sig_bytes),
        }
        if completeness_claim is not None:
            attestation['completeness_claim'] = completeness_claim

        return attestation


# ── Key registration helpers ───────────────────────────────────────────────────

def register_signing_key(
    key_id: str,
    public_key_path: Optional[str] = None,
    public_key_b64: Optional[str] = None,
    description: Optional[str] = None,
) -> dict:
    """
    Register a public key with DarkMatter for L3 commits.
    After registering, commits can use key_id only (no inline public key needed).

    Usage:
        dm.register_signing_key('my-key', public_key_path='my-key.pub')

    Or from a SigningConfig:
        cfg = dm.SigningConfig(key_id='my-key', private_key_path='my-key.pem')
        dm.register_signing_key('my-key', public_key_b64=cfg._public_key_b64)
    """
    if public_key_path:
        raw = Path(public_key_path).expanduser().read_bytes()
        # Accept raw 32-byte binary or PEM
        if raw[:4] == b'-----':
            from cryptography.hazmat.primitives import serialization as _ser
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pub = _ser.load_pem_public_key(raw)
            pub_b64 = _b64url(pub.public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw))
        else:
            pub_b64 = _b64url(raw)
    elif public_key_b64:
        pub_b64 = public_key_b64
    else:
        raise ValueError('Provide public_key_path or public_key_b64')

    body = {'key_id': key_id, 'public_key': pub_b64, 'algorithm': 'Ed25519'}
    if description:
        body['description'] = description

    r = requests.post(
        f'{_cfg()["host"]}/api/signing-keys',
        json=body, headers=_headers(), timeout=10
    )
    r.raise_for_status()
    return r.json()


def list_signing_keys() -> list:
    """List all registered signing keys for this account."""
    r = requests.get(f'{_cfg()["host"]}/api/signing-keys', headers=_headers(), timeout=10)
    r.raise_for_status()
    return r.json().get('keys', [])


def revoke_signing_key(key_id: str) -> dict:
    """Revoke a registered signing key. Existing L3 records are unaffected."""
    r = requests.delete(
        f'{_cfg()["host"]}/api/signing-keys/{key_id}',
        headers=_headers(), timeout=10
    )
    r.raise_for_status()
    return r.json()


# ── Test vector runner — SDK release gate ──────────────────────────────────────

def run_envelope_test_vectors(vectors_path: Optional[str] = None) -> dict:
    """
    Run the 3 canonical envelope test vectors from ENVELOPE_SPEC_V1.
    All must pass before any SDK release.

    Returns dict with 'passed' (bool) and 'results' (list).
    """
    import importlib.resources, json as _json

    if vectors_path:
        vectors = _json.loads(Path(vectors_path).read_text())
    else:
        # Try to find vectors relative to this file or cwd
        candidates = [
            Path(__file__).parent.parent / 'test-vectors-envelope-v1.json',
            Path(__file__).parent       / 'test-vectors-envelope-v1.json',
            Path.cwd()                  / 'test-vectors-envelope-v1.json',
        ]
        vectors = None
        for c in candidates:
            if c.exists():
                vectors = _json.loads(c.read_text())
                break
        if vectors is None:
            raise FileNotFoundError(
                'test-vectors-envelope-v1.json not found. '
                'Pass vectors_path= explicitly or place the file in the repo root.'
            )

    results = []
    all_passed = True

    for v in vectors:
        checks = {}
        try:
            # Recompute payload hash
            payload_canon = _canonical_json_l3(v['payload'])
            payload_hash  = 'sha256:' + _sha256_hex_l3(payload_canon)
            checks['payload_canonical'] = payload_canon == v['expected']['payload_canonical']
            checks['payload_hash']      = payload_hash  == v['expected']['payload_hash']

            # Recompute metadata hash
            meta      = v.get('metadata')
            meta_hash = _hash_field_l3(meta)
            checks['metadata_hash'] = meta_hash == v['expected'].get('metadata_hash')

            # Build envelope
            envelope = {
                'version':          'dm-envelope-v1',
                'algorithm':        'Ed25519',
                'agent_id':         v['agent_id'],
                'client_timestamp': v['client_timestamp'],
                'key_id':           v['key_id'],
                'metadata_hash':    meta_hash,
                'parent_id':        v.get('parent_id'),
                'payload_hash':     payload_hash,
            }
            env_canon = _canonical_json_l3(envelope)
            env_hash  = 'sha256:' + _sha256_hex_l3(env_canon)
            checks['envelope_canonical'] = env_canon == v['expected']['envelope_canonical']
            checks['envelope_hash']      = env_hash  == v['expected']['envelope_hash']

            # Verify pre-computed signature from test vector
            if CRYPTO_AVAILABLE:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                from cryptography.hazmat.primitives import serialization as _ser
                from cryptography.exceptions import InvalidSignature
                pub_b64   = v['test_public_key']
                pub_raw   = base64.urlsafe_b64decode(pub_b64 + '==')
                pub_key   = Ed25519PublicKey.from_public_bytes(pub_raw)
                sig_bytes = base64.urlsafe_b64decode(v['expected']['signature'] + '==')
                try:
                    pub_key.verify(sig_bytes, env_canon.encode('utf-8'))
                    checks['signature_valid'] = True
                except InvalidSignature:
                    checks['signature_valid'] = False

            passed = all(checks.values())
            if not passed:
                all_passed = False
            results.append({'name': v['name'], 'passed': passed, 'checks': checks})
        except Exception as e:
            all_passed = False
            results.append({'name': v.get('name', '?'), 'passed': False, 'error': str(e)})

    return {'passed': all_passed, 'results': results}


# ─────────────────────────────────────────────────────────────────────────────
# AGENT SIGNING (L1/L2 — DM-provisioned key)
# For L3 customer keys, see SigningConfig above.
# ─────────────────────────────────────────────────────────────────────────────

def _sign_envelope(envelope: dict) -> tuple[Optional[str], Optional[str]]:
    """
    Sign canonical(envelope) with the active key.

    Priority: customer_key (Phase 2) > private_key (Phase 1) > None

    Returns (signature_hex, agent_public_key_pem).
    agent_public_key_pem is non-None only for customer keys — it is sent
    to the server on every commit so verifiers can check the signature
    without contacting DarkMatter.
    """
    if not CRYPTO_AVAILABLE:
        return None, None

    # Phase 2 — customer key takes priority when configured
    if _config.get('customer_key'):
        key = _config['customer_key']
        msg = canonicalize(envelope).encode('utf-8')
        sig = key.sign(msg)
        return sig.hex(), _config.get('customer_pubkey')

    # Phase 1 — DM-provisioned key
    if _config.get('private_key'):
        key = _config['private_key']
        msg = canonicalize(envelope).encode('utf-8')
        sig = key.sign(msg)
        return sig.hex(), None   # server already holds the public key

    return None, None


# ─────────────────────────────────────────────────────────────────────────────
# CORE PRIMITIVES
# ─────────────────────────────────────────────────────────────────────────────

def commit(
    to_agent_id:        str,
    payload:            dict,
    parent_id:          Optional[str]  = None,
    trace_id:           Optional[str]  = None,
    branch_key:         Optional[str]  = None,
    event_type:         Optional[str]  = None,
    agent:              Optional[dict] = None,
    auto_thread:        bool           = True,
    timestamp:          Optional[str]  = None,
    metadata:           Optional[dict] = None,
    signing:            Optional['SigningConfig'] = None,
    completeness_claim: Optional[bool] = None,
) -> dict:
    """
    Commit agent context to DarkMatter.

    completeness_claim: set True to assert this record is complete — nothing omitted.
    This claim is signed and cannot be altered after signing.
    Default None = no claim made (neutral).

    Phase 1 guarantees (client-side):
      - payload_hash computed locally via canonical serialization
      - integrity_hash computed over full envelope (payload + parent + agent + key + timestamp)
      - envelope signed with agent Ed25519 private key (if configured)
      - server validates all hashes — mismatches flagged in receipt._warnings
    """
    from datetime import datetime, timezone
    cfg = _cfg()
    # Per-call signing override takes precedence over global config
    if signing is not None:
        _config['_signing_config'] = signing

    resolved_parent = parent_id or (auto_thread and _config.get('last_ctx_id') or None)
    ts = timestamp or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    payload_hash  = hash_payload(payload)
    parent_ih     = _config.get('last_integrity') if (auto_thread and not parent_id) else None
    active_key_id = _config.get('customer_key_id') or cfg.get('key_id') or 'default'
    integrity_hash, envelope = compute_integrity_hash(
        payload_hash, parent_ih,
        cfg['agent_id'] or 'unknown', active_key_id, ts,
    )
    agent_signature, agent_public_key = _sign_envelope(envelope)

    # ── L3 client_attestation (ENVELOPE_SPEC_V1) ─────────────────────────────
    sc: Optional['SigningConfig'] = _config.get('_signing_config')
    client_attestation = None
    if sc is not None and sc.mode == 'customer':
        client_attestation = sc.build_attestation(
            payload=payload,
            agent_id=cfg['agent_id'] or 'unknown',
            parent_id=resolved_parent,
            metadata=metadata,
            client_timestamp=ts,
            completeness_claim=completeness_claim,
        )

    body = {
        'payload':          payload,
        'payload_hash':     payload_hash,
        'integrity_hash':   integrity_hash,
        'envelope':         envelope,
        **(({'toAgentId':          to_agent_id})        if to_agent_id        else {}),
        **(({'agent_signature':    agent_signature})    if agent_signature    else {}),
        **(({'agent_public_key':   agent_public_key})   if agent_public_key   else {}),
        **(({'parentId':           resolved_parent})    if resolved_parent    else {}),
        **(({'traceId':            trace_id})           if trace_id           else {}),
        **(({'branchKey':          branch_key})         if branch_key         else {}),
        **(({'eventType':          event_type})         if event_type         else {}),
        **(({'agent':              agent})              if agent              else {}),
        **(({'metadata':           metadata})           if metadata           else {}),
        **(({'client_attestation': client_attestation}) if client_attestation else {}),
        **(({'completeness_claim': completeness_claim}) if completeness_claim is not None else {}),
    }

    r = requests.post(f'{cfg["host"]}/api/commit', json=body, headers=_headers(), timeout=10)
    r.raise_for_status()
    data = r.json()
    if data.get('error'):
        raise RuntimeError(f'Commit failed: {data["error"]}')

    _config['last_ctx_id']   = data.get('id')
    _config['last_integrity'] = integrity_hash
    return data


def replay(ctx_id: str, mode: str = 'full') -> dict:
    r = requests.get(f'{_cfg()["host"]}/api/replay/{ctx_id}', params={'mode': mode}, headers=_headers(), timeout=15)
    r.raise_for_status(); return r.json()


def fork(ctx_id: str, branch_key: Optional[str] = None) -> dict:
    body = {**(({'branchKey': branch_key}) if branch_key else {})}
    r = requests.post(f'{_cfg()["host"]}/api/fork/{ctx_id}', json=body, headers=_headers(), timeout=10)
    r.raise_for_status(); return r.json()


def verify(ctx_id: str) -> dict:
    r = requests.get(f'{_cfg()["host"]}/api/verify/{ctx_id}', headers=_headers(), timeout=15)
    r.raise_for_status(); return r.json()


def diff(ctx_id_a: str, ctx_id_b: str) -> dict:
    r = requests.get(f'{_cfg()["host"]}/api/diff', params={'a': ctx_id_a, 'b': ctx_id_b}, headers=_headers(), timeout=15)
    r.raise_for_status(); return r.json()


def bundle(ctx_id: str) -> dict:
    r = requests.get(f'{_cfg()["host"]}/api/export/{ctx_id}', headers=_headers(), timeout=20)
    r.raise_for_status(); return r.json()


def me() -> dict:
    r = requests.get(f'{_cfg()["host"]}/api/me', headers=_headers(), timeout=10)
    r.raise_for_status(); return r.json()


def checkpoint() -> dict:
    r = requests.get(f'{_cfg()["host"]}/api/log/checkpoint', headers=_headers(), timeout=10)
    r.raise_for_status(); return r.json()


# ─────────────────────────────────────────────────────────────────────────────
# LOCAL VERIFICATION (no network)
# Strict by default — missing hashes = broken.
# ─────────────────────────────────────────────────────────────────────────────

def verify_local(chain_export, strict: bool = True) -> dict:
    """
    Verify a chain export locally with zero network calls.
    Same algorithm as verify_darkmatter_chain.py.

    Returns three separate result sections:
      structure:   payload hashes and chain links
      signatures:  agent signature verification (if public keys present)
      checkpoints: log checkpoint verification (if checkpoint data present)
    """
    commits = chain_export if isinstance(chain_export, list) else \
              (chain_export.get('commits') or chain_export.get('replay') or [])

    structure_broken  = None
    sig_results       = []
    prev_integrity    = None
    steps             = []

    for commit in commits:
        cid       = commit.get('id', '?')
        payload   = commit.get('payload') or commit.get('context') or {}
        agent_id  = commit.get('agent_id') or (commit.get('agent_info') or {}).get('id') or ''
        key_id    = commit.get('key_id')   or (commit.get('agent_info') or {}).get('key_id') or 'default'
        timestamp = commit.get('timestamp') or ''

        stored_ph = (commit.get('payload_hash')   or '').removeprefix('sha256:') or None
        stored_ih = (commit.get('integrity_hash') or '').removeprefix('sha256:') or None

        # Strict: missing hashes = broken
        if strict and (not stored_ph or not stored_ih):
            steps.append({'id': cid, 'payload_ok': False, 'integrity_ok': False, 'link_ok': False, 'reason': 'missing_hashes'})
            if not structure_broken: structure_broken = cid
            continue

        server_ph             = hash_payload(payload)
        ih, envelope          = compute_integrity_hash(server_ph, prev_integrity, agent_id, key_id, timestamp)
        payload_ok            = not stored_ph or server_ph == stored_ph
        integrity_ok          = not stored_ih or ih == stored_ih
        link_ok               = payload_ok and integrity_ok

        steps.append({'id': cid, 'payload_ok': payload_ok, 'integrity_ok': integrity_ok, 'link_ok': link_ok})
        if not link_ok and not structure_broken: structure_broken = cid
        prev_integrity = ih

    structure_ok = structure_broken is None
    return {
        'structure': {
            'ok':        structure_ok,
            'broken_at': structure_broken,
            'length':    len(commits),
            'mode':      'strict' if strict else 'legacy',
            'steps':     steps,
        },
        'signatures':   {'ok': None, 'note': 'use verify_darkmatter_chain.py for full signature verification'},
        'checkpoints':  {'ok': None, 'note': 'pass --checkpoint to verify_darkmatter_chain.py'},
        'verified':     structure_ok,
    }


# ─────────────────────────────────────────────────────────────────────────────
# KEY MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

def generate_keypair(agent_name: str, output_dir: str = '.') -> dict:
    if not CRYPTO_AVAILABLE:
        raise RuntimeError('pip install cryptography')
    private_key = Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()
    private_pem = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public_pem  = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    agent_id    = 'dm_' + hashlib.sha256(public_pem).hexdigest()[:16]
    safe        = agent_name.replace(' ', '-').lower()
    out         = Path(output_dir)
    priv_path   = out / f'{safe}.private.pem'
    pub_path    = out / f'{safe}.public.pem'
    priv_path.write_bytes(private_pem); priv_path.chmod(0o600)
    pub_path.write_bytes(public_pem)
    print(f'✓ Keypair: {agent_id}\n  Private: {priv_path}\n  Public:  {pub_path}')
    return {'agent_id': agent_id, 'private_key_path': str(priv_path), 'public_key_path': str(pub_path)}


def generate_customer_keypair(name: str, output_dir: str = '.') -> dict:
    """
    Phase 2: Generate a customer-held Ed25519 keypair.

    The private key never leaves your infrastructure. DarkMatter stores only
    the public key (sent on each commit). Because DarkMatter never holds the
    private key, it cannot forge your signatures — even if DarkMatter is
    compromised.

    Usage (set up once, works with current API — no Phase 2 required to start):

        keys = dm.generate_customer_keypair('acme-corp')
        dm.configure(
            customer_key_path=keys['private_key_path'],
            customer_key_id=keys['key_id'],
        )
        # All subsequent dm.commit() calls are signed with your key.
        # The public key is sent to DarkMatter on every commit.
        # When Phase 2 verification ships, your commits are already compatible.

    Key rotation: generate a new keypair, update customer_key_path and
    customer_key_id. Old commits retain their original key_id in the envelope.
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError('pip install cryptography')

    private_key = Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_id    = 'ck_' + hashlib.sha256(public_pem).hexdigest()[:16]
    safe      = name.replace(' ', '-').lower()
    out       = Path(output_dir)
    priv_path = out / f'{safe}.customer.private.pem'
    pub_path  = out / f'{safe}.customer.public.pem'
    priv_path.write_bytes(private_pem)
    priv_path.chmod(0o600)
    pub_path.write_bytes(public_pem)
    print(
        f'✓ Customer keypair generated\n'
        f'  Key ID:  {key_id}\n'
        f'  Private: {priv_path}  ← keep this secret, never share\n'
        f'  Public:  {pub_path}   ← DarkMatter stores this per commit\n'
        f'\n'
        f'  dm.configure(customer_key_path="{priv_path}", customer_key_id="{key_id}")'
    )
    return {
        'key_id':           key_id,
        'private_key_path': str(priv_path),
        'public_key_path':  str(pub_path),
        'public_key_pem':   public_pem.decode('utf-8'),
    }
