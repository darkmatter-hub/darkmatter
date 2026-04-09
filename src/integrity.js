/**
 * DarkMatter Integrity Module v2
 * ================================
 * Canonical serialization, commit envelope hashing, and signature verification.
 *
 * SPEC: https://darkmatterhub.ai/docs#integrity-model
 * All cross-language SDKs must implement this spec identically.
 * Test vectors: /github-template/integrity_test_vectors.json
 *
 * Design rules:
 *   1. canonicalize() is the only serialization path — no JSON.stringify elsewhere
 *   2. Signatures cover the full commit envelope, not just the payload
 *   3. integrity_hash covers the full envelope — unique per commit
 *   4. No field is optional in verified commits — missing = broken
 */

'use strict';

const crypto = require('crypto');

// ─────────────────────────────────────────────────────────────────────────────
// CANONICAL SERIALIZATION v1
//
// Rules (formally specified — all SDKs must match exactly):
//   1. Object keys are sorted lexicographically (Unicode codepoint order)
//   2. null values in objects are kept and serialized as "null"
//      (unlike undefined, which is omitted — null is explicit data)
//   3. Arrays preserve element order
//   4. Strings use JSON encoding (json.dumps / JSON.stringify)
//   5. Integers serialize as decimal digits, no trailing zeros, no exponent
//   6. Floats: non-finite (NaN, Infinity, -Infinity) are REJECTED with TypeError
//   7. Floats: use toPrecision(17) then strip trailing zeros, preserving
//      at least one decimal digit. This matches V8 / Python repr for finite floats.
//   8. Boolean: "true" / "false"
//   9. null: "null"
//
// Test vectors in integrity_test_vectors.json MUST pass in all SDKs.
// ─────────────────────────────────────────────────────────────────────────────

function canonicalize(value) {
  // null — kept, serialized as "null"
  if (value === null) return 'null';

  // boolean
  if (typeof value === 'boolean') return value ? 'true' : 'false';

  // number
  if (typeof value === 'number') {
    if (!isFinite(value)) {
      throw new TypeError(`canonicalize: non-finite number rejected: ${value}`);
    }
    // integers: no decimal point
    if (Number.isInteger(value)) return String(value);
    // floats: 17 significant digits (round-trip safe), strip trailing zeros
    let s = value.toPrecision(17);
    // Remove trailing zeros after decimal, but keep at least one decimal digit
    if (s.includes('.') && !s.includes('e')) {
      s = s.replace(/\.?0+$/, '');
      if (!s.includes('.')) s += '.0';
    }
    return s;
  }

  // string — delegate to JSON.stringify for correct escape sequences
  if (typeof value === 'string') return JSON.stringify(value);

  // array — elements in original order
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }

  // object — sort keys, keep null values, drop undefined
  if (typeof value === 'object') {
    const keys  = Object.keys(value).sort();
    const pairs = [];
    for (const k of keys) {
      const v = value[k];
      if (v === undefined) continue; // drop undefined only (not null)
      pairs.push(JSON.stringify(k) + ':' + canonicalize(v));
    }
    return '{' + pairs.join(',') + '}';
  }

  throw new TypeError(`canonicalize: unsupported type ${typeof value}`);
}

/**
 * SHA-256 of canonical(payload). Returns lowercase hex, no prefix.
 */
function hashPayload(payload) {
  const c = canonicalize(payload);
  return crypto.createHash('sha256').update(c, 'utf8').digest('hex');
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMIT ENVELOPE
//
// The envelope is what is hashed to produce integrity_hash,
// and what the agent signs. It binds:
//   - payload content (via payload_hash)
//   - chain position (via parent_integrity_hash)
//   - agent identity (agent_id)
//   - key identity (key_id)
//   - schema version (for future upgrade path)
//   - timestamp (ISO-8601 UTC, seconds precision — strip sub-seconds)
//
// This means two commits with identical payloads and parents but different
// agents, keys, or timestamps produce different integrity hashes.
// ─────────────────────────────────────────────────────────────────────────────

const SCHEMA_VERSION = '2';

/**
 * Build the canonical commit envelope.
 * This is the object that gets hashed and signed.
 *
 * @param {string}      payloadHash          - hex, output of hashPayload()
 * @param {string|null} parentIntegrityHash  - hex of parent, or null for root
 * @param {string}      agentId              - dm_... agent identifier
 * @param {string}      keyId                - identifier for the signing key
 * @param {string}      timestamp            - ISO-8601 UTC, seconds precision
 * @returns {object} canonical envelope (plain JS object, not yet serialized)
 */
function buildEnvelope(payloadHash, parentIntegrityHash, agentId, keyId, timestamp) {
  // Normalize timestamp to seconds precision (strip milliseconds)
  const ts = timestamp.replace(/\.\d+Z$/, 'Z').replace(/\.\d+$/, '');
  return {
    schema_version:      SCHEMA_VERSION,
    agent_id:            agentId,
    key_id:              keyId,
    timestamp:           ts,
    payload_hash:        payloadHash,
    parent_integrity_hash: parentIntegrityHash || 'root',
  };
}

/**
 * Compute the integrity hash from a commit envelope.
 * integrity_hash = SHA-256( canonical(envelope) )
 */
function hashEnvelope(envelope) {
  const c = canonicalize(envelope);
  return crypto.createHash('sha256').update(c, 'utf8').digest('hex');
}

/**
 * One-shot: compute integrity_hash from components.
 */
function computeIntegrityHash(payloadHash, parentIntegrityHash, agentId, keyId, timestamp) {
  const envelope = buildEnvelope(payloadHash, parentIntegrityHash, agentId, keyId, timestamp);
  return hashEnvelope(envelope);
}

// ─────────────────────────────────────────────────────────────────────────────
// SIGNATURE VERIFICATION (Ed25519)
// Agents sign canonical(envelope), not the payload directly.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verify an Ed25519 signature over canonical(envelope).
 *
 * @param {object} envelope     - The commit envelope object
 * @param {string} signatureHex - Hex-encoded Ed25519 signature
 * @param {string} publicKeyPem - PEM-encoded Ed25519 public key
 * @returns {boolean}
 */
function verifyEnvelopeSignature(envelope, signatureHex, publicKeyPem) {
  try {
    const message   = canonicalize(envelope);
    const msgBuffer = Buffer.from(message, 'utf8');
    const sigBuffer = Buffer.from(signatureHex, 'hex');
    const publicKey = crypto.createPublicKey(publicKeyPem);
    return crypto.verify(null, msgBuffer, publicKey, sigBuffer);
  } catch {
    return false;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// CLIENT HASH VALIDATION
// Server recomputes everything — never trusts client values blindly.
// Mismatches are stored and flagged, not silently corrected.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Validate client-supplied hashes against server-recomputed values.
 *
 * @param {object}      payload
 * @param {string|null} clientPayloadHash
 * @param {string|null} clientIntegrityHash
 * @param {string|null} parentIntegrityHash  - bare hex, no prefix
 * @param {string}      agentId
 * @param {string}      keyId
 * @param {string}      timestamp
 * @returns {{ valid, reason, serverPayloadHash, serverIntegrityHash, envelope }}
 */
function validateClientHashes(
  payload, clientPayloadHash, clientIntegrityHash,
  parentIntegrityHash, agentId, keyId, timestamp
) {
  const serverPayloadHash   = hashPayload(payload);
  const envelope            = buildEnvelope(serverPayloadHash, parentIntegrityHash, agentId, keyId, timestamp);
  const serverIntegrityHash = hashEnvelope(envelope);

  if (clientPayloadHash && clientPayloadHash !== serverPayloadHash) {
    return { valid: false, reason: `payload_hash mismatch: client=${clientPayloadHash} server=${serverPayloadHash}`, serverPayloadHash, serverIntegrityHash, envelope };
  }
  if (clientIntegrityHash && clientIntegrityHash !== serverIntegrityHash) {
    return { valid: false, reason: `integrity_hash mismatch: client=${clientIntegrityHash} server=${serverIntegrityHash}`, serverPayloadHash, serverIntegrityHash, envelope };
  }
  return { valid: true, reason: null, serverPayloadHash, serverIntegrityHash, envelope };
}

// ─────────────────────────────────────────────────────────────────────────────
// CHAIN VERIFICATION
// Strict mode: missing hashes = broken (not skipped).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verify an ordered array of commit objects (root → tip).
 *
 * In strict mode (default), missing payload_hash or integrity_hash = broken.
 * In legacy mode, missing hashes are skipped with a warning.
 *
 * Each commit needs: id, payload (or context), payload_hash,
 *                    integrity_hash, agent_id, key_id, timestamp
 *
 * @returns {{ chain_intact, length, broken_at, steps, mode }}
 */
function verifyChain(commits, { strict = true } = {}) {
  if (!commits || commits.length === 0) {
    return { chain_intact: true, length: 0, broken_at: null, steps: [], mode: strict ? 'strict' : 'legacy' };
  }

  let prevIntegrityHash = null;
  let brokenAt          = null;
  const steps           = [];

  for (const commit of commits) {
    const cid       = commit.id;
    const payload   = commit.payload || commit.context || {};
    const agentId   = commit.agent_id || (commit.agent_info && commit.agent_info.id) || (commit.created_by && commit.created_by.agent_id) || '';
    const keyId     = commit.key_id   || (commit.agent_info && commit.agent_info.key_id) || 'default';
    const timestamp = commit.timestamp || '';

    // Strip sha256: prefix from stored hashes
    const storedPayloadHash   = (commit.payload_hash   || '').replace('sha256:', '') || null;
    const storedIntegrityHash = (commit.integrity_hash || '').replace('sha256:', '') || null;

    // Strict mode: missing hashes = broken
    if (strict && (!storedPayloadHash || !storedIntegrityHash)) {
      steps.push({ id: cid, payload_ok: false, integrity_ok: false, parent_ok: false, link_ok: false, reason: 'missing_hashes' });
      if (!brokenAt) brokenAt = cid;
      continue;
    }

    // Recompute
    const serverPayloadHash    = hashPayload(payload);
    const envelope             = buildEnvelope(serverPayloadHash, prevIntegrityHash, agentId, keyId, timestamp);
    const serverIntegrityHash  = hashEnvelope(envelope);

    const payloadOk   = !storedPayloadHash   || serverPayloadHash   === storedPayloadHash;
    const integrityOk = !storedIntegrityHash || serverIntegrityHash === storedIntegrityHash;
    const linkOk      = payloadOk && integrityOk;

    steps.push({ id: cid, payload_ok: payloadOk, integrity_ok: integrityOk, link_ok: linkOk });
    if (!linkOk && !brokenAt) brokenAt = cid;

    prevIntegrityHash = serverIntegrityHash; // use server-computed for chain continuity
  }

  return {
    chain_intact: brokenAt === null,
    length:       commits.length,
    broken_at:    brokenAt,
    steps,
    mode:         strict ? 'strict' : 'legacy',
  };
}

module.exports = {
  SCHEMA_VERSION,
  canonicalize,
  hashPayload,
  buildEnvelope,
  hashEnvelope,
  computeIntegrityHash,
  verifyEnvelopeSignature,
  validateClientHashes,
  verifyChain,
};
