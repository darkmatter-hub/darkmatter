'use strict';
/**
 * DarkMatter attestation.js
 * Implements ENVELOPE_SPEC_V1 — canonical envelope verification.
 *
 * This file is the server-side reference implementation.
 * All SDK implementations must produce output that passes the test vectors
 * in test-vectors-envelope-v1.json before they can be released.
 */

const crypto = require('crypto');

// ── Canonicalization ──────────────────────────────────────────────────────────
// Rule: recursively sorted keys, no whitespace, UTF-8, no escaped Unicode.
// Equivalent to Python: json.dumps(obj, sort_keys=True, separators=(',',':'), ensure_ascii=False)

function canonicalJson(obj) {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'boolean') return obj ? 'true' : 'false';
  if (typeof obj === 'number') return String(obj);
  if (typeof obj === 'string') {
    // JSON-encode the string but allow non-ASCII to pass through unescaped
    return JSON.stringify(obj)
      .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => {
        const cp = parseInt(hex, 16);
        // Only keep escape for chars that must be escaped in JSON
        if (cp < 0x20 || cp === 0x22 || cp === 0x5c) return _;
        return String.fromCodePoint(cp);
      });
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJson).join(',') + ']';
  }
  if (typeof obj === 'object') {
    const sortedKeys = Object.keys(obj).sort();
    const pairs = sortedKeys.map(k => canonicalJson(k) + ':' + canonicalJson(obj[k]));
    return '{' + pairs.join(',') + '}';
  }
  return String(obj);
}

function sha256hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

function hashField(obj) {
  if (obj === null || obj === undefined) return null;
  return 'sha256:' + sha256hex(canonicalJson(obj));
}

// ── Build envelope from commit fields ─────────────────────────────────────────
function buildEnvelope({ agentId, keyId, clientTimestamp, payload, metadata, parentId }) {
  return {
    version:          'dm-envelope-v1',
    algorithm:        'Ed25519',
    agent_id:         agentId,
    client_timestamp: clientTimestamp,
    key_id:           keyId,
    metadata_hash:    hashField(metadata),
    parent_id:        parentId || null,
    payload_hash:     hashField(payload),
  };
}

// ── Verify client_attestation ──────────────────────────────────────────────────
// Returns { valid: true } or { valid: false, reason: string, message: string }
function verifyAttestation({ attestation, payload, metadata, agentId, parentId, completenessClaim }) {
  try {
    if (!attestation) return { valid: false, reason: 'missing_attestation', message: 'No client_attestation provided' };
    if (attestation.algorithm && attestation.algorithm !== 'Ed25519') {
      return { valid: false, reason: 'unsupported_algorithm', message: `Algorithm '${attestation.algorithm}' is not supported. Use Ed25519.` };
    }

    // 1. Recompute payload hash
    const expectedPayloadHash = hashField(payload);
    if (attestation.payload_hash !== expectedPayloadHash) {
      return { valid: false, reason: 'payload_hash_mismatch',
        message: `payload_hash mismatch. Expected ${expectedPayloadHash}, got ${attestation.payload_hash}` };
    }

    // 2. Recompute metadata hash
    const expectedMetaHash = hashField(metadata || null);
    const attestedMetaHash = attestation.metadata_hash || null;
    if (attestedMetaHash !== expectedMetaHash) {
      return { valid: false, reason: 'metadata_hash_mismatch',
        message: `metadata_hash mismatch. Expected ${expectedMetaHash}, got ${attestedMetaHash}` };
    }

    // 3. Reconstruct canonical envelope
    // completeness_claim is included in the signed surface when present.
    // This means the claim cannot be added, removed, or changed after signing.
    const envelope = {
      version:          attestation.version || 'dm-envelope-v1',
      algorithm:        attestation.algorithm || 'Ed25519',
      agent_id:         agentId || attestation.agent_id || '',
      client_timestamp: attestation.client_timestamp,
      key_id:           attestation.key_id,
      metadata_hash:    attestedMetaHash,
      parent_id:        parentId || attestation.parent_id || null,
      payload_hash:     attestation.payload_hash,
    };

    // Include completeness_claim in envelope only when explicitly set
    // (boolean false is a meaningful value — must be preserved)
    const cc = completenessClaim !== undefined ? completenessClaim
             : attestation.completeness_claim !== undefined ? attestation.completeness_claim
             : undefined;
    if (cc !== undefined) envelope.completeness_claim = cc;

    const envelopeCanonical = canonicalJson(envelope);

    // 4. Verify envelope hash
    const expectedEnvHash = 'sha256:' + sha256hex(envelopeCanonical);
    if (attestation.envelope_hash !== expectedEnvHash) {
      return { valid: false, reason: 'envelope_hash_mismatch',
        message: `envelope_hash mismatch. Expected ${expectedEnvHash}` };
    }

    // 5. Verify Ed25519 signature
    if (!attestation.public_key) {
      return { valid: false, reason: 'missing_public_key', message: 'public_key required for verification' };
    }
    if (!attestation.signature) {
      return { valid: false, reason: 'missing_signature', message: 'signature required' };
    }

    // Decode base64url public key (32 bytes raw Ed25519)
    const pubBytes = Buffer.from(
      (attestation.public_key + '==').replace(/-/g, '+').replace(/_/g, '/'),
      'base64'
    );
    if (pubBytes.length !== 32) {
      return { valid: false, reason: 'invalid_public_key', message: 'public_key must be 32 bytes (base64url Ed25519 public key)' };
    }

    // Decode base64url signature (64 bytes)
    const sigBytes = Buffer.from(
      (attestation.signature + '==').replace(/-/g, '+').replace(/_/g, '/'),
      'base64'
    );
    if (sigBytes.length !== 64) {
      return { valid: false, reason: 'invalid_signature_format', message: 'signature must be 64 bytes' };
    }

    // Verify using Node.js crypto (Ed25519 verify)
    const keyObject = crypto.createPublicKey({
      key: Buffer.concat([
        // Ed25519 SubjectPublicKeyInfo DER prefix
        Buffer.from('302a300506032b6570032100', 'hex'),
        pubBytes,
      ]),
      format: 'der',
      type: 'spki',
    });

    const messageBytes = Buffer.from(envelopeCanonical, 'utf8');
    const valid = crypto.verify(null, messageBytes, keyObject, sigBytes);

    if (!valid) {
      return { valid: false, reason: 'invalid_signature', message: 'Ed25519 signature verification failed' };
    }

    return { valid: true };

  } catch(e) {
    console.error('[attestation] verify error:', e.message);
    return { valid: false, reason: 'verification_error', message: e.message };
  }
}

// ── Test vector runner ────────────────────────────────────────────────────────
// Call this in tests or a health-check to ensure the implementation is correct.
function runTestVectors() {
  const vectors = require('../test-vectors-envelope-v1.json');
  const results = [];

  for (const v of vectors) {
    try {
      // Check canonical payload
      const payloadCanon = canonicalJson(v.payload);
      const payloadHash  = 'sha256:' + sha256hex(payloadCanon);
      const metaHash     = v.metadata ? 'sha256:' + sha256hex(canonicalJson(v.metadata)) : null;

      const envelope = buildEnvelope({
        agentId: v.agent_id, keyId: v.key_id,
        clientTimestamp: v.client_timestamp,
        payload: v.payload, metadata: v.metadata || null,
        parentId: v.parent_id || null,
      });
      const envCanon = canonicalJson(envelope);
      const envHash  = 'sha256:' + sha256hex(envCanon);

      const exp = v.expected;
      const checks = {
        payload_canonical:  payloadCanon  === exp.payload_canonical,
        payload_hash:       payloadHash   === exp.payload_hash,
        metadata_hash:      metaHash      === (exp.metadata_hash || null),
        envelope_canonical: envCanon      === exp.envelope_canonical,
        envelope_hash:      envHash       === exp.envelope_hash,
      };

      // Verify the pre-computed signature
      const sigResult = verifyAttestation({
        attestation: {
          ...exp,
          key_id: v.key_id,
          version: 'dm-envelope-v1',
          algorithm: 'Ed25519',
          client_timestamp: v.client_timestamp,
          public_key: v.test_public_key,
          agent_id: v.agent_id,
          parent_id: v.parent_id || null,
        },
        payload: v.payload, metadata: v.metadata || null,
        agentId: v.agent_id, parentId: v.parent_id || null,
      });
      checks.signature_valid = sigResult.valid;

      const passed = Object.values(checks).every(Boolean);
      results.push({ name: v.name, passed, checks, sigResult });
    } catch(e) {
      results.push({ name: v.name, passed: false, error: e.message });
    }
  }

  return results;
}

module.exports = { canonicalJson, hashField, buildEnvelope, verifyAttestation, runTestVectors };
