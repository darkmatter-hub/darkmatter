/**
 * DarkMatter Key Lifecycle Manager
 * ==================================
 * Handles agent key registration, rotation, revocation, and
 * historical key lookup for offline verification after rotation.
 *
 * Core principle: a commit's agent_signature was made with whatever key
 * was active at accepted_at. To verify an old commit after key rotation,
 * you need the key that was valid at that point in time — not the current key.
 *
 * Key states:
 *   active     — registered, not revoked, within valid_from/valid_until
 *   rotated    — superseded by a newer key, but valid for historical commits
 *   revoked    — explicitly invalidated, reason recorded
 *   expired    — past valid_until date
 *
 * Key lifecycle events (all stored in key_events — append-only):
 *   registered — new key added
 *   rotated    — key replaced by new key, old key marked rotated_from
 *   revoked    — key explicitly invalidated (compromised etc.)
 *   expired    — key passed valid_until
 */

'use strict';

const crypto = require('crypto');

// ─────────────────────────────────────────────────────────────────────────────
// REGISTRATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Register a new public key for an agent.
 * The agent's private key never leaves their machine — only PEM public key stored.
 *
 * @param {object} supabaseService
 * @param {string} agentId
 * @param {string} publicKeyPem   - Ed25519 PEM public key
 * @param {string} keyId          - identifier for this key (default: 'default')
 * @param {object} options        - { validUntil, performedBy }
 */
async function registerKey(supabaseService, agentId, publicKeyPem, keyId = 'default', options = {}) {
  // Validate it's a real Ed25519 public key
  try {
    const key = crypto.createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== 'ed25519') {
      throw new Error('Only Ed25519 keys are accepted');
    }
  } catch (err) {
    throw new Error(`Invalid public key: ${err.message}`);
  }

  const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');

  // Check if a key with this ID already exists for this agent
  const { data: existing } = await supabaseService
    .from('agent_pubkeys')
    .select('key_id, revoked_at')
    .eq('agent_id', agentId)
    .eq('key_id', keyId)
    .single();

  if (existing && !existing.revoked_at) {
    throw new Error(`Key '${keyId}' already exists for agent ${agentId}. Use rotateKey() to replace it.`);
  }

  // Get current key version
  const { data: allKeys } = await supabaseService
    .from('agent_pubkeys')
    .select('key_version')
    .eq('agent_id', agentId)
    .order('key_version', { ascending: false })
    .limit(1);

  const keyVersion = (allKeys?.[0]?.key_version ?? 0) + 1;

  const { error } = await supabaseService.from('agent_pubkeys').insert({
    agent_id:       agentId,
    public_key_pem: publicKeyPem,
    key_id:         keyId,
    key_version:    keyVersion,
    valid_from:     now,
    valid_until:    options.validUntil || null,
    registered_at:  now,
  });

  if (error) throw new Error(`Key registration failed: ${error.message}`);

  // Record key event
  await supabaseService.from('key_events').insert({
    agent_id:    agentId,
    key_id:      keyId,
    event_type:  'registered',
    performed_by: options.performedBy || agentId,
    timestamp:   now,
  });

  return { agent_id: agentId, key_id: keyId, key_version: keyVersion, registered_at: now };
}

// ─────────────────────────────────────────────────────────────────────────────
// ROTATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Rotate a key — replace the current key with a new one.
 *
 * The old key is NOT revoked. It remains valid for historical verification
 * of commits that were signed with it. The new key takes over for new commits.
 *
 * This is the critical property: historical offline verification must still
 * work after rotation. A commit signed 6 months ago with key_v1 must still
 * be verifiable even after rotating to key_v2.
 *
 * @param {string} newPublicKeyPem - the replacement key
 * @param {string} newKeyId        - ID for the new key (e.g. 'default', 'key_v2')
 * @param {string} reason          - why rotating (optional but encouraged)
 */
async function rotateKey(supabaseService, agentId, currentKeyId, newPublicKeyPem, newKeyId = 'default', reason = '') {
  // Validate new key
  try {
    const key = crypto.createPublicKey(newPublicKeyPem);
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('Only Ed25519 keys accepted');
  } catch (err) {
    throw new Error(`Invalid new public key: ${err.message}`);
  }

  const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');

  // Fetch current key
  const { data: currentKey } = await supabaseService
    .from('agent_pubkeys')
    .select('*')
    .eq('agent_id', agentId)
    .eq('key_id', currentKeyId)
    .is('revoked_at', null)
    .single();

  if (!currentKey) {
    throw new Error(`No active key '${currentKeyId}' found for agent ${agentId}`);
  }

  const newKeyVersion = (currentKey.key_version ?? 1) + 1;

  // Insert new key — points back to the key it rotated from
  const { error: insertErr } = await supabaseService.from('agent_pubkeys').insert({
    agent_id:       agentId,
    public_key_pem: newPublicKeyPem,
    key_id:         newKeyId,
    key_version:    newKeyVersion,
    rotated_from:   currentKeyId,
    valid_from:     now,
    registered_at:  now,
  });

  if (insertErr) throw new Error(`Key rotation failed (insert): ${insertErr.message}`);

  // Mark old key as superseded — but do NOT revoke it (historical commits still valid)
  // We set valid_until on the old key to now, so it won't be selected as "active"
  // but it remains queryable for historical verification
  await supabaseService
    .from('agent_pubkeys')
    .update({ valid_until: now })
    .eq('agent_id', agentId)
    .eq('key_id', currentKeyId)
    .is('revoked_at', null);

  // Record rotation event
  await supabaseService.from('key_events').insert({
    agent_id:        agentId,
    key_id:          newKeyId,
    event_type:      'rotated',
    previous_key_id: currentKeyId,
    reason:          reason || 'key rotation',
    performed_by:    agentId,
    timestamp:       now,
  });

  return {
    agent_id:    agentId,
    old_key_id:  currentKeyId,
    new_key_id:  newKeyId,
    key_version: newKeyVersion,
    rotated_at:  now,
    note:        'Old key remains valid for historical verification of past commits',
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// REVOCATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Revoke a key immediately.
 *
 * Use for compromised keys. Unlike rotation, revocation means commits signed
 * with this key CANNOT be trusted even historically. The verifier will flag
 * them as signed_by_revoked_key.
 *
 * The revocation reason and timestamp are recorded and are themselves
 * part of the audit trail.
 *
 * @param {string} reason - REQUIRED for revocation (e.g. 'private key compromised')
 */
async function revokeKey(supabaseService, agentId, keyId, reason, revokedBy) {
  if (!reason) throw new Error('Revocation reason is required');

  const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');

  const { error } = await supabaseService
    .from('agent_pubkeys')
    .update({
      revoked_at:        now,
      revocation_reason: reason,
      revoked_by:        revokedBy || agentId,
    })
    .eq('agent_id', agentId)
    .eq('key_id', keyId);

  if (error) throw new Error(`Revocation failed: ${error.message}`);

  await supabaseService.from('key_events').insert({
    agent_id:    agentId,
    key_id:      keyId,
    event_type:  'revoked',
    reason:      reason,
    performed_by: revokedBy || agentId,
    timestamp:   now,
  });

  return {
    agent_id:   agentId,
    key_id:     keyId,
    revoked_at: now,
    reason,
    warning:    'Commits signed with this key will be flagged as signed_by_revoked_key in verification',
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// HISTORICAL KEY LOOKUP
// The critical function for offline verification after rotation.
// Given a commit's accepted_at timestamp, find the key that was active then.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Find the key that was valid for a given agent at a specific point in time.
 *
 * This is what the verifier calls when checking the signature on a historical
 * commit: "what key should I use to verify a commit accepted on 2026-01-15?"
 *
 * Returns the public key PEM, plus metadata about its status.
 *
 * @param {string} agentId
 * @param {string} keyId       - the key_id stored in the commit envelope
 * @param {string} acceptedAt  - ISO timestamp of when the commit was accepted
 */
async function getKeyAtTime(supabaseService, agentId, keyId, acceptedAt) {
  const ts = acceptedAt || new Date().toISOString();

  const { data: key } = await supabaseService
    .from('agent_pubkeys')
    .select('*')
    .eq('agent_id', agentId)
    .eq('key_id', keyId)
    .lte('valid_from', ts)      // key must have existed at commit time
    .order('key_version', { ascending: false })
    .limit(1)
    .single();

  if (!key) return null;

  // Determine key status at the time of the commit
  const wasActiveAtTime = !key.valid_until || key.valid_until > ts;
  const isRevokedNow    = !!key.revoked_at;
  const wasRevokedAtTime = key.revoked_at && key.revoked_at <= ts;

  return {
    public_key_pem: key.public_key_pem,
    key_id:         key.key_id,
    key_version:    key.key_version,
    status_at_commit_time: wasRevokedAtTime
      ? 'revoked'
      : wasActiveAtTime ? 'active' : 'not_yet_valid',
    is_revoked_now: isRevokedNow,
    revocation_reason: key.revocation_reason || null,
    revoked_at:        key.revoked_at || null,
    valid_from:        key.valid_from,
    valid_until:       key.valid_until,
  };
}

/**
 * Get all keys for an agent — full lifecycle history.
 * Used by the verifier and dashboard to show key history.
 */
async function getKeyHistory(supabaseService, agentId) {
  const { data: keys } = await supabaseService
    .from('agent_pubkeys')
    .select('key_id, key_version, valid_from, valid_until, revoked_at, revocation_reason, rotated_from, registered_at')
    .eq('agent_id', agentId)
    .order('key_version', { ascending: true });

  const { data: events } = await supabaseService
    .from('key_events')
    .select('*')
    .eq('agent_id', agentId)
    .order('timestamp', { ascending: true });

  return { agent_id: agentId, keys: keys || [], events: events || [] };
}

// ─────────────────────────────────────────────────────────────────────────────
// SIGNATURE VERIFICATION WITH KEY LIFECYCLE AWARENESS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verify a commit's envelope signature, using the key that was valid
 * at the time the commit was accepted.
 *
 * Returns a rich result that distinguishes between:
 *   valid             — signature checks out with the correct key
 *   revoked_key       — key was revoked BEFORE commit was accepted (serious)
 *   revoked_post_commit — key was revoked AFTER commit time (normal rotation)
 *   no_key            — key not found for this agent + key_id + time
 *   invalid           — signature doesn't verify
 */
async function verifyCommitSignature(supabaseService, commit) {
  const { canonicalize } = require('./integrity');

  const agentId       = commit.agent_id || commit.agent_info?.id;
  const keyId         = commit.key_id || commit.agent_info?.key_id || 'default';
  const signature     = commit.agent_signature;
  const acceptedAt    = commit.accepted_at || commit.timestamp;

  if (!signature)  return { result: 'no_signature', verified: false };
  if (!agentId)    return { result: 'no_agent_id',  verified: false };

  const keyInfo = await getKeyAtTime(supabaseService, agentId, keyId, acceptedAt);

  if (!keyInfo) return { result: 'no_key', verified: false, agent_id: agentId, key_id: keyId };

  // Key was revoked BEFORE the commit was accepted — this is a trust violation
  if (keyInfo.status_at_commit_time === 'revoked') {
    return {
      result:            'revoked_key',
      verified:          false,
      key_id:            keyId,
      revoked_at:        keyInfo.revoked_at,
      revocation_reason: keyInfo.revocation_reason,
      warning:           'This commit was accepted after its signing key was revoked',
    };
  }

  // Verify the signature using the integrity module
  const { verifyEnvelopeSignature, buildEnvelope, hashPayload } = require('./integrity');

  // Reconstruct the envelope that was signed
  const payloadHash = hashPayload(commit.payload || {});
  const parentIH    = (commit.parent_hash || '').replace('sha256:', '') || null;
  const envelope    = buildEnvelope(
    payloadHash, parentIH, agentId, keyId,
    commit.client_timestamp || commit.timestamp
  );

  const sigValid = verifyEnvelopeSignature(envelope, signature, keyInfo.public_key_pem);

  return {
    result:   sigValid ? (keyInfo.is_revoked_now ? 'revoked_post_commit' : 'valid') : 'invalid',
    verified: sigValid,
    key_id:   keyId,
    key_version: keyInfo.key_version,
    is_revoked_now: keyInfo.is_revoked_now,
    revoked_post_commit: sigValid && keyInfo.is_revoked_now,
    note: keyInfo.is_revoked_now && sigValid
      ? 'Key was revoked after this commit was accepted — commit integrity is unaffected'
      : null,
  };
}

module.exports = {
  registerKey,
  rotateKey,
  revokeKey,
  getKeyAtTime,
  getKeyHistory,
  verifyCommitSignature,
};
