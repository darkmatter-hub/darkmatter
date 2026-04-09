/**
 * DarkMatter Append-Only Log — Phase 3
 * ======================================
 * Every commit appended here gets:
 *   - a log_position (sequential, immutable)
 *   - a leaf_hash (RFC 6962, over canonical leaf envelope)
 *   - a tree_root (Merkle root of all leaves 0..position)
 *   - a log_root (running SHA-256 hash chain — Phase 2 compatibility)
 *   - an inclusion_proof (derivable on demand)
 *   - a server_sig over the checkpoint envelope
 *
 * Failure semantics:
 *   - appendToLog throws → caller sets proof_status = 'proof_unavailable'
 *   - tree build fails   → commit still stored, proof_status = 'pending'
 *   - checkpoint fails   → proof_status = 'included' (not yet 'checkpointed')
 */

'use strict';

const crypto = require('crypto');
const { canonicalize }                         = require('./integrity');
const { leafHash, computeRoot,
        generateInclusionProof,
        buildLeafEnvelope }                    = require('./merkle');

// ─────────────────────────────────────────────────────────────────────────────
// SERVER SIGNING KEY
// ─────────────────────────────────────────────────────────────────────────────

let _serverKey    = null;
let _serverPubPem = null;

function _initKey() {
  if (_serverKey) return;
  const rawPem = process.env.DM_LOG_SIGNING_KEY_PEM;
  if (rawPem) {
    try {
      // Railway stores env vars with literal \n — normalize to real newlines
      const normalizedPem = rawPem.replace(/\\n/g, '\n').replace(/\n/g, '\n').trim();
      _serverKey = crypto.createPrivateKey(normalizedPem);
      console.log('[append-log] Signing key loaded from DM_LOG_SIGNING_KEY_PEM');
    } catch (err) {
      console.error('[append-log] Failed to load DM_LOG_SIGNING_KEY_PEM:', err.message);
      console.error('[append-log] Check that the PEM value in Railway has proper newlines');
      const { privateKey } = crypto.generateKeyPairSync('ed25519');
      _serverKey = privateKey;
      console.warn('[append-log] WARNING: Falling back to ephemeral key — checkpoints will not verify across restarts');
    }
  } else {
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    _serverKey = privateKey;
    console.warn('[append-log] WARNING: DM_LOG_SIGNING_KEY_PEM not set — using ephemeral key');
  }
  _serverPubPem = crypto.createPublicKey(_serverKey).export({ type: 'spki', format: 'pem' });
  console.log('[append-log] Server public key fingerprint:', 
    crypto.createHash('sha256').update(_serverPubPem).digest('hex').slice(0, 16) + '...');
}

function getServerPublicKeyPem() { _initKey(); return _serverPubPem; }

// ─────────────────────────────────────────────────────────────────────────────
// LOG ROOT (Phase 2 — running hash chain, kept for backwards compat)
// ─────────────────────────────────────────────────────────────────────────────

function computeLogRoot(prevLogRoot, integrityHash) {
  const prev  = prevLogRoot || 'genesis';
  return crypto.createHash('sha256').update(prev + ':' + integrityHash, 'utf8').digest('hex');
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECKPOINT SIGNING
// Checkpoint envelope (what gets signed):
// {
//   schema_version:      "3",
//   checkpoint_id:       "cp_<timestamp>_<hex>",
//   tree_root:           "<hex>",
//   tree_size:           <int>,
//   log_root:            "<hex>",
//   log_position:        <int>,
//   timestamp:           "<ISO seconds>",
//   previous_cp_id:      "<cp_...> | null",
//   previous_tree_root:  "<hex> | null"
// }
// ─────────────────────────────────────────────────────────────────────────────

const CHECKPOINT_SCHEMA_VERSION = '3';

function buildCheckpointEnvelope(treeRoot, treeSize, logRoot, logPosition, timestamp, prevCpId, prevTreeRoot) {
  const ts = timestamp.replace(/\.\d+Z?$/, '').replace(/Z?$/, 'Z');
  return {
    schema_version:      CHECKPOINT_SCHEMA_VERSION,
    checkpoint_id:       `cp_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
    tree_root:           treeRoot,
    tree_size:           treeSize,
    log_root:            logRoot,
    log_position:        logPosition,
    timestamp:           ts,
    previous_cp_id:      prevCpId   || null,
    previous_tree_root:  prevTreeRoot || null,
  };
}

function signCheckpointEnvelope(envelope) {
  _initKey();
  const msg = Buffer.from(canonicalize(envelope), 'utf8');
  return crypto.sign(null, msg, _serverKey).toString('hex');
}

function verifyCheckpointSig(envelope, signatureHex, publicKeyPem) {
  try {
    const msg    = Buffer.from(canonicalize(envelope), 'utf8');
    const sig    = Buffer.from(signatureHex, 'hex');
    const pubKey = crypto.createPublicKey(publicKeyPem);
    return crypto.verify(null, msg, pubKey, sig);
  } catch { return false; }
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN APPEND — called inside commit transaction
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Append a commit to the log. Computes leaf_hash, tree_root, and log_root.
 *
 * @returns {object} {
 *   position, leaf_hash, tree_root, tree_size, log_root, accepted_at,
 *   inclusion_proof: { leaf_index, tree_size, proof: [{hash, direction}] }
 * }
 */
async function appendToLog(supabaseService, commitId, integrityHash) {
  const accepted_at = new Date().toISOString().replace(/\.\d+Z?$/, 'Z');

  // Fetch all existing log entries (sorted) for tree construction
  const { data: existing, error: fetchErr } = await supabaseService
    .from('log_entries')
    .select('position, leaf_hash, log_root')
    .order('position', { ascending: true });

  if (fetchErr) throw new Error(`Log fetch failed: ${fetchErr.message}`);

  const prevEntries  = existing || [];
  const newPosition  = prevEntries.length;
  const prevLogRoot  = prevEntries.length > 0
    ? prevEntries[prevEntries.length - 1].log_root
    : null;

  // Compute this entry's leaf hash
  const lHash = leafHash(commitId, integrityHash, newPosition, accepted_at);

  // Build full leaf set for Merkle root computation
  const allLeafHashes = [
    ...prevEntries.map(e => e.leaf_hash),
    lHash,
  ];
  const treeRoot  = computeRoot(allLeafHashes);
  const treeSize  = allLeafHashes.length;
  const logRoot   = computeLogRoot(prevLogRoot, integrityHash);

  // Generate inclusion proof for this commit
  const inclusionProof = generateInclusionProof(allLeafHashes, newPosition);

  // Insert log entry
  const { error: insertErr } = await supabaseService
    .from('log_entries')
    .insert({
      position:       newPosition,
      commit_id:      commitId,
      integrity_hash: integrityHash,
      leaf_hash:      lHash,
      tree_root:      treeRoot,
      tree_size:      treeSize,
      log_root:       logRoot,
      server_sig:     '',   // placeholder — checkpoint signs the tree, not each entry
      timestamp:      accepted_at,
    });

  if (insertErr) throw new Error(`Log insert failed: ${insertErr.message}`);

  return {
    position:       newPosition,
    leaf_hash:      lHash,
    tree_root:      treeRoot,
    tree_size:      treeSize,
    log_root:       logRoot,
    accepted_at,
    inclusion_proof: inclusionProof,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// PROOF GENERATION (on demand, from stored leaf hashes)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate an inclusion proof for any commit by ID.
 * Fetches all leaf hashes up to and including this commit's position.
 */
async function generateProofForCommit(supabaseService, commitId) {
  // Find this commit's log entry
  const { data: entry } = await supabaseService
    .from('log_entries')
    .select('position, leaf_hash, tree_root, tree_size, integrity_hash, timestamp')
    .eq('commit_id', commitId)
    .single();

  if (!entry) return null;

  // Fetch all entries up to tree_size at time of append
  const { data: allEntries } = await supabaseService
    .from('log_entries')
    .select('leaf_hash')
    .lte('position', entry.tree_size - 1)
    .order('position', { ascending: true });

  const allLeafHashes = (allEntries || []).map(e => e.leaf_hash);

  // Recompute to verify consistency
  const recomputedRoot = computeRoot(allLeafHashes);
  const consistent     = recomputedRoot === entry.tree_root;

  const proof = generateInclusionProof(allLeafHashes, entry.position);

  // Build leaf envelope for verifier
  const leafEnvelope = buildLeafEnvelope(
    commitId, entry.integrity_hash, entry.position, entry.timestamp
  );

  return {
    commit_id:      commitId,
    log_position:   entry.position,
    tree_size:      entry.tree_size,
    tree_root:      entry.tree_root,
    leaf_hash:      entry.leaf_hash,
    leaf_envelope:  leafEnvelope,
    consistent,
    inclusion_proof: proof,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// LOG CONSISTENCY VERIFICATION
// ─────────────────────────────────────────────────────────────────────────────

function verifyLogConsistency(entries, pubKeyPem) {
  let prevRoot  = null;
  let brokenAt  = null;

  for (const entry of entries) {
    // Rebuild log root
    const expectedLogRoot = computeLogRoot(prevRoot, entry.integrity_hash);
    if (expectedLogRoot !== entry.log_root) {
      brokenAt = entry.position; break;
    }
    prevRoot = entry.log_root;
  }

  return {
    consistent:      brokenAt === null,
    broken_at:       brokenAt,
    entries_checked: entries.length,
  };
}

module.exports = {
  getServerPublicKeyPem,
  computeLogRoot,
  buildCheckpointEnvelope,
  signCheckpointEnvelope,
  verifyCheckpointSig,
  appendToLog,
  generateProofForCommit,
  verifyLogConsistency,
  CHECKPOINT_SCHEMA_VERSION,
};

// ─────────────────────────────────────────────────────────────────────────────
// CHECKPOINT CONSISTENCY VERIFICATION
// Proves that checkpoint B is an append-only extension of checkpoint A.
// No entries were deleted or rewritten between the two snapshots.
//
// Method: fetch all leaf hashes between the two checkpoints, recompute
// both tree roots, and verify they match the signed checkpoint values.
//
// This is the lightweight version — full RFC 6962 consistency proofs
// (which only require O(log n) hashes rather than all leaves) are Phase 4.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verify that checkpoint B is a valid append-only extension of checkpoint A.
 *
 * @param {object} supabaseService
 * @param {object} cpA  - older checkpoint { checkpoint_id, tree_root, tree_size, position }
 * @param {object} cpB  - newer checkpoint { checkpoint_id, tree_root, tree_size, position }
 * @param {string} pubKeyPem - server public key PEM for signature verification
 * @returns {object} { consistent, reason, old_root_ok, new_root_ok, sig_a_ok, sig_b_ok }
 */
async function verifyCheckpointConsistency(supabaseService, cpA, cpB, pubKeyPem) {
  // 1. Both checkpoint signatures must be valid
  const sig_a_ok = verifyCheckpointSig(
    { schema_version: cpA.schema_version || '3', checkpoint_id: cpA.checkpoint_id,
      tree_root: cpA.tree_root, tree_size: cpA.tree_size, log_root: cpA.log_root,
      log_position: cpA.position, timestamp: cpA.timestamp,
      previous_cp_id: cpA.previous_cp_id || null,
      previous_tree_root: cpA.previous_tree_root || null },
    cpA.server_sig, pubKeyPem
  );
  const sig_b_ok = verifyCheckpointSig(
    { schema_version: cpB.schema_version || '3', checkpoint_id: cpB.checkpoint_id,
      tree_root: cpB.tree_root, tree_size: cpB.tree_size, log_root: cpB.log_root,
      log_position: cpB.position, timestamp: cpB.timestamp,
      previous_cp_id: cpB.previous_cp_id || null,
      previous_tree_root: cpB.previous_tree_root || null },
    cpB.server_sig, pubKeyPem
  );

  if (!sig_a_ok) return { consistent: false, reason: 'checkpoint_a_sig_invalid', sig_a_ok, sig_b_ok };
  if (!sig_b_ok) return { consistent: false, reason: 'checkpoint_b_sig_invalid', sig_a_ok, sig_b_ok };

  // 2. Verify checkpoint chain linkage — B must reference A (or a later checkpoint that does)
  const chain_linked = cpB.previous_cp_id === cpA.checkpoint_id
    || cpB.previous_tree_root === cpA.tree_root;

  // 3. Fetch all leaf hashes up to B's tree_size
  const { data: allLeaves } = await supabaseService
    .from('log_entries')
    .select('position, leaf_hash')
    .lte('position', (cpB.tree_size || 0) - 1)
    .order('position', { ascending: true });

  if (!allLeaves || allLeaves.length < (cpB.tree_size || 0)) {
    return {
      consistent: false,
      reason:     'insufficient_log_entries',
      entries_found: allLeaves?.length ?? 0,
      expected: cpB.tree_size,
      sig_a_ok, sig_b_ok,
    };
  }

  const allLeafHashes = allLeaves.map(e => e.leaf_hash);

  // 4. Recompute root A from first cpA.tree_size leaves
  const oldLeaves     = allLeafHashes.slice(0, cpA.tree_size || 0);
  const recomputedOld = computeRoot(oldLeaves);
  const old_root_ok   = recomputedOld === (cpA.tree_root || '').replace('sha256:', '');

  // 5. Recompute root B from all cpB.tree_size leaves
  const recomputedNew = computeRoot(allLeafHashes.slice(0, cpB.tree_size || 0));
  const new_root_ok   = recomputedNew === (cpB.tree_root || '').replace('sha256:', '');

  const consistent = old_root_ok && new_root_ok && sig_a_ok && sig_b_ok;

  return {
    consistent,
    reason:       consistent ? 'ok' : (!old_root_ok ? 'old_root_mismatch' : 'new_root_mismatch'),
    old_root_ok,
    new_root_ok,
    sig_a_ok,
    sig_b_ok,
    chain_linked,
    checkpoints_compared: { a: cpA.checkpoint_id, b: cpB.checkpoint_id },
    tree_sizes:           { a: cpA.tree_size, b: cpB.tree_size },
  };
}

module.exports = Object.assign(module.exports, { verifyCheckpointConsistency });
