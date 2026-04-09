/**
 * DarkMatter Append-Only Log (Phase 2)
 * =====================================
 * Maintains a signed, sequential log of all commit integrity_hashes.
 * Every entry is immutable. The log root is signed by DarkMatter's
 * server key and published to a public checkpoint surface.
 *
 * Phase 2: DarkMatter-signed checkpoints (no external witnesses yet)
 * Phase 3: Merkle tree inclusion proofs added on top of this
 *
 * Why this matters:
 *   With only a database, DarkMatter could silently delete or rewrite
 *   a commit. With an append-only log, any such rewrite changes the
 *   log root — detectable by anyone who holds the previous checkpoint.
 *
 * Table: log_entries
 *   position        BIGSERIAL PRIMARY KEY
 *   commit_id       TEXT NOT NULL
 *   integrity_hash  TEXT NOT NULL
 *   timestamp       TIMESTAMPTZ NOT NULL
 *   log_root        TEXT NOT NULL  -- sha256 of all entries 0..position
 *   server_sig      TEXT NOT NULL  -- Ed25519 sig over log_root + position
 *   created_at      TIMESTAMPTZ DEFAULT now()
 */

'use strict';

const crypto  = require('crypto');
const { canonicalize } = require('./integrity');

// ─────────────────────────────────────────────────────────────────────────────
// SERVER SIGNING KEY
// Generated once at startup. Public key published at /api/log/pubkey
// In production: load from env, not generated fresh each restart.
// ─────────────────────────────────────────────────────────────────────────────

let _serverKey    = null;
let _serverPubPem = null;

function getServerKey() {
  if (!_serverKey) {
    if (process.env.DM_LOG_SIGNING_KEY_PEM) {
      _serverKey = crypto.createPrivateKey(process.env.DM_LOG_SIGNING_KEY_PEM);
    } else {
      // Dev: generate ephemeral key (not suitable for production)
      const { privateKey } = crypto.generateKeyPairSync('ed25519');
      _serverKey = privateKey;
      console.warn('[append-log] WARNING: Using ephemeral signing key. Set DM_LOG_SIGNING_KEY_PEM in production.');
    }
    _serverPubPem = crypto.createPublicKey(_serverKey)
      .export({ type: 'spki', format: 'pem' });
  }
  return { privateKey: _serverKey, publicKeyPem: _serverPubPem };
}

function getServerPublicKeyPem() {
  return getServerKey().publicKeyPem;
}

// ─────────────────────────────────────────────────────────────────────────────
// LOG ROOT COMPUTATION
// log_root at position N = SHA-256 of canonical(all entries 0..N)
// This is a simple running hash — Phase 3 upgrades to a Merkle tree.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute the log root given the previous root and a new entry.
 * log_root_N = SHA-256( log_root_{N-1} + ":" + integrity_hash_N )
 * For the first entry: log_root_0 = SHA-256( "genesis:" + integrity_hash_0 )
 */
function computeLogRoot(prevLogRoot, integrityHash) {
  const prev  = prevLogRoot || 'genesis';
  const input = prev + ':' + integrityHash;
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Sign a log checkpoint: sign( canonical({ log_root, position, timestamp }) )
 * Returns hex-encoded Ed25519 signature.
 */
function signCheckpoint(logRoot, position, timestamp) {
  const { privateKey } = getServerKey();
  const message = canonicalize({ log_root: logRoot, position, timestamp });
  const msgBuf  = Buffer.from(message, 'utf8');
  return crypto.sign(null, msgBuf, privateKey).toString('hex');
}

/**
 * Verify a checkpoint signature (used by the offline verifier).
 */
function verifyCheckpointSig(logRoot, position, timestamp, signatureHex, publicKeyPem) {
  try {
    const message = canonicalize({ log_root: logRoot, position, timestamp });
    const msgBuf  = Buffer.from(message, 'utf8');
    const sigBuf  = Buffer.from(signatureHex, 'hex');
    const pubKey  = crypto.createPublicKey(publicKeyPem);
    return crypto.verify(null, msgBuf, pubKey, sigBuf);
  } catch {
    return false;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// LOG APPEND
// Called inside the commit transaction, after the commit row is written.
// Fails closed: if the log append fails, the commit is rejected.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Append a commit to the log.
 *
 * @param {object} supabaseService - Admin Supabase client
 * @param {string} commitId        - The ctx_... ID
 * @param {string} integrityHash   - The commit's integrity_hash (no prefix)
 * @returns {object} { position, log_root, server_sig, timestamp }
 */
async function appendToLog(supabaseService, commitId, integrityHash) {
  // Fetch the latest log entry to get current root and position
  const { data: latest } = await supabaseService
    .from('log_entries')
    .select('position, log_root')
    .order('position', { ascending: false })
    .limit(1)
    .single();

  const prevPosition = latest?.position ?? -1;
  const prevLogRoot  = latest?.log_root  ?? null;

  const newPosition  = prevPosition + 1;
  const newLogRoot   = computeLogRoot(prevLogRoot, integrityHash);
  const timestamp    = new Date().toISOString();
  const serverSig    = signCheckpoint(newLogRoot, newPosition, timestamp);

  const { error } = await supabaseService
    .from('log_entries')
    .insert({
      position:       newPosition,
      commit_id:      commitId,
      integrity_hash: integrityHash,
      log_root:       newLogRoot,
      server_sig:     serverSig,
      timestamp,
    });

  if (error) throw new Error(`Log append failed: ${error.message}`);

  return { position: newPosition, log_root: newLogRoot, server_sig: serverSig, timestamp };
}

// ─────────────────────────────────────────────────────────────────────────────
// LOG CONSISTENCY CHECK
// Verify that the log has not been tampered with between two positions.
// Anyone with a checkpoint can verify the entire log from that point forward.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verify the log is consistent from startPosition to endPosition.
 * Recomputes every log_root and checks server signatures.
 *
 * @param {Array}  entries     - Log entries in ascending position order
 * @param {string} pubKeyPem   - Server's public key PEM
 * @returns {{ consistent, broken_at, entries_checked }}
 */
function verifyLogConsistency(entries, pubKeyPem) {
  let prevRoot  = null;
  let brokenAt  = null;

  for (const entry of entries) {
    const expectedRoot = computeLogRoot(prevRoot, entry.integrity_hash);

    const rootOk = expectedRoot === entry.log_root;
    const sigOk  = verifyCheckpointSig(
      entry.log_root, entry.position, entry.timestamp,
      entry.server_sig, pubKeyPem
    );

    if (!rootOk || !sigOk) {
      brokenAt = entry.position;
      break;
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
  signCheckpoint,
  verifyCheckpointSig,
  appendToLog,
  verifyLogConsistency,
};
