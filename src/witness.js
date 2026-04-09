/**
 * DarkMatter Witness Module — Phase 4A
 * ======================================
 * External witnesses independently co-sign DarkMatter checkpoints.
 * This is the "independence beyond operator" milestone.
 *
 * Design principles:
 *   1. Witnesses sign exactly the same checkpoint envelope that DarkMatter signs
 *   2. Witness signatures are verified by DarkMatter on receipt and stored
 *   3. Any third party can verify a witness signature using only:
 *      - the checkpoint JSON (public)
 *      - the witness public key (registered and public)
 *   4. If DarkMatter is compromised, witnesses still hold signed records of
 *      what the tree root was at each checkpoint — tampering becomes detectable
 *
 * Witness flow (Phase 4A):
 *   1. DarkMatter publishes a checkpoint (as in Phase 3)
 *   2. DarkMatter delivers the checkpoint to registered witnesses via HTTP
 *   3. Each witness independently verifies the checkpoint structure and signs it
 *   4. Witness returns their signature to DarkMatter
 *   5. DarkMatter verifies the witness signature and stores it
 *   6. Checkpoint is now "witnessed" — export bundles include witness sigs
 *   7. Offline verifier can validate witness signatures independently
 *
 * What a witness signature proves:
 *   "At timestamp T, the witness attests that the DarkMatter log had
 *    tree_root R at tree_size N, and that the checkpoint is structurally valid."
 *
 * What it does NOT prove (yet — Phase 4B):
 *   - That the witness independently computed the tree from raw leaves
 *   - That witnesses cross-verify each other
 *
 * Phase 4B adds: witnesses run their own log mirrors and cross-verify.
 */

'use strict';

const crypto = require('crypto');
const https  = require('https');
const { canonicalize } = require('./integrity');

// ─────────────────────────────────────────────────────────────────────────────
// WITNESS REGISTRATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Register a new external witness.
 * Witnesses have their own Ed25519 keypair — private key held by the witness,
 * public key registered with DarkMatter.
 *
 * @param {object} supabaseService
 * @param {string} name           - human-readable name (e.g. "Deloitte Audit Node 1")
 * @param {string} publicKeyPem   - witness Ed25519 public key
 * @param {string} endpointUrl    - optional webhook for checkpoint delivery
 */
async function registerWitness(supabaseService, name, publicKeyPem, endpointUrl = null) {
  // Validate Ed25519 public key
  try {
    const key = crypto.createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== 'ed25519') {
      throw new Error('Only Ed25519 witness keys are accepted');
    }
  } catch (err) {
    throw new Error(`Invalid witness public key: ${err.message}`);
  }

  // Derive witness ID from public key (deterministic)
  const pubBytes = crypto.createPublicKey(publicKeyPem)
    .export({ type: 'spki', format: 'der' });
  const witnessId = 'wit_' + crypto.createHash('sha256').update(pubBytes).digest('hex').slice(0, 16);

  const { data: existing } = await supabaseService
    .from('witnesses')
    .select('witness_id')
    .eq('witness_id', witnessId)
    .single();

  if (existing) throw new Error(`Witness ${witnessId} already registered`);

  const { error } = await supabaseService.from('witnesses').insert({
    witness_id:     witnessId,
    name,
    public_key_pem: publicKeyPem,
    endpoint_url:   endpointUrl,
    active:         true,
  });

  if (error) throw new Error(`Witness registration failed: ${error.message}`);

  return { witness_id: witnessId, name, registered: true };
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECKPOINT DELIVERY TO WITNESSES
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Deliver a checkpoint to a witness endpoint for signing.
 *
 * Protocol:
 *   POST <witness_endpoint>
 *   Body: { checkpoint: <checkpoint_object>, darkmatter_pubkey: <pem> }
 *
 *   Response: { witness_sig: <hex>, witnessed_at: <ISO>, witness_id: <wit_...> }
 *
 * The witness is expected to:
 *   1. Verify DarkMatter's server_sig on the checkpoint
 *   2. Verify the checkpoint is structurally valid
 *   3. Sign the canonical checkpoint envelope with their own key
 *   4. Return their signature
 */
async function deliverToWitness(witness, checkpoint, serverPubKeyPem) {
  if (!witness.endpoint_url) {
    return { delivered: false, reason: 'no_endpoint' };
  }

  const payload = JSON.stringify({
    checkpoint,
    darkmatter_pubkey: serverPubKeyPem,
    spec_url: 'https://darkmatterhub.ai/docs#integrity-spec',
  });

  return new Promise((resolve) => {
    const url = new URL(witness.endpoint_url);
    const opts = {
      hostname: url.hostname,
      port:     url.port || (url.protocol === 'https:' ? 443 : 80),
      path:     url.pathname + url.search,
      method:   'POST',
      headers:  {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'User-Agent':     'darkmatter-witness-delivery/1.0',
        'X-DarkMatter-Checkpoint-ID': checkpoint.checkpoint_id,
      },
    };

    const proto = url.protocol === 'https:' ? https : require('http');
    const req   = proto.request(opts, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const body = JSON.parse(data);
          resolve({ delivered: true, status: res.statusCode, response: body });
        } catch {
          resolve({ delivered: false, error: 'invalid JSON response', status: res.statusCode });
        }
      });
    });

    req.on('error', e => resolve({ delivered: false, error: e.message }));
    req.setTimeout(10000, () => { req.destroy(); resolve({ delivered: false, error: 'timeout' }); });
    req.write(payload);
    req.end();
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// WITNESS SIGNATURE SUBMISSION
// Called when a witness submits their signature (via POST /api/witness/sign)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Accept and verify a witness signature on a checkpoint.
 * The witness signature is over canonical(checkpoint_envelope) —
 * the exact same bytes DarkMatter signed.
 *
 * @param {object} supabaseService
 * @param {string} checkpointId   - the checkpoint being co-signed
 * @param {string} witnessId      - wit_... identifier
 * @param {string} witnessSigHex  - Ed25519 hex signature
 * @param {string} witnessedAt    - ISO timestamp the witness asserted
 */
async function acceptWitnessSignature(supabaseService, checkpointId, witnessId, witnessSigHex, witnessedAt) {
  // Fetch checkpoint
  const { data: checkpoint } = await supabaseService
    .from('checkpoints')
    .select('*')
    .eq('checkpoint_id', checkpointId)
    .single();

  if (!checkpoint) throw new Error(`Checkpoint not found: ${checkpointId}`);

  // Fetch witness public key
  const { data: witness } = await supabaseService
    .from('witnesses')
    .select('public_key_pem, name')
    .eq('witness_id', witnessId)
    .eq('active', true)
    .single();

  if (!witness) throw new Error(`Active witness not found: ${witnessId}`);

  // Rebuild the checkpoint envelope (same object that was signed)
  const { published, published_url, witness_count, witness_status, ...cpFields } = checkpoint;
  const { server_sig, ...envelopeWithoutSig } = cpFields;

  // Remove any non-spec fields before verifying
  const envelope = {
    schema_version:      envelopeWithoutSig.schema_version || '3',
    checkpoint_id:       envelopeWithoutSig.checkpoint_id,
    tree_root:           envelopeWithoutSig.tree_root,
    tree_size:           envelopeWithoutSig.tree_size,
    log_root:            envelopeWithoutSig.log_root,
    log_position:        envelopeWithoutSig.position,  // DB uses 'position', envelope uses 'log_position'
    timestamp:           envelopeWithoutSig.timestamp,
    previous_cp_id:      envelopeWithoutSig.previous_cp_id   || null,
    previous_tree_root:  envelopeWithoutSig.previous_tree_root || null,
  };

  // Verify the witness signature
  const message = Buffer.from(canonicalize(envelope), 'utf8');
  const sigBuf  = Buffer.from(witnessSigHex, 'hex');
  const pubKey  = crypto.createPublicKey(witness.public_key_pem);
  const sigValid = crypto.verify(null, message, pubKey, sigBuf);

  const ts = witnessedAt || new Date().toISOString().replace(/\.\d+Z?$/, 'Z');

  // Store the witness signature
  const { error: insertErr } = await supabaseService.from('witness_sigs').insert({
    checkpoint_id: checkpointId,
    witness_id:    witnessId,
    witness_sig:   witnessSigHex,
    witnessed_at:  ts,
    sig_valid:     sigValid,
  });

  if (insertErr && !insertErr.message.includes('duplicate')) {
    throw new Error(`Failed to store witness sig: ${insertErr.message}`);
  }

  // Update checkpoint witness count and status
  const { data: allSigs } = await supabaseService
    .from('witness_sigs')
    .select('witness_id, sig_valid')
    .eq('checkpoint_id', checkpointId);

  const validCount  = (allSigs || []).filter(s => s.sig_valid).length;
  const witnessStatus = validCount >= 1 ? 'witnessed' : 'witness_failed';

  await supabaseService.from('checkpoints').update({
    witness_count:  validCount,
    witness_status: witnessStatus,
  }).eq('checkpoint_id', checkpointId);

  // Update proof_status on covered commits
  if (validCount >= 1) {
    await supabaseService.from('commits').update({
      proof_status: 'checkpointed_witnessed',
    })
    .eq('checkpoint_id', checkpointId)
    .in('proof_status', ['checkpointed', 'checkpointed_published']);
  }

  console.log(`[witness] ${witness.name} (${witnessId}) signed ${checkpointId}: valid=${sigValid}`);

  return {
    checkpoint_id: checkpointId,
    witness_id:    witnessId,
    witness_name:  witness.name,
    sig_valid:     sigValid,
    witness_count: validCount,
    witness_status: witnessStatus,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// BROADCAST TO ALL ACTIVE WITNESSES
// Called after each checkpoint is published
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Deliver a freshly published checkpoint to all active witnesses.
 * Fire-and-forget — witnesses may respond asynchronously.
 * DarkMatter does not block the checkpoint flow waiting for witness responses.
 */
async function broadcastToWitnesses(supabaseService, checkpoint, serverPubKeyPem) {
  const { data: witnesses } = await supabaseService
    .from('witnesses')
    .select('*')
    .eq('active', true)
    .not('endpoint_url', 'is', null);

  if (!witnesses || witnesses.length === 0) {
    console.log('[witness] No active witnesses with endpoints configured');
    return { sent: 0, results: [] };
  }

  const results = await Promise.allSettled(
    witnesses.map(async (w) => {
      const result = await deliverToWitness(w, checkpoint, serverPubKeyPem);
      if (result.delivered && result.response?.witness_sig) {
        // Accept the signature if witness responded synchronously
        try {
          await acceptWitnessSignature(
            supabaseService,
            checkpoint.checkpoint_id,
            w.witness_id,
            result.response.witness_sig,
            result.response.witnessed_at,
          );
        } catch (err) {
          console.error(`[witness] Failed to accept sig from ${w.witness_id}:`, err.message);
        }
      }
      return { witness_id: w.witness_id, name: w.name, ...result };
    })
  );

  const deliveries = results.map(r => r.status === 'fulfilled' ? r.value : { error: r.reason?.message });
  console.log(`[witness] Broadcast to ${witnesses.length} witnesses: ${deliveries.filter(d => d.delivered).length} delivered`);

  return { sent: witnesses.length, results: deliveries };
}

// ─────────────────────────────────────────────────────────────────────────────
// WITNESS SIGNATURE VERIFICATION (for offline verifier)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verify a witness signature on a checkpoint envelope.
 * Called by the offline verifier — requires only the checkpoint JSON
 * and the witness public key PEM. No DarkMatter dependency.
 *
 * @param {object} checkpointEnvelope - the canonical checkpoint fields (no server_sig, no witness_sig)
 * @param {string} witnessSigHex      - the witness signature to verify
 * @param {string} witnessPublicKeyPem - witness Ed25519 public key
 */
function verifyWitnessSignature(checkpointEnvelope, witnessSigHex, witnessPublicKeyPem) {
  try {
    const message = Buffer.from(canonicalize(checkpointEnvelope), 'utf8');
    const sigBuf  = Buffer.from(witnessSigHex, 'hex');
    const pubKey  = crypto.createPublicKey(witnessPublicKeyPem);
    return crypto.verify(null, message, pubKey, sigBuf);
  } catch { return false; }
}

// ─────────────────────────────────────────────────────────────────────────────
// REFERENCE WITNESS IMPLEMENTATION
// A minimal witness server that can be run independently.
// This is what a Deloitte or E&Y node would implement.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Process a checkpoint delivery request from DarkMatter.
 * This function contains the complete witness logic — nothing else needed.
 *
 * In production, a witness would:
 *   1. Maintain their own Ed25519 keypair (private key on their server only)
 *   2. Run this function on receipt of each checkpoint
 *   3. Return their signature
 *   4. Optionally store checkpoint + sig locally for independent audit
 *
 * @param {object} body          - { checkpoint, darkmatter_pubkey }
 * @param {string} privateKeyPem - witness's own private key (never sent to DarkMatter)
 */
function processCheckpointAsWitness(body, privateKeyPem) {
  const { checkpoint, darkmatter_pubkey } = body;

  if (!checkpoint?.checkpoint_id || !checkpoint?.tree_root || !checkpoint?.server_sig) {
    return { error: 'invalid checkpoint structure' };
  }

  // 1. Verify DarkMatter's own signature on the checkpoint
  const { server_sig, published, published_url, witness_count, witness_status, ...cpFields } = checkpoint;
  const { position, ...rest } = cpFields;
  const envelope = {
    schema_version:      rest.schema_version || '3',
    checkpoint_id:       rest.checkpoint_id,
    tree_root:           rest.tree_root,
    tree_size:           rest.tree_size,
    log_root:            rest.log_root,
    log_position:        position ?? rest.log_position,
    timestamp:           rest.timestamp,
    previous_cp_id:      rest.previous_cp_id   || null,
    previous_tree_root:  rest.previous_tree_root || null,
  };

  try {
    const msg     = Buffer.from(canonicalize(envelope), 'utf8');
    const sig     = Buffer.from(server_sig, 'hex');
    const pubKey  = crypto.createPublicKey(darkmatter_pubkey);
    const dmSigOk = crypto.verify(null, msg, pubKey, sig);

    if (!dmSigOk) {
      return { error: 'DarkMatter server signature invalid — refusing to co-sign' };
    }
  } catch (err) {
    return { error: `Signature verification error: ${err.message}` };
  }

  // 2. Sign the same envelope with our witness key
  const privKey     = crypto.createPrivateKey(privateKeyPem);
  const message     = Buffer.from(canonicalize(envelope), 'utf8');
  const witnessedAt = new Date().toISOString().replace(/\.\d+Z?$/, 'Z');
  const witnessSig  = crypto.sign(null, message, privKey).toString('hex');

  // 3. Derive our witness_id from our public key
  const pubBytes  = crypto.createPublicKey(privKey).export({ type: 'spki', format: 'der' });
  const witnessId = 'wit_' + crypto.createHash('sha256').update(pubBytes).digest('hex').slice(0, 16);

  return {
    witness_id:   witnessId,
    checkpoint_id: checkpoint.checkpoint_id,
    tree_root:    envelope.tree_root,
    tree_size:    envelope.tree_size,
    witness_sig:  witnessSig,
    witnessed_at: witnessedAt,
  };
}

module.exports = {
  registerWitness,
  deliverToWitness,
  acceptWitnessSignature,
  broadcastToWitnesses,
  verifyWitnessSignature,
  processCheckpointAsWitness,
};
