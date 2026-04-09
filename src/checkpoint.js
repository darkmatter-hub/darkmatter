/**
 * DarkMatter Checkpoint Publisher — Phase 3
 * ==========================================
 * Checkpoints now sign the Merkle tree root, not just the log root.
 * Checkpoint envelope is fully specified and test-vector backed.
 *
 * Checkpoint schema v3:
 * {
 *   "schema_version":     "3",
 *   "checkpoint_id":      "cp_<ms>_<hex>",
 *   "tree_root":          "<hex>",    ← Merkle root (Phase 3)
 *   "tree_size":          <int>,
 *   "log_root":           "<hex>",    ← running hash (Phase 2 compat)
 *   "log_position":       <int>,
 *   "timestamp":          "<ISO-seconds>",
 *   "previous_cp_id":     "<cp_...> | null",
 *   "previous_tree_root": "<hex> | null",
 *   "server_sig":         "<hex>"     ← Ed25519 over canonical(above fields minus sig)
 * }
 *
 * Checkpoint chain: each checkpoint references previous_cp_id, enabling
 * verification that the log was only ever appended to between snapshots.
 */

'use strict';

const https  = require('https');
const {
  buildCheckpointEnvelope,
  signCheckpointEnvelope,
  CHECKPOINT_SCHEMA_VERSION,
} = require('./append-log');
const { broadcastToWitnesses }   = require('./witness');
const { getServerPublicKeyPem }  = require('./append-log');

const INTERVAL_MS = 10 * 60 * 1000; // 10 minutes

// ─────────────────────────────────────────────────────────────────────────────
// PUBLISH
// ─────────────────────────────────────────────────────────────────────────────

async function publishToGitHub(checkpoint) {
  const token = process.env.DM_GITHUB_TOKEN;
  const repo  = process.env.DM_GITHUB_CHECKPOINT_REPO;
  if (!token || !repo) {
    console.log('[checkpoint] GitHub publishing skipped — env vars not set');
    return { published: false, reason: 'not_configured' };
  }

  const [owner, repoName] = repo.split('/');
  const ts       = checkpoint.timestamp.replace(/[:.]/g, '-');
  const filename = `checkpoints/cp-${ts}-pos${checkpoint.log_position}.json`;
  const content  = Buffer.from(JSON.stringify(checkpoint, null, 2)).toString('base64');
  const message  = `checkpoint pos=${checkpoint.log_position} tree=${checkpoint.tree_root.slice(0,12)}... size=${checkpoint.tree_size}`;
  const body     = JSON.stringify({ message, content });

  return new Promise((resolve) => {
    const req = https.request({
      hostname: 'api.github.com',
      path:     `/repos/${owner}/${repoName}/contents/${filename}`,
      method:   'PUT',
      headers:  {
        'Authorization': `Bearer ${token}`,
        'Content-Type':  'application/json',
        'User-Agent':    'darkmatter-checkpoint/3.0',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        const ok = res.statusCode >= 200 && res.statusCode < 300;
        resolve({
          published:    ok,
          status:       res.statusCode,
          filename,
          url: `https://github.com/${repo}/blob/main/${filename}`,
        });
      });
    });
    req.on('error', e => resolve({ published: false, error: e.message }));
    req.write(body);
    req.end();
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN PUBLISH FLOW
// ─────────────────────────────────────────────────────────────────────────────

async function publishCheckpoint(supabaseService) {
  try {
    // Get latest log entry for tree state
    const { data: latest } = await supabaseService
      .from('log_entries')
      .select('position, tree_root, tree_size, log_root, timestamp')
      .order('position', { ascending: false })
      .limit(1)
      .single();

    if (!latest) {
      console.log('[checkpoint] No log entries yet');
      return { published: false, reason: 'no_entries' };
    }

    // Get previous checkpoint for chain linkage
    const { data: prevCp } = await supabaseService
      .from('checkpoints')
      .select('checkpoint_id, tree_root')
      .order('log_position', { ascending: false })
      .limit(1)
      .single();

    const timestamp = new Date().toISOString().replace(/\.\d+Z?$/, 'Z');

    // Build and sign the checkpoint envelope
    const envelope = buildCheckpointEnvelope(
      latest.tree_root,
      latest.tree_size,
      latest.log_root,
      latest.position,
      timestamp,
      prevCp?.checkpoint_id  || null,
      prevCp?.tree_root      || null,
    );
    const serverSig = signCheckpointEnvelope(envelope);
    const checkpoint = { ...envelope, server_sig: serverSig };

    // Store in DB
    await supabaseService.from('checkpoints').insert({
      checkpoint_id:       checkpoint.checkpoint_id,
      position:            checkpoint.log_position,
      log_root:            checkpoint.log_root,
      tree_root:           checkpoint.tree_root,
      tree_size:           checkpoint.tree_size,
      server_sig:          serverSig,
      timestamp:           checkpoint.timestamp,
      previous_cp_id:      checkpoint.previous_cp_id,
      previous_tree_root:  checkpoint.previous_tree_root,
      published:           false,
    });

    // Update commits covered by this checkpoint
    await supabaseService
      .from('commits')
      .update({
        checkpoint_id: checkpoint.checkpoint_id,
        proof_status:  'checkpointed',
      })
      .lte('log_position', checkpoint.log_position)
      .in('proof_status', ['pending', 'included']);

    // Publish to GitHub
    const githubResult = await publishToGitHub(checkpoint);
    if (githubResult.published) {
      await supabaseService
        .from('checkpoints')
        .update({ published: true, published_url: githubResult.url })
        .eq('checkpoint_id', checkpoint.checkpoint_id);

      // Mark commits as fully published
      await supabaseService
        .from('commits')
        .update({ proof_status: 'checkpointed_published' })
        .eq('checkpoint_id', checkpoint.checkpoint_id);
    }

    console.log(`[checkpoint] ${checkpoint.checkpoint_id} pos=${checkpoint.log_position} tree_root=${checkpoint.tree_root.slice(0,12)}... github=${githubResult.published}`);

    // ── Phase 4A: broadcast to witnesses (non-blocking) ──────────────────────
    broadcastToWitnesses(supabaseService, checkpoint, getServerPublicKeyPem())
      .then(r => console.log(`[witness] Broadcast complete: ${r.sent} witnesses`))
      .catch(e => console.error('[witness] Broadcast error:', e.message));

    return { checkpoint, github: githubResult };

  } catch (err) {
    console.error('[checkpoint] Error:', err.message);
    return { published: false, error: err.message };
  }
}

function startCheckpointScheduler(supabaseService) {
  setTimeout(() => publishCheckpoint(supabaseService), 8000);
  setInterval(()  => publishCheckpoint(supabaseService), INTERVAL_MS);
  console.log(`[checkpoint] Scheduler started — interval ${INTERVAL_MS / 1000}s`);
}

module.exports = { publishCheckpoint, startCheckpointScheduler, publishToGitHub };
