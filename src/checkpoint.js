/**
 * DarkMatter Checkpoint Publisher (Phase 2 → 4)
 * ===============================================
 * Periodically publishes signed log checkpoints to external surfaces
 * that DarkMatter cannot unilaterally modify.
 *
 * Phase 2: Publish to a public GitHub repository (via GitHub API)
 * Phase 3: Add Merkle root to checkpoint, include in exports
 * Phase 4: Add witness co-signatures + optional blockchain anchoring
 *
 * Checkpoint format:
 * {
 *   "version":   "2",
 *   "timestamp": "ISO-8601",
 *   "position":  48291,          -- log entry count
 *   "log_root":  "sha256:abc...", -- running hash of entire log
 *   "tree_root": "sha256:xyz...", -- Merkle root (Phase 3+)
 *   "server_sig": "hex...",       -- Ed25519 over canonical(checkpoint)
 *   "pubkey_url": "https://darkmatterhub.ai/api/log/pubkey"
 * }
 *
 * Anyone holding a checkpoint from any point in time can verify that
 * every subsequent checkpoint is consistent — no entries were deleted.
 */

'use strict';

const crypto = require('crypto');
const https  = require('https');
const { canonicalize }        = require('./integrity');
const { signCheckpoint, getServerPublicKeyPem } = require('./append-log');

const CHECKPOINT_INTERVAL_MS = 10 * 60 * 1000; // every 10 minutes

// ─────────────────────────────────────────────────────────────────────────────
// CHECKPOINT CONSTRUCTION
// ─────────────────────────────────────────────────────────────────────────────

function buildCheckpoint(position, logRoot, treeRoot = null) {
  const timestamp = new Date().toISOString();
  const checkpoint = {
    version:    '2',
    timestamp,
    position,
    log_root:   'sha256:' + logRoot,
    ...(treeRoot ? { tree_root: 'sha256:' + treeRoot } : {}),
    pubkey_url: 'https://darkmatterhub.ai/api/log/pubkey',
  };

  // Sign the canonical form of the checkpoint (without the sig field)
  const message    = canonicalize(checkpoint);
  const { privateKey } = require('./append-log').getServerKey
    ? { privateKey: null } : { privateKey: null }; // accessed via signCheckpoint
  const serverSig  = signCheckpoint(logRoot, position, timestamp);

  return { ...checkpoint, server_sig: serverSig };
}

// ─────────────────────────────────────────────────────────────────────────────
// GITHUB PUBLISHER
// Commits the checkpoint JSON to a public repository.
// DarkMatter cannot delete GitHub commit history — making this tamper-evident.
// ─────────────────────────────────────────────────────────────────────────────

async function publishToGitHub(checkpoint) {
  const token = process.env.DM_GITHUB_TOKEN;
  const repo  = process.env.DM_GITHUB_CHECKPOINT_REPO; // e.g. "darkmatter-hub/checkpoints"
  if (!token || !repo) {
    console.log('[checkpoint] GitHub publishing skipped — DM_GITHUB_TOKEN or DM_GITHUB_CHECKPOINT_REPO not set');
    return { published: false, reason: 'not_configured' };
  }

  const [owner, repoName] = repo.split('/');
  const filename  = `checkpoints/${checkpoint.timestamp.replace(/[:.]/g, '-')}.json`;
  const content   = Buffer.from(JSON.stringify(checkpoint, null, 2)).toString('base64');
  const message   = `checkpoint: position=${checkpoint.position} root=${checkpoint.log_root.slice(0, 16)}...`;

  const body = JSON.stringify({ message, content });

  return new Promise((resolve) => {
    const req = https.request({
      hostname: 'api.github.com',
      path:     `/repos/${owner}/${repoName}/contents/${filename}`,
      method:   'PUT',
      headers:  {
        'Authorization': `Bearer ${token}`,
        'Content-Type':  'application/json',
        'User-Agent':    'darkmatter-checkpoint/1.0',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        const ok = res.statusCode >= 200 && res.statusCode < 300;
        resolve({ published: ok, status: res.statusCode, url: `https://github.com/${repo}/blob/main/${filename}` });
      });
    });
    req.on('error', err => resolve({ published: false, error: err.message }));
    req.write(body);
    req.end();
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN SCHEDULER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fetch the latest log state, build a checkpoint, and publish it.
 * Called on a timer and also on-demand via POST /api/log/checkpoint.
 */
async function publishCheckpoint(supabaseService) {
  try {
    // Get latest log entry
    const { data: latest } = await supabaseService
      .from('log_entries')
      .select('position, log_root, timestamp')
      .order('position', { ascending: false })
      .limit(1)
      .single();

    if (!latest) {
      console.log('[checkpoint] No log entries yet — skipping checkpoint');
      return { published: false, reason: 'no_entries' };
    }

    const checkpoint = buildCheckpoint(latest.position, latest.log_root);

    // Store in DB (so API can serve it)
    await supabaseService.from('checkpoints').insert({
      position:    checkpoint.position,
      log_root:    checkpoint.log_root,
      tree_root:   checkpoint.tree_root || null,
      server_sig:  checkpoint.server_sig,
      timestamp:   checkpoint.timestamp,
      published:   false,
    });

    // Publish to GitHub
    const githubResult = await publishToGitHub(checkpoint);

    if (githubResult.published) {
      await supabaseService
        .from('checkpoints')
        .update({ published: true, published_url: githubResult.url })
        .eq('position', checkpoint.position);
    }

    console.log(`[checkpoint] Published position=${checkpoint.position} github=${githubResult.published}`);
    return { checkpoint, github: githubResult };

  } catch (err) {
    console.error('[checkpoint] Error publishing checkpoint:', err.message);
    return { published: false, error: err.message };
  }
}

/**
 * Start the checkpoint scheduler.
 * Call once at server startup.
 */
function startCheckpointScheduler(supabaseService) {
  // Publish immediately on startup, then every CHECKPOINT_INTERVAL_MS
  setTimeout(() => publishCheckpoint(supabaseService), 5000);
  setInterval(() => publishCheckpoint(supabaseService), CHECKPOINT_INTERVAL_MS);
  console.log(`[checkpoint] Scheduler started — interval: ${CHECKPOINT_INTERVAL_MS / 1000}s`);
}

module.exports = {
  buildCheckpoint,
  publishCheckpoint,
  startCheckpointScheduler,
  publishToGitHub,
};
