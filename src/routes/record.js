// ============================================================
// PHASE 1: Zero-config agent ingestion endpoint
// POST /record
//
// Wraps dm.commit with a flat, agent-friendly payload schema.
// No UI interaction required. Works with or without a workspace.
// Existing dm.commit logic is unchanged — this is a thin adapter.
// ============================================================

const express = require('express');
const crypto = require('crypto');
const router = express.Router();

// ------------------------------------------------------------------
// Helper: build a SHA-256 hash of the record's canonical fields.
// This is the tamper-evidence primitive for Phase 2 verification.
// ------------------------------------------------------------------
function buildRecordHash(fields) {
  const canonical = JSON.stringify({
    agent:     fields.agent     || null,
    model:     fields.model     || null,
    input:     fields.input     || null,
    output:    fields.output    || null,
    timestamp: fields.timestamp,
  });
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

// ------------------------------------------------------------------
// POST /record
//
// Minimal required fields: input, output
// Optional: agent, model, metadata, workspace_id, session_id
//
// Returns: { id, hash, timestamp, verification_url }
//
// Design principles:
//   - No auth required for free tier (API key optional in header)
//   - capture_mode = 'direct' (agent pushed this directly)
//   - payload_protection = 'plaintext' unless client specifies
//   - One round-trip from any agent in any language
// ------------------------------------------------------------------
router.post('/record', async (req, res) => {
  const supabase = req.app.get('supabase');

  // --- Validate minimum payload ---
  const { input, output, agent, model, metadata, workspace_id, session_id } = req.body;

  if (!input || !output) {
    return res.status(400).json({
      error: 'missing_fields',
      message: 'Both input and output are required.',
      docs: 'https://darkmatterhub.ai/docs/record',
    });
  }

  // --- Resolve workspace ---
  // API key in Authorization header resolves to a workspace.
  // If missing, records land in the anonymous free-tier bucket.
  let resolvedWorkspaceId = workspace_id || null;
  const authHeader = req.headers['authorization'];

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const apiKey = authHeader.slice(7);
    try {
      const { data: keyRow } = await supabase
        .from('user_recording_keys')
        .select('workspace_id, user_id')
        .eq('api_key', apiKey)
        .eq('is_active', true)
        .single();

      if (keyRow) {
        resolvedWorkspaceId = keyRow.workspace_id;
      }
    } catch (_) {
      // Key not found — continue as anonymous
    }
  }

  // --- Build record ---
  const timestamp = new Date().toISOString();
  const recordHash = buildRecordHash({ agent, model, input, output, timestamp });

  const record = {
    workspace_id:      resolvedWorkspaceId,
    session_id:        session_id || null,
    agent_name:        agent || 'unknown',
    model:             model || 'unknown',
    input:             typeof input === 'string' ? input : JSON.stringify(input),
    output:            typeof output === 'string' ? output : JSON.stringify(output),
    metadata:          metadata || {},
    capture_mode:      'direct',          // agent pushed this directly
    payload_protection:'plaintext',       // default; clients can override via metadata
    record_hash:       recordHash,
    created_at:        timestamp,
  };

  // --- Insert into commits table (reuses existing schema) ---
  const { data, error } = await supabase
    .from('commits')
    .insert([record])
    .select('id')
    .single();

  if (error) {
    console.error('[/record] insert error:', error.message);
    return res.status(500).json({
      error: 'insert_failed',
      message: 'Failed to record agent action.',
    });
  }

  const id = data.id;

  return res.status(201).json({
    id,
    hash:             recordHash,
    timestamp,
    capture_mode:     'direct',
    verification_url: `https://darkmatterhub.ai/verify/${id}`,
  });
});

module.exports = router;
