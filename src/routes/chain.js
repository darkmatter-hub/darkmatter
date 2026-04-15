// ============================================================
// PHASE 3: Multi-agent decision lineage / chain tracing
//
// POST /chain              — create or extend a decision chain
// GET  /chain/:chain_id    — retrieve full chain with integrity
// GET  /chain/:chain_id/export — download chain proof bundle
//
// A "chain" is an ordered sequence of records linked by
// parent_record_id. Each step records which agent acted,
// what it received (input), what it produced (output),
// and which record it was responding to.
//
// This answers: "Agent A decided X. Agent B received X and
// decided Y. Agent C received Y and decided Z. Here is the
// full traceable lineage, independently verifiable at each step."
// ============================================================

const express = require('express');
const crypto  = require('crypto');
const router  = express.Router();

// ------------------------------------------------------------------
// Helper: hash a chain step (same algorithm as /record)
// ------------------------------------------------------------------
function hashStep(fields) {
  const canonical = JSON.stringify({
    agent:            fields.agent     || null,
    model:            fields.model     || null,
    input:            fields.input     || null,
    output:           fields.output    || null,
    timestamp:        fields.timestamp,
    parent_record_id: fields.parent_record_id || null,
    chain_id:         fields.chain_id  || null,
    step_index:       fields.step_index,
  });
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

// ------------------------------------------------------------------
// Resolve API key to workspace_id (shared helper pattern)
// ------------------------------------------------------------------
async function resolveWorkspace(supabase, req) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const apiKey = authHeader.slice(7);
  try {
    const { data } = await supabase
      .from('user_recording_keys')
      .select('workspace_id')
      .eq('api_key', apiKey)
      .eq('is_active', true)
      .single();
    return data ? data.workspace_id : null;
  } catch (_) {
    return null;
  }
}

// ------------------------------------------------------------------
// POST /chain
//
// Create a new chain step or extend an existing chain.
//
// Body:
//   chain_id         — omit to start a new chain; include to extend
//   agent            — name/id of the acting agent
//   model            — model used
//   input            — what this agent received
//   output           — what this agent produced
//   parent_record_id — id of the record this step responds to (optional)
//   metadata         — any additional context
//
// Response:
//   { record_id, chain_id, step_index, hash, timestamp, verification_url }
// ------------------------------------------------------------------
router.post('/chain', async (req, res) => {
  const supabase = req.app.get('supabase');
  const workspaceId = await resolveWorkspace(supabase, req);

  const { chain_id, agent, model, input, output, parent_record_id, metadata } = req.body;

  if (!input || !output) {
    return res.status(400).json({
      error: 'missing_fields',
      message: 'Both input and output are required.',
    });
  }

  // Determine step_index: count existing steps in this chain
  let resolvedChainId = chain_id || crypto.randomUUID();
  let stepIndex = 0;

  if (chain_id) {
    const { count } = await supabase
      .from('commits')
      .select('id', { count: 'exact', head: true })
      .eq('chain_id', chain_id);
    stepIndex = count || 0;
  }

  const timestamp = new Date().toISOString();
  const recordHash = hashStep({
    agent, model, input, output, timestamp,
    parent_record_id: parent_record_id || null,
    chain_id: resolvedChainId,
    step_index: stepIndex,
  });

  const record = {
    workspace_id:      workspaceId,
    agent_name:        agent || 'unknown',
    model:             model || 'unknown',
    input:             typeof input === 'string' ? input : JSON.stringify(input),
    output:            typeof output === 'string' ? output : JSON.stringify(output),
    metadata:          { ...(metadata || {}), step_index: stepIndex, parent_record_id: parent_record_id || null },
    capture_mode:      'direct',
    payload_protection:'plaintext',
    record_hash:       recordHash,
    chain_id:          resolvedChainId,
    parent_record_id:  parent_record_id || null,
    step_index:        stepIndex,
    created_at:        timestamp,
  };

  const { data, error } = await supabase
    .from('commits')
    .insert([record])
    .select('id')
    .single();

  if (error) {
    console.error('[/chain POST] insert error:', error.message);
    return res.status(500).json({ error: 'insert_failed', message: 'Failed to record chain step.' });
  }

  return res.status(201).json({
    record_id:        data.id,
    chain_id:         resolvedChainId,
    step_index:       stepIndex,
    hash:             recordHash,
    timestamp,
    verification_url: `https://darkmatterhub.ai/verify/${data.id}`,
    chain_url:        `https://darkmatterhub.ai/chain/${resolvedChainId}`,
  });
});

// ------------------------------------------------------------------
// GET /chain/:chain_id
//
// Return all steps in a chain in order, with per-step integrity.
// Public — no auth required (verifiers need access without login).
// ------------------------------------------------------------------
router.get('/chain/:chain_id', async (req, res) => {
  const supabase = req.app.get('supabase');
  const { chain_id } = req.params;

  const { data: steps, error } = await supabase
    .from('commits')
    .select('id, agent_name, model, input, output, metadata, capture_mode, record_hash, chain_id, parent_record_id, step_index, created_at')
    .eq('chain_id', chain_id)
    .order('step_index', { ascending: true });

  if (error || !steps || steps.length === 0) {
    return res.status(404).json({ error: 'not_found', message: `No chain found: ${chain_id}` });
  }

  // Verify integrity of each step
  const verifiedSteps = steps.map(step => {
    let integrity = null;
    if (step.record_hash) {
      const canonical = JSON.stringify({
        agent:            step.agent_name     || null,
        model:            step.model          || null,
        input:            step.input          || null,
        output:           step.output         || null,
        timestamp:        step.created_at,
        parent_record_id: step.parent_record_id || null,
        chain_id:         step.chain_id,
        step_index:       step.step_index,
      });
      const computed = crypto.createHash('sha256').update(canonical).digest('hex');
      integrity = {
        valid:         computed === step.record_hash,
        stored_hash:   step.record_hash,
        computed_hash: computed,
      };
    }

    return {
      step_index:       step.step_index,
      record_id:        step.id,
      timestamp:        step.created_at,
      agent:            step.agent_name,
      model:            step.model,
      input:            step.input,
      output:           step.output,
      parent_record_id: step.parent_record_id,
      capture_mode:     step.capture_mode,
      integrity,
    };
  });

  const allValid = verifiedSteps.every(s => s.integrity === null || s.integrity.valid);

  return res.json({
    chain_id,
    step_count:               verifiedSteps.length,
    chain_integrity_valid:    allValid,
    first_step_at:            verifiedSteps[0]?.timestamp,
    last_step_at:             verifiedSteps[verifiedSteps.length - 1]?.timestamp,
    steps:                    verifiedSteps,
    verified_at:              new Date().toISOString(),
  });
});

// ------------------------------------------------------------------
// GET /chain/:chain_id/export
//
// Self-contained proof bundle for the entire chain.
// Includes embedded standalone verifier.
// Suitable for legal/compliance delivery.
// ------------------------------------------------------------------
router.get('/chain/:chain_id/export', async (req, res) => {
  const supabase = req.app.get('supabase');
  const { chain_id } = req.params;

  const { data: steps, error } = await supabase
    .from('commits')
    .select('id, agent_name, model, input, output, metadata, capture_mode, payload_protection, record_hash, chain_id, parent_record_id, step_index, created_at')
    .eq('chain_id', chain_id)
    .order('step_index', { ascending: true });

  if (error || !steps || steps.length === 0) {
    return res.status(404).json({ error: 'not_found', message: `No chain found: ${chain_id}` });
  }

  const standaloneVerifier = `#!/usr/bin/env python3
"""
DarkMatter standalone chain verifier.
No dependencies. No network calls. No DarkMatter account required.

Usage:
    python3 verify_chain.py chain_bundle.json
"""
import json, hashlib, sys

def verify_chain(bundle_path):
    with open(bundle_path) as f:
        bundle = json.load(f)

    steps = bundle["chain"]["steps"]
    print(f"Chain ID  : {bundle['chain']['chain_id']}")
    print(f"Steps     : {len(steps)}")
    print()

    all_valid = True
    for step in steps:
        canonical = json.dumps({
            "agent":            step.get("agent"),
            "model":            step.get("model"),
            "input":            step.get("input"),
            "output":           step.get("output"),
            "timestamp":        step.get("timestamp"),
            "parent_record_id": step.get("parent_record_id"),
            "chain_id":         bundle["chain"]["chain_id"],
            "step_index":       step.get("step_index"),
        }, separators=(",", ":"))

        computed = hashlib.sha256(canonical.encode()).hexdigest()
        stored   = step.get("record_hash")
        valid    = computed == stored

        if not valid:
            all_valid = False

        status = "✓" if valid else "✗ FAILED"
        print(f"  Step {step['step_index']} [{step['agent']}] {status}")

    print()
    if all_valid:
        print("✓ CHAIN INTEGRITY VERIFIED — all steps are unmodified.")
    else:
        print("✗ CHAIN INTEGRITY FAILED — one or more steps may have been tampered with.")
        sys.exit(1)

if __name__ == "__main__":
    verify_chain(sys.argv[1] if len(sys.argv) > 1 else "chain_bundle.json")
`;

  const bundle = {
    bundle_version: '1.0',
    bundle_type:    'darkmatter_chain_proof_bundle',
    exported_at:    new Date().toISOString(),
    exported_by:    'darkmatterhub.ai',
    chain: {
      chain_id:    chain_id,
      step_count:  steps.length,
      first_step:  steps[0]?.created_at,
      last_step:   steps[steps.length - 1]?.created_at,
      steps: steps.map(s => ({
        step_index:       s.step_index,
        record_id:        s.id,
        timestamp:        s.created_at,
        agent:            s.agent_name,
        model:            s.model,
        input:            s.input,
        output:           s.output,
        parent_record_id: s.parent_record_id,
        capture_mode:     s.capture_mode,
        payload_protection: s.payload_protection,
        record_hash:      s.record_hash,
      })),
    },
    verifier: {
      description: 'Standalone Python chain verifier — no dependencies, no network calls.',
      usage:       'python3 verify_chain.py chain_bundle.json',
      script:      standaloneVerifier,
    },
    disclaimer: 'This bundle was exported from DarkMatter. Each step hash was computed at ingestion and is not controlled by the model provider or the deploying organization.',
  };

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="darkmatter-chain-${chain_id}.json"`);
  return res.json(bundle);
});

module.exports = router;
