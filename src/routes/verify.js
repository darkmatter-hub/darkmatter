// ============================================================
// PHASE 2: Public verification + proof bundle export
//
// GET  /verify/:id        — anyone can verify a record, no login
// GET  /verify/:id/bundle — download a self-contained proof bundle
//
// These are intentionally public (no auth required).
// That is the independence guarantee made concrete:
// a third party — regulator, auditor, client, court —
// can verify a record without asking DarkMatter, the model
// provider, or the client's infrastructure to vouch for it.
// ============================================================

const express = require('express');
const crypto  = require('crypto');
const router  = express.Router();

// ------------------------------------------------------------------
// Recompute the hash from stored fields and compare.
// Returns { valid: bool, stored_hash, computed_hash }
// ------------------------------------------------------------------
function verifyIntegrity(record) {
  const canonical = JSON.stringify({
    agent:     record.agent_name || null,
    model:     record.model      || null,
    input:     record.input      || null,
    output:    record.output     || null,
    timestamp: record.created_at,
  });
  const computed = crypto.createHash('sha256').update(canonical).digest('hex');
  return {
    valid:         computed === record.record_hash,
    stored_hash:   record.record_hash,
    computed_hash: computed,
  };
}

// ------------------------------------------------------------------
// GET /verify/:id
//
// Public. No auth. Returns full record + integrity proof.
// This is the shareable verification URL returned by POST /record.
//
// Response shape:
// {
//   id, timestamp, agent, model, capture_mode,
//   integrity: { valid, stored_hash, computed_hash },
//   payload: { input, output, metadata },
//   verification_performed_at: <ISO>
// }
// ------------------------------------------------------------------
router.get('/verify/:id', async (req, res) => {
  const supabase = req.app.get('supabase');
  const { id } = req.params;

  const { data: record, error } = await supabase
    .from('commits')
    .select('id, workspace_id, agent_name, model, input, output, metadata, capture_mode, payload_protection, record_hash, created_at')
    .eq('id', id)
    .single();

  if (error || !record) {
    return res.status(404).json({
      error: 'not_found',
      message: `No record found for id: ${id}`,
    });
  }

  // Only verify records that have a stored hash (Phase 1+ records).
  // Older dm.commit records without record_hash return integrity: null.
  const integrity = record.record_hash
    ? verifyIntegrity(record)
    : null;

  return res.json({
    id:                        record.id,
    timestamp:                 record.created_at,
    agent:                     record.agent_name,
    model:                     record.model,
    capture_mode:              record.capture_mode,
    payload_protection:        record.payload_protection,
    integrity,
    payload: {
      input:    record.input,
      output:   record.output,
      metadata: record.metadata,
    },
    verification_performed_at: new Date().toISOString(),
    verified_by:               'darkmatterhub.ai',
    note: integrity && !integrity.valid
      ? 'INTEGRITY CHECK FAILED: the stored hash does not match the record content. This record may have been tampered with.'
      : null,
  });
});

// ------------------------------------------------------------------
// GET /verify/:id/bundle
//
// Public. No auth.
// Returns a self-contained JSON proof bundle suitable for:
//   - attaching to a legal filing
//   - including in an audit package
//   - running through the standalone Python verifier
//
// The bundle is intentionally self-contained: the verifier script
// and all data needed to re-run the check are included in one file.
// ------------------------------------------------------------------
router.get('/verify/:id/bundle', async (req, res) => {
  const supabase = req.app.get('supabase');
  const { id } = req.params;

  const { data: record, error } = await supabase
    .from('commits')
    .select('id, agent_name, model, input, output, metadata, capture_mode, payload_protection, record_hash, created_at')
    .eq('id', id)
    .single();

  if (error || !record) {
    return res.status(404).json({ error: 'not_found', message: `No record found for id: ${id}` });
  }

  const integrity = record.record_hash ? verifyIntegrity(record) : null;

  // The standalone verifier is embedded in the bundle so the recipient
  // can verify without any dependency on DarkMatter's infrastructure.
  const standaloneVerifier = `#!/usr/bin/env python3
"""
DarkMatter standalone record verifier.
No dependencies. No network calls. No DarkMatter account required.

Usage:
    python3 verify.py bundle.json

The bundle is self-contained. This script recomputes the SHA-256 hash
from the record's canonical fields and compares it to the stored hash.
"""
import json, hashlib, sys

def verify(bundle_path):
    with open(bundle_path) as f:
        bundle = json.load(f)

    record = bundle["record"]
    canonical = json.dumps({
        "agent":     record.get("agent"),
        "model":     record.get("model"),
        "input":     record.get("input"),
        "output":    record.get("output"),
        "timestamp": record.get("timestamp"),
    }, separators=(",", ":"))

    computed = hashlib.sha256(canonical.encode()).hexdigest()
    stored   = record.get("record_hash")

    print(f"Record ID : {record['id']}")
    print(f"Timestamp : {record['timestamp']}")
    print(f"Stored    : {stored}")
    print(f"Computed  : {computed}")
    print()

    if computed == stored:
        print("✓ INTEGRITY VERIFIED — record has not been modified.")
    else:
        print("✗ INTEGRITY FAILED — stored hash does not match record content.")
        sys.exit(1)

if __name__ == "__main__":
    verify(sys.argv[1] if len(sys.argv) > 1 else "bundle.json")
`;

  const bundle = {
    bundle_version:   '1.0',
    bundle_type:      'darkmatter_proof_bundle',
    exported_at:      new Date().toISOString(),
    exported_by:      'darkmatterhub.ai',
    record: {
      id:               record.id,
      timestamp:        record.created_at,
      agent:            record.agent_name,
      model:            record.model,
      input:            record.input,
      output:           record.output,
      metadata:         record.metadata,
      capture_mode:     record.capture_mode,
      payload_protection: record.payload_protection,
      record_hash:      record.record_hash,
    },
    integrity,
    verifier: {
      description: 'Standalone Python verifier — no dependencies, no network calls.',
      usage:       'python3 verify.py bundle.json',
      script:      standaloneVerifier,
    },
    disclaimer: 'This bundle was exported from DarkMatter, an independent verification layer. The hash was computed at ingestion time and is not controlled by the model provider or the deploying organization.',
  };

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="darkmatter-proof-${id}.json"`);
  return res.json(bundle);
});

module.exports = router;
