# DarkMatter — Phase Implementation Status

**Last updated:** 2026-04-09  
**Spec version:** 1.0 (frozen)

---

## Phase 1 — Client-Side Hashing + Agent Signatures ✅ COMPLETE

**What it means:** Payload hashes are computed by the SDK before transmission. Agents sign the full commit envelope with their own Ed25519 private key. The server validates but cannot forge.

**What you can claim:**
- Commits are hashed client-side before transmission
- Agents sign the full commit envelope (payload + parent + agent_id + key_id + timestamp)
- Records are verifiable offline without DarkMatter servers
- Missing integrity fields fail verification by default

**Key files:**
- `src/integrity.js` — canonical serialization, envelope hashing, chain verify
- `client/darkmatter.py` — Python SDK with client-side hashing
- `sdk/typescript/src/integrity.ts` — TypeScript port
- `github-template/verify_darkmatter_chain.py` — offline verifier
- `github-template/integrity_test_vectors.json` — 18 cross-language test vectors (all pass)

**Test:** `npm test` in `sdk/typescript/` → 46/46 pass

---

## Phase 2 — Append-Only Log + Signed Checkpoints ✅ COMPLETE

**What it means:** Every commit is appended to a sequential, append-only log in Supabase (no UPDATE/DELETE RLS policies). Every 10 minutes, DarkMatter signs the log root and publishes the checkpoint to GitHub.

**What you can claim:**
- DarkMatter cannot silently delete or rewrite a commit without the log root changing
- Checkpoints are published to a surface DarkMatter cannot unilaterally modify
- Anyone holding a checkpoint can verify all subsequent checkpoints are consistent

**Key files:**
- `src/append-log.js` — append-only log with running log root hash
- `src/checkpoint.js` — checkpoint publisher (GitHub + DB)
- `supabase/schema_integrity_v1.sql` — `log_entries` table with append-only RLS

**Public endpoints (no auth):**
- `GET /api/log/pubkey` — DarkMatter server Ed25519 public key
- `GET /api/log/checkpoint` — latest signed checkpoint
- `GET /api/log/checkpoints` — recent checkpoints

**Published checkpoints:** https://github.com/darkmatter-hub/checkpoints

---

## Phase 3 — Merkle Inclusion Proofs ✅ COMPLETE

**What it means:** Every commit gets a Merkle inclusion proof at commit time. The tree root is signed into checkpoints. Export bundles are self-sufficient for fully offline verification.

**What you can claim:**
- Every commit returns a cryptographic receipt with Merkle inclusion proof
- Proof can be verified offline against any published checkpoint
- Export bundles contain everything needed — no DarkMatter servers required for verification

**Leaf spec (frozen):**
```
leaf_hash = SHA256(0x00 || UTF8(canonical({accepted_at, commit_id, integrity_hash, log_position})))
```

**Key files:**
- `src/merkle.js` — RFC 6962 Merkle tree, inclusion proofs, consistency proofs
- `github-template/merkle_test_vectors.json` — 11 vectors (all pass in JS + Python)
- `supabase/schema_phase3.sql` — adds `leaf_hash`, `tree_root` to log_entries

**Public endpoints:**
- `GET /api/log/proof/:commitId` — inclusion proof for any commit
- `GET /api/export/:ctxId` — self-sufficient proof bundle (v3.0)

**Verifier usage:**
```bash
python verify_darkmatter_chain.py bundle.json
# Phase 1 — Chain integrity:  ✓ PASS
# Phase 2 — Checkpoint sig:   ✓ PASS
# Phase 3 — Merkle inclusion: ✓ PASS
```

---

## Phase 3.5 — Checkpoint Consistency ✅ COMPLETE

**What it means:** Proves checkpoint B is an append-only extension of checkpoint A. No entries were deleted or rewritten between the two snapshots.

**What you can claim:**
- Checkpoint continuity and root correctness between snapshots is verifiable
- (Note: this is recomputation-based consistency, not compact RFC 6962 consistency proofs)

**Public endpoint:**
- `GET /api/log/consistency?from=first&to=latest`

**Verifier usage:**
```bash
python verify_darkmatter_chain.py bundle.json \
  --checkpoint old_checkpoint.json \
  --checkpoint-b new_checkpoint.json \
  --pubkey server_pubkey.pem
```

---

## Pre-Phase-4 Hardening ✅ COMPLETE

Three hardening items completed before external witnesses:

**1. Dual timestamps**
- `client_timestamp` — what the agent asserted (in signed envelope)
- `accepted_at` — when the server ledger accepted (used in Merkle leaf)
These are never conflated. Both appear in proof receipts.

**2. Key lifecycle**
- `src/keys.js` — `registerKey`, `rotateKey`, `revokeKey`, `getKeyAtTime`
- `getKeyAtTime(agentId, keyId, acceptedAt)` — historical key lookup for offline verification after rotation
- Signature states: `valid`, `revoked_key`, `revoked_post_commit`, `invalid`
- `supabase/schema_hardening.sql` — `key_events` table (immutable audit log)

**API endpoints:**
- `POST /api/agents/keys` — register public key
- `POST /api/agents/keys/rotate` — rotate (old key stays valid for historical commits)
- `POST /api/agents/keys/revoke` — revoke (flags historical commits)
- `GET /api/agents/:agentId/pubkey?at=<ISO>` — historical key lookup

**3. Frozen Spec v1**
- `INTEGRITY_SPEC_V1.md` — complete frozen protocol specification
- Every commit records `spec_version: "1.0"`
- `spec_versions` table in Supabase is the authoritative registry

---

## Phase 4A — External Witness ✅ COMPLETE (infrastructure live)

**What it means:** An independent witness server co-signs each checkpoint with its own Ed25519 key. DarkMatter cannot produce a valid witness signature. Tampering requires compromising both DarkMatter and every witness.

**What you can claim:**
- Each checkpoint is co-signed by an independently operated witness
- Any attempt to rewrite history requires compromising both DarkMatter and the witness infrastructure
- Witness signatures are verifiable offline using only the witness public key

**What you cannot yet claim (Phase 4B):**
- Independent log reconstruction by the witness
- Censorship resistance
- Multi-party consensus

**Witness infrastructure:**
- `src/witness.js` — `registerWitness`, `broadcastToWitnesses`, `acceptWitnessSignature`, `verifyWitnessSignature`
- `witness-server/app.py` — standalone witness server (Railway deployed)
- Witness endpoint: https://witness-server-production.up.railway.app/witness
- Registered witness: `wit_bd46a5a1d670bfb7` — DarkMatter Witness Node 1

**Security properties of witness server:**
- Pins DarkMatter public key from `DARKMATTER_PUBKEY` env var (prevents fake checkpoint attack)
- Replay protection: refuses to sign `log_position <= last_signed`
- Rate limiting: 10 requests/minute per IP
- Append-only local witness log at `/app/witness_log.jsonl`

**API endpoints:**
- `GET /api/witnesses` — list active witnesses (public)
- `GET /api/witnesses/:witnessId/pubkey` — witness public key (public)
- `POST /api/witness/sign` — submit witness signature
- `GET /api/log/checkpoint/:id/witnesses` — witness sigs on checkpoint (public)

**Verifier usage:**
```bash
python verify_darkmatter_chain.py bundle.json
# Phase 4A— Witness signatures: ✓ PASS (1/1)
```

**supabase/schema_phase4a.sql** — `witnesses` and `witness_sigs` tables

---

## Validation

Run the full phase validation suite:

```bash
# Test vectors only (no network)
python github-template/validate_phases.py --test-vectors-only --vectors-dir github-template/

# Against a live system
python github-template/validate_phases.py \
  --api-key dm_sk_... \
  --base-url https://darkmatterhub.ai

# Against an exported proof bundle
python github-template/validate_phases.py --bundle export.json
```

Run TypeScript integrity tests:
```bash
cd sdk/typescript && npm test
# ✓ All 46 tests passed
```

---

## What's Next — Phase 4B

Phase 4B adds true independence:
- Witnesses reconstruct the Merkle tree from raw leaf data (not just co-sign)
- Multi-witness quorum (2-of-3 signing requirement)
- Witnesses cross-verify each other
- Optional blockchain anchoring

**Gate for Phase 4B:** at least one external organisation (not operated by DarkMatter) running a witness node.

---

## Summary Table

| Phase | Description | Status | Claim |
|-------|-------------|--------|-------|
| 1 | Client-side hashing + envelope signatures | ✅ Complete | "Commits are hashed and signed client-side" |
| 2 | Append-only log + signed checkpoints | ✅ Complete | "We cannot silently rewrite history" |
| 3 | Merkle inclusion proofs | ✅ Complete | "You don't need to trust us at all" |
| 3.5 | Checkpoint consistency | ✅ Complete | "Checkpoint continuity is verifiable" |
| Pre-4 | Dual timestamps + key lifecycle + frozen spec | ✅ Complete | "Protocol is stable for external witnesses" |
| 4A | External witness co-signing | ✅ Live | "Tampering requires compromising both DarkMatter and witnesses" |
| 4B | Independent log reconstruction + quorum | 🔲 Planned | "Neutral infrastructure layer" |
