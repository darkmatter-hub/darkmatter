/**
 * darkmatter-js — TypeScript/Node.js SDK v1.2.0
 * ===============================================
 * Phase 1: client-side hashing + envelope signing
 * Phase 2: append-only log + signed checkpoints
 * Phase 3: Merkle inclusion proofs + offline bundle verification
 *
 * npm install darkmatter-js
 * Node.js 18+ required (native fetch)
 */

// ── Re-export all crypto primitives ──────────────────────────────────────────
export {
  SCHEMA_VERSION,
  canonicalize,
  hashPayload,
  buildEnvelope,
  hashEnvelope,
  computeIntegrityHash,
  validateClientHashes,
  verifyEnvelopeSignature,
  verifyChain,
  stripPrefix,
  runTestVectors,
} from './integrity';

export type {
  CommitEnvelope,
  ChainVerifyResult,
  ChainStep,
  ClientHashValidation,
  CommitRecord,
  TestResult,
} from './integrity';

import {
  hashPayload,
  buildEnvelope,
  hashEnvelope,
  computeIntegrityHash,
  verifyChain,
  stripPrefix,
} from './integrity';

import type { CommitEnvelope, ChainVerifyResult } from './integrity';
import { createHash, createPublicKey, verify as cryptoVerify } from 'crypto';

// ─────────────────────────────────────────────────────────────────────────────
// TYPES — PHASE 3 COMPLETE
// ─────────────────────────────────────────────────────────────────────────────

export interface InclusionProofStep {
  hash:      string;   // hex
  direction: 'left' | 'right';
}

export interface InclusionProof {
  leaf_index: number;
  tree_size:  number;
  proof:      InclusionProofStep[];
}

/** Returned on every commit. Contains full Merkle inclusion proof. */
export interface ProofReceipt {
  log_position:    number;
  leaf_hash:       string;   // hex
  tree_root:       string;   // hex
  tree_size:       number;
  accepted_at:     string;
  inclusion_proof: InclusionProof;
  proof_status:    'pending' | 'included' | 'checkpointed' | 'checkpointed_published' | 'proof_unavailable';
  pubkey_url:      string;
  checkpoint_url:  string;
  verify_url:      string;
}

export interface LogReceipt {
  position:   number;
  log_root:   string;
  timestamp:  string;
  pubkey_url: string;
}

export interface CommitReceipt {
  id:             string;
  schema_version: string;
  integrity_hash: string;
  payload_hash:   string;
  parent_hash:    string | null;
  verified:       boolean;
  timestamp:      string;
  _proof?:        ProofReceipt;    // Phase 3 — Merkle inclusion
  _log?:          LogReceipt;      // Phase 2 — log position (kept for compat)
  _warnings?:     string[];
  _envelope?:     CommitEnvelope;  // the envelope that was signed
}

/** Phase 3 signed checkpoint */
export interface Checkpoint {
  schema_version:     string;
  checkpoint_id:      string;
  tree_root:          string;
  tree_size:          number;
  log_root:           string;
  log_position:       number;
  timestamp:          string;
  previous_cp_id:     string | null;
  previous_tree_root: string | null;
  server_sig:         string;
  published?:         boolean;
  published_url?:     string;
}

/** Self-sufficient Phase 3 export bundle */
export interface ProofBundle {
  _spec: {
    bundle_version:  string;
    spec_url:        string;
    verifier_url:    string;
    verify_command:  string;
    checkpoint_repo: string;
    phases:          string[];
  };
  metadata: {
    ctx_id:       string;
    chain_length: number;
    lineage_root: string;
    trace_id:     string | null;
    exported_at:  string;
    exported_by:  string;
  };
  integrity: {
    chain_intact:    boolean;
    algorithm:       string;
    root_hash:       string | null;
    tip_hash:        string | null;
    chain_hash:      string;
    timestamp_range: { from: string; to: string };
  };
  checkpoint:   Checkpoint | null;
  server_pubkey: {
    algorithm:  string;
    public_key: string;
    use:        string;
    pubkey_url: string;
  };
  commits:      Array<CommitReceipt & { _proof?: ProofReceipt }>;
  export_hash:  string;
}

/** Result of verifying a proof bundle locally */
export interface BundleVerifyResult {
  verified:   boolean;
  structure:  ChainVerifyResult;
  merkle: {
    ok:            boolean | null;
    proofs_found:  number;
    proofs_valid:  number;
    proofs_failed: number;
  };
  checkpoint: {
    ok:       boolean | null;
    sig_ok:   boolean | null;
    chain_ok: boolean | null;
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// MERKLE VERIFICATION (mirrors merkle.js + verifier logic)
// ─────────────────────────────────────────────────────────────────────────────

function sha256hex(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/** RFC 6962 leaf hash over the canonical leaf envelope string */
function leafHashFromCommit(
  commitId:       string,
  integrityHash:  string,
  logPosition:    number,
  acceptedAt:     string,
): string {
  const ts  = (acceptedAt || '').replace(/\.\d+Z?$/, '').replace(/Z?$/, 'Z');
  const ih  = integrityHash.startsWith('sha256:') ? integrityHash.slice(7) : integrityHash;
  // Canonical leaf envelope — keys sorted: accepted_at, commit_id, integrity_hash, log_position
  const envelope = { accepted_at: ts, commit_id: commitId, integrity_hash: ih, log_position: logPosition };
  const canonical = canonicalizeObj(envelope);
  const buf = Buffer.concat([Buffer.from([0x00]), Buffer.from(canonical, 'utf8')]);
  return sha256hex(buf);
}

// Local canonicalize for the leaf envelope (4 known keys, always sorted the same way)
function canonicalizeObj(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj).sort();
  const pairs = keys.map(k => JSON.stringify(k) + ':' + JSON.stringify(obj[k]));
  return '{' + pairs.join(',') + '}';
}

function nodeHash(left: string, right: string): string {
  const buf = Buffer.concat([Buffer.from([0x01]), Buffer.from(left, 'hex'), Buffer.from(right, 'hex')]);
  return sha256hex(buf);
}

/** Verify a Merkle inclusion proof */
function verifyInclusionProof(leafH: string, proof: InclusionProof, expectedRoot: string): boolean {
  try {
    let current = leafH;
    for (const step of proof.proof) {
      current = step.direction === 'right'
        ? nodeHash(current, step.hash)
        : nodeHash(step.hash, current);
    }
    return current === expectedRoot;
  } catch { return false; }
}

/** Verify a checkpoint's Ed25519 server signature */
function verifyCheckpointSig(cp: Checkpoint, publicKeyPem: string): boolean {
  try {
    const { server_sig, published, published_url, ...rest } = cp as unknown as Record<string, unknown>;
    delete (rest as Record<string, unknown>)['note'];
    const keys    = Object.keys(rest).sort();
    const pairs   = keys.map(k => JSON.stringify(k) + ':' + JSON.stringify((rest as Record<string, unknown>)[k]));
    const message = Buffer.from('{' + pairs.join(',') + '}', 'utf8');
    const sig     = Buffer.from(cp.server_sig, 'hex');
    const pubKey  = createPublicKey(publicKeyPem);
    // Use Boolean() to ensure return type is boolean, not narrowed to true
    return Boolean(cryptoVerify(null, message, pubKey, sig));
  } catch { return false; }
}

// ─────────────────────────────────────────────────────────────────────────────
// BUNDLE VERIFICATION — fully offline, no network calls
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verify a Phase 3 proof bundle locally.
 * No network calls. No DarkMatter dependency.
 *
 * Checks:
 *   1. Chain structure (payload hashes, integrity chain)
 *   2. Per-commit Merkle inclusion proofs against tree_root
 *   3. Checkpoint signature (if server public key is in bundle)
 *
 * @param bundle    - The parsed ProofBundle object
 * @param options   - { strict: boolean } — default true
 */
export function verifyBundle(
  bundle:  ProofBundle,
  options: { strict?: boolean } = {},
): BundleVerifyResult {
  const strict = options.strict ?? true;

  // ── 1. Chain structure ────────────────────────────────────────────────────
  const commits = bundle.commits as CommitReceipt[];
  const structure = verifyChain(
    commits.map(c => {
      const raw      = c as unknown as Record<string, unknown>;
      const agentInfo = raw['agent_info'] as Record<string, unknown> | undefined;
      return {
        id:             c.id,
        payload:        (raw['payload'] ?? {}) as Record<string, unknown>,
        payload_hash:   c.payload_hash,
        integrity_hash: c.integrity_hash,
        // Check top-level agent_id first, then agent_info.id, then empty string
        agent_id:       (raw['agent_id'] as string)
                        ?? (agentInfo?.['id'] as string)
                        ?? '',
        key_id:         (raw['key_id'] as string)
                        ?? (agentInfo?.['key_id'] as string)
                        ?? 'default',
        timestamp:      c.timestamp,
      };
    }),
    { strict },
  );

  // ── 2. Merkle inclusion proofs ─────────────────────────────────────────────
  let proofsFound = 0; let proofsValid = 0; let proofsFaild = 0;
  const cpTreeRoot = bundle.checkpoint?.tree_root
    ? (bundle.checkpoint.tree_root.startsWith('sha256:')
        ? bundle.checkpoint.tree_root.slice(7)
        : bundle.checkpoint.tree_root)
    : null;

  for (const commit of commits) {
    const pr = commit._proof;
    if (!pr) continue;
    proofsFound++;

    const lhStored  = pr.leaf_hash;
    const treeRoot  = pr.tree_root?.startsWith('sha256:') ? pr.tree_root.slice(7) : (pr.tree_root || cpTreeRoot);
    const ih        = commit.integrity_hash?.startsWith('sha256:') ? commit.integrity_hash.slice(7) : commit.integrity_hash;

    // Recompute leaf hash from first principles
    let lhOk = true;
    if (lhStored && ih && pr.log_position != null) {
      const recomp = leafHashFromCommit(commit.id, ih, pr.log_position, pr.accepted_at || commit.timestamp);
      lhOk = recomp === lhStored;
    }

    // Verify inclusion proof
    const proofOk = lhStored && treeRoot && pr.inclusion_proof
      ? verifyInclusionProof(lhStored, pr.inclusion_proof, treeRoot)
      : false;

    if (lhOk && proofOk) proofsValid++;
    else proofsFaild++;
  }

  const merkleOk = proofsFound === 0 ? null : proofsFaild === 0;

  // ── 3. Checkpoint signature ───────────────────────────────────────────────
  let sigOk: boolean | null = null;
  let chainOk: true | false | null = null;

  const cp     = bundle.checkpoint;
  const pubPem = bundle.server_pubkey?.public_key;

  if (cp && pubPem) {
    try { sigOk = verifyCheckpointSig(cp, pubPem); } catch { sigOk = false; }
  }

  // Checkpoint chain linkage — just verify previous_cp_id reference exists
  // (full consistency proof requires all leaf hashes, which may not be in bundle)
  if (cp) {
    chainOk = Boolean(cp.checkpoint_id); // linkage present; full consistency proof in Phase 3.5
  }

  const verified = structure.chain_intact
    && merkleOk !== false
    && sigOk   !== false;

  return {
    verified,
    structure,
    merkle:     { ok: merkleOk, proofs_found: proofsFound, proofs_valid: proofsValid, proofs_failed: proofsFaild },
    checkpoint: { ok: sigOk !== false && chainOk !== false, sig_ok: sigOk, chain_ok: chainOk },
  };
}

/**
 * Verify a single commit receipt locally (no bundle needed).
 * Checks the proof receipt returned by commit().
 */
export function verifyReceipt(receipt: CommitReceipt): {
  ok:           boolean;
  leaf_hash_ok: boolean | null;
  proof_ok:     boolean | null;
  reason?:      string;
} {
  const pr = receipt._proof;
  if (!pr) return { ok: false, leaf_hash_ok: null, proof_ok: null, reason: 'no proof receipt' };

  const ih = receipt.integrity_hash?.startsWith('sha256:')
    ? receipt.integrity_hash.slice(7)
    : receipt.integrity_hash;

  // Recompute leaf hash
  let lhOk: boolean | null = null;
  if (pr.leaf_hash && ih && pr.log_position != null) {
    const recomp = leafHashFromCommit(receipt.id, ih, pr.log_position, pr.accepted_at || receipt.timestamp);
    lhOk = recomp === pr.leaf_hash;
  }

  // Verify inclusion proof
  let proofOk: boolean | null = null;
  const treeRoot = pr.tree_root?.startsWith('sha256:') ? pr.tree_root.slice(7) : pr.tree_root;
  if (pr.leaf_hash && treeRoot && pr.inclusion_proof?.proof) {
    proofOk = verifyInclusionProof(pr.leaf_hash, pr.inclusion_proof, treeRoot);
  }

  const ok = (lhOk !== false) && (proofOk !== false);
  return { ok, leaf_hash_ok: lhOk, proof_ok: proofOk };
}

// ─────────────────────────────────────────────────────────────────────────────
// CONFIGURATION
// ─────────────────────────────────────────────────────────────────────────────

const DM_BASE = 'https://darkmatterhub.ai';

interface SDKState {
  apiKey:        string | null;
  agentId:       string | null;
  keyId:         string;
  baseUrl:       string;
  lastCtxId:     string | null;
  lastIntegrity: string | null;
}

const state: SDKState = {
  apiKey:        null,
  agentId:       null,
  keyId:         'default',
  baseUrl:       DM_BASE,
  lastCtxId:     null,
  lastIntegrity: null,
};

export function configure(options: {
  apiKey?:  string;
  agentId?: string;
  keyId?:   string;
  baseUrl?: string;
}): void {
  if (options.apiKey)  state.apiKey  = options.apiKey;
  if (options.agentId) state.agentId = options.agentId;
  if (options.keyId)   state.keyId   = options.keyId;
  if (options.baseUrl) state.baseUrl = options.baseUrl.replace(/\/$/, '');
}

function getApiKey(override?: string): string {
  const key = override ?? state.apiKey ?? process.env.DARKMATTER_API_KEY ?? '';
  if (!key) throw new Error(
    'No API key. Call configure({ apiKey }) or set DARKMATTER_API_KEY.\n' +
    'Get a free key: https://darkmatterhub.ai/signup'
  );
  return key;
}

function getAgentId(override?: string): string {
  const id = override ?? state.agentId ?? process.env.DARKMATTER_AGENT_ID ?? '';
  if (!id) throw new Error('No agent ID. Call configure({ agentId }) or set DARKMATTER_AGENT_ID.');
  return id;
}

function hdrs(apiKey: string): Record<string, string> {
  return {
    'Content-Type':  'application/json',
    'Authorization': `Bearer ${apiKey}`,
    'User-Agent':    'darkmatter-js/1.2.0',
  };
}

async function request<T>(method: string, path: string, body?: unknown, apiKey?: string): Promise<T> {
  const key      = getApiKey(apiKey);
  const url      = (state.baseUrl || DM_BASE) + path;
  const response = await fetch(url, {
    method,
    headers: hdrs(key),
    body:    body ? JSON.stringify(body) : undefined,
  });
  const data = await response.json() as T & { error?: string };
  if (!response.ok || data.error) throw new Error(data.error ?? `HTTP ${response.status}`);
  return data;
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMIT OPTIONS
// ─────────────────────────────────────────────────────────────────────────────

export interface CommitOptions {
  toAgentId:       string;
  payload:         Record<string, unknown>;
  parentId?:       string;
  traceId?:        string;
  branchKey?:      string;
  eventType?:      string;
  agent?:          { role?: string; provider?: string; model?: string };
  agentSignature?: string;   // pre-computed Ed25519 hex over canonical(envelope)
  agentId?:        string;
  keyId?:          string;
  autoThread?:     boolean;
  apiKey?:         string;
}

// ─────────────────────────────────────────────────────────────────────────────
// CORE PRIMITIVES
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Commit agent context to DarkMatter.
 *
 * Phase 3 receipt includes:
 *   receipt._proof.leaf_hash        — RFC 6962 leaf hash
 *   receipt._proof.inclusion_proof  — Merkle proof steps
 *   receipt._proof.tree_root        — tree root at time of append
 *
 * Verify immediately: verifyReceipt(receipt)
 */
export async function commit(options: CommitOptions): Promise<CommitReceipt> {
  const {
    toAgentId, payload, parentId, traceId, branchKey,
    eventType, agent, agentSignature, autoThread = true, apiKey,
  } = options;

  const agentId = getAgentId(options.agentId);
  const keyId   = options.keyId ?? state.keyId;
  const ts      = new Date().toISOString().replace(/\.\d+Z$/, 'Z');

  const resolvedParent = parentId
    ?? (autoThread ? state.lastCtxId ?? undefined : undefined);

  const parentIH = autoThread && !parentId ? state.lastIntegrity : null;
  const { payloadHash, integrityHash, envelope } = computeIntegrityHash(
    payload, parentIH, agentId, keyId, ts,
  );

  const body = {
    toAgentId,
    payload,
    payload_hash:   payloadHash,
    integrity_hash: integrityHash,
    envelope,
    ...(agentSignature  ? { agent_signature: agentSignature } : {}),
    ...(resolvedParent  ? { parentId: resolvedParent }        : {}),
    ...(traceId         ? { traceId }                         : {}),
    ...(branchKey       ? { branchKey }                       : {}),
    ...(eventType       ? { eventType }                       : {}),
    ...(agent           ? { agent }                           : {}),
  };

  const receipt = await request<CommitReceipt>('POST', '/api/commit', body, apiKey);
  receipt._envelope = envelope;

  state.lastCtxId    = receipt.id;
  state.lastIntegrity = integrityHash;

  return receipt;
}

export async function replay(ctxId: string, options?: { mode?: 'full' | 'summary'; apiKey?: string }): Promise<unknown> {
  return request('GET', `/api/replay/${ctxId}?mode=${options?.mode ?? 'full'}`, undefined, options?.apiKey);
}

export async function fork(ctxId: string, options?: { branchKey?: string; apiKey?: string }): Promise<unknown> {
  return request('POST', `/api/fork/${ctxId}`, options?.branchKey ? { branchKey: options.branchKey } : {}, options?.apiKey);
}

export async function verify(ctxId: string, apiKey?: string): Promise<unknown> {
  return request('GET', `/api/verify/${ctxId}`, undefined, apiKey);
}

export async function diff(ctxIdA: string, ctxIdB: string, apiKey?: string): Promise<unknown> {
  return request('GET', `/api/diff?a=${ctxIdA}&b=${ctxIdB}`, undefined, apiKey);
}

/** Fetch a Phase 3 self-sufficient proof bundle. Verify offline with verifyBundle(). */
export async function bundle(ctxId: string, apiKey?: string): Promise<ProofBundle> {
  return request<ProofBundle>('GET', `/api/export/${ctxId}`, undefined, apiKey);
}

export async function me(apiKey?: string): Promise<unknown> {
  return request('GET', '/api/me', undefined, apiKey);
}

export async function checkpoint(apiKey?: string): Promise<{ checkpoint: Checkpoint; pubkey_url: string }> {
  return request('GET', '/api/log/checkpoint', undefined, apiKey);
}

/** Fetch inclusion proof for any commit by ID. No auth required. */
export async function proof(commitId: string): Promise<ProofReceipt & { leaf_envelope: unknown }> {
  const base = state.baseUrl || DM_BASE;
  const r    = await fetch(`${base}/api/log/proof/${commitId}`);
  const data = await r.json() as ProofReceipt & { leaf_envelope: unknown; error?: string };
  if (!r.ok) throw new Error(data.error ?? `HTTP ${r.status}`);
  return data;
}

export async function serverPubkey(): Promise<string> {
  const base = state.baseUrl || DM_BASE;
  const r    = await fetch(`${base}/api/log/pubkey`);
  const data = await r.json() as { public_key: string };
  return data.public_key;
}

// ─────────────────────────────────────────────────────────────────────────────
// CLASS INTERFACE
// ─────────────────────────────────────────────────────────────────────────────

export class DarkMatter {
  constructor(options?: { apiKey?: string; agentId?: string; keyId?: string; baseUrl?: string }) {
    if (options) configure(options);
  }
  commit       = commit;
  replay       = replay;
  fork         = fork;
  verify       = verify;
  diff         = diff;
  bundle       = bundle;
  me           = me;
  checkpoint   = checkpoint;
  proof        = proof;
  verifyReceipt  = verifyReceipt;
  verifyBundle   = verifyBundle;
}

export default DarkMatter;
