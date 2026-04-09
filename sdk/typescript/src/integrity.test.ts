/**
 * DarkMatter Integrity Test Suite
 * ================================
 * Run with: npx ts-node src/integrity.test.ts
 * Or: npx jest (if configured)
 *
 * All 18 canonical serialization vectors + chain verification tests.
 * Must pass before any SDK release.
 */

import { readFileSync } from 'fs';
import { join } from 'path';
import {
  canonicalize,
  hashPayload,
  buildEnvelope,
  hashEnvelope,
  computeIntegrityHash,
  verifyChain,
  stripPrefix,
  runTestVectors,
} from './integrity';

// ─── Colours ────────────────────────────────────────────────────────────────
const G = '\x1b[32m✓\x1b[0m';
const R = '\x1b[31m✗\x1b[0m';
const Y = '\x1b[33m~\x1b[0m';

let passed = 0; let failed = 0;

function test(desc: string, fn: () => void): void {
  try { fn(); console.log(`  ${G} ${desc}`); passed++; }
  catch (e) { console.log(`  ${R} ${desc}\n    ${e}`); failed++; }
}

function assert(condition: boolean, msg = 'assertion failed'): void {
  if (!condition) throw new Error(msg);
}

function assertEq<T>(a: T, b: T, msg = ''): void {
  if (a !== b) throw new Error(`${msg}\n  expected: ${JSON.stringify(b)}\n  got:      ${JSON.stringify(a)}`);
}

// ─── 1. Test vectors from JSON ────────────────────────────────────────────────
console.log('\nDarkMatter Integrity — TypeScript test suite\n');
console.log('1. Canonical serialization test vectors');

const vectorsPath = join(__dirname, '../../../github-template/integrity_test_vectors.json');
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));
const { passed: vp, failed: vf, results } = runTestVectors(vectors);

for (const r of results) {
  if (r.ok) { console.log(`  ${G} ${r.id}: ${r.desc}`); passed++; }
  else { console.log(`  ${R} ${r.id}: ${r.desc}\n    exp: ${r.expected}\n    got: ${r.got}`); failed++; }
}

// ─── 2. Null handling ─────────────────────────────────────────────────────────
console.log('\n2. null / undefined handling');

test('null in dict is kept as "null"', () => {
  assertEq(canonicalize({ a: null, b: 1 }), '{"a":null,"b":1}');
});

test('null payload field changes hash vs missing', () => {
  const withNull    = hashPayload({ output: 'x', error: null });
  const withMissing = hashPayload({ output: 'x' });
  assert(withNull !== withMissing, 'null and missing should produce different hashes');
});

test('undefined in dict is dropped', () => {
  const obj = { a: 1, b: undefined as unknown as string, c: 3 };
  assertEq(canonicalize(obj), '{"a":1,"c":3}');
});

// ─── 3. Float handling ────────────────────────────────────────────────────────
console.log('\n3. Float handling');

test('NaN rejected with TypeError', () => {
  try { canonicalize(NaN); throw new Error('should have thrown'); }
  catch (e) { assert(e instanceof TypeError); }
});

test('Infinity rejected', () => {
  try { canonicalize(Infinity); throw new Error('should have thrown'); }
  catch (e) { assert(e instanceof TypeError); }
});

test('-Infinity rejected', () => {
  try { canonicalize(-Infinity); throw new Error('should have thrown'); }
  catch (e) { assert(e instanceof TypeError); }
});

test('integer serialized without decimal point', () => {
  assertEq(canonicalize(42),   '42');
  assertEq(canonicalize(-1),   '-1');
  assertEq(canonicalize(0),    '0');
});

// ─── 4. stripPrefix (lstrip bug guard) ────────────────────────────────────────
console.log('\n4. stripPrefix — lstrip bug guard');

test('sha256:24bc... strips correctly (leading "2" not eaten)', () => {
  const h = '24bc7fe452590b7f5bacbd53aeed7bb0c956bf3fd7065f80a25dc0b4df682163';
  assertEq(stripPrefix('sha256:' + h), h);
});

test('sha256:abc... strips correctly', () => {
  const h = 'abc123def456';
  assertEq(stripPrefix('sha256:' + h), h);
});

test('null input returns null', () => {
  assertEq(stripPrefix(null), null);
});

test('already-stripped hash returned as-is', () => {
  const h = 'deadbeef';
  assertEq(stripPrefix(h), h);
});

// ─── 5. Envelope construction ─────────────────────────────────────────────────
console.log('\n5. Envelope construction');

const AGENT = 'dm_test'; const KEY = 'default'; const TS = '2026-04-08T12:00:00Z';

test('root commit uses "root" as parent_integrity_hash', () => {
  const env = buildEnvelope('abc', null, AGENT, KEY, TS);
  assertEq(env.parent_integrity_hash, 'root');
});

test('timestamp milliseconds stripped', () => {
  const env = buildEnvelope('abc', null, AGENT, KEY, '2026-04-08T12:00:00.123Z');
  assertEq(env.timestamp, '2026-04-08T12:00:00Z');
});

test('schema_version is "2"', () => {
  const env = buildEnvelope('abc', null, AGENT, KEY, TS);
  assertEq(env.schema_version, '2');
});

test('E-001 envelope canonical matches spec', () => {
  const emptyHash = hashPayload({});
  const env       = buildEnvelope(emptyHash, null, 'dm_test123', 'default', TS);
  const got       = canonicalize(env as unknown as Record<string, unknown>);
  const expected  = vectors.envelope_vectors.find((v: { id: string }) => v.id === 'E-001')?.expected_canonical;
  assertEq(got, expected);
});

// ─── 6. Chain verification ────────────────────────────────────────────────────
console.log('\n6. Chain verification');

function makeCommit(payload: Record<string, unknown>, prevIH: string | null) {
  const { payloadHash, integrityHash } = computeIntegrityHash(payload, prevIH, AGENT, KEY, TS);
  return {
    id:              'ctx_' + payloadHash.slice(0, 8),
    payload,
    payload_hash:    'sha256:' + payloadHash,
    integrity_hash:  'sha256:' + integrityHash,
    agent_id:        AGENT,
    key_id:          KEY,
    timestamp:       TS,
    _ih:             integrityHash,
  };
}

test('valid 2-step chain passes strict', () => {
  const c1 = makeCommit({ output: 'step1' }, null);
  const c2 = makeCommit({ output: 'step2' }, c1._ih);
  const r  = verifyChain([c1, c2], { strict: true });
  assert(r.chain_intact, `broken_at: ${r.broken_at}`);
});

test('valid chain with null field', () => {
  const c1 = makeCommit({ output: 'x', error: null }, null);
  const r  = verifyChain([c1]);
  assert(r.chain_intact);
});

test('tampered payload detected', () => {
  const c1   = makeCommit({ output: 'original' }, null);
  const evil = { ...c1, payload: { output: 'TAMPERED' } };
  const r    = verifyChain([evil]);
  assert(!r.chain_intact);
  assertEq(r.broken_at, evil.id);
});

test('tampered integrity_hash detected', () => {
  const c1    = makeCommit({ output: 'a' }, null);
  const evil  = { ...c1, integrity_hash: 'sha256:' + 'f'.repeat(64) };
  const r     = verifyChain([evil]);
  assert(!r.chain_intact);
});

test('missing hash breaks in strict mode', () => {
  const c = { id: 'ctx_x', payload: { output: 'a' }, agent_id: AGENT, key_id: KEY, timestamp: TS };
  const r = verifyChain([c as any], { strict: true });
  assert(!r.chain_intact);
  assertEq(r.steps[0].reason, 'missing_hashes');
});

test('missing hash passes in legacy mode', () => {
  const c = { id: 'ctx_x', payload: { output: 'a' }, agent_id: AGENT, key_id: KEY, timestamp: TS };
  const r = verifyChain([c as any], { strict: false });
  assert(r.chain_intact);
});

test('key-order independence of payload hash', () => {
  const h1 = hashPayload({ z: 1, a: 2 });
  const h2 = hashPayload({ a: 2, z: 1 });
  assertEq(h1, h2);
});

// ─── 7. Phase 3 — verifyReceipt + verifyBundle ───────────────────────────────
import { verifyReceipt, verifyBundle } from './index';

console.log('\n7. Phase 3 — receipt and bundle verification');

const AGENT3 = 'dm_test3'; const KEY3 = 'default'; const TS3 = '2026-04-09T10:00:00Z';

function makeProofReceipt(
  commitId: string,
  ih: string,
  logPosition: number,
  treeRoot: string,
  proof: Array<{ hash: string; direction: 'left' | 'right' }>,
): import('./index').ProofReceipt {
  // Compute leaf hash using same algorithm as server
  const ts = TS3.replace(/\.\d+Z?$/, '').replace(/Z?$/, 'Z');
  const ihBare = ih.startsWith('sha256:') ? ih.slice(7) : ih;
  const leafEnv = `{"accepted_at":${JSON.stringify(ts)},"commit_id":${JSON.stringify(commitId)},"integrity_hash":${JSON.stringify(ihBare)},"log_position":${logPosition}}`;
  const crypto = require('crypto');
  const buf = Buffer.concat([Buffer.from([0x00]), Buffer.from(leafEnv, 'utf8')]);
  const leafH = crypto.createHash('sha256').update(buf).digest('hex');

  return {
    log_position:   logPosition,
    leaf_hash:      leafH,
    tree_root:      treeRoot,
    tree_size:      logPosition + 1,
    accepted_at:    TS3,
    inclusion_proof: { leaf_index: logPosition, tree_size: logPosition + 1, proof },
    proof_status:   'included',
    pubkey_url:     'https://darkmatterhub.ai/api/log/pubkey',
    checkpoint_url: 'https://darkmatterhub.ai/api/log/checkpoint',
    verify_url:     `https://darkmatterhub.ai/api/log/proof/${commitId}`,
  };
}

// Single-commit receipt — leaf is also root, no proof steps
const { payloadHash: ph1t, integrityHash: ih1t } = computeIntegrityHash(
  { output: 'step1' }, null, AGENT3, KEY3, TS3
);
// leaf hash for single-leaf tree = the leaf hash itself = tree root
const crypto2 = require('crypto');
const ts3norm = TS3;
const ih1bare = ih1t;
const leafEnv1 = `{"accepted_at":${JSON.stringify(ts3norm)},"commit_id":"ctx_t1","integrity_hash":${JSON.stringify(ih1bare)},"log_position":0}`;
const buf1 = Buffer.concat([Buffer.from([0x00]), Buffer.from(leafEnv1, 'utf8')]);
const lh1 = crypto2.createHash('sha256').update(buf1).digest('hex');

const receipt1: import('./index').CommitReceipt = {
  id: 'ctx_t1', schema_version: '2', integrity_hash: 'sha256:' + ih1t,
  payload_hash: 'sha256:' + ph1t, parent_hash: null,
  verified: true, timestamp: TS3,
  _proof: {
    log_position: 0, leaf_hash: lh1, tree_root: lh1, tree_size: 1,
    accepted_at: TS3, inclusion_proof: { leaf_index: 0, tree_size: 1, proof: [] },
    proof_status: 'included', pubkey_url: '', checkpoint_url: '', verify_url: '',
  },
};

test('verifyReceipt: valid single-commit proof (empty proof steps = leaf is root)', () => {
  const r = verifyReceipt(receipt1);
  assert(r.ok, `leaf_hash_ok=${r.leaf_hash_ok} proof_ok=${r.proof_ok} reason=${r.reason}`);
});

test('verifyReceipt: missing _proof returns ok=false', () => {
  const r = verifyReceipt({ ...receipt1, _proof: undefined });
  assert(!r.ok && r.reason === 'no proof receipt');
});

test('verifyReceipt: tampered integrity_hash detected', () => {
  const tampered = { ...receipt1, integrity_hash: 'sha256:' + 'f'.repeat(64) };
  const r = verifyReceipt(tampered);
  // leaf_hash_ok should be false — recomputed leaf won't match stored
  assert(!r.ok || r.leaf_hash_ok === false);
});

// verifyBundle with a minimal valid bundle
const bundle1: import('./index').ProofBundle = {
  _spec: { bundle_version: '3.0', spec_url: '', verifier_url: '', verify_command: '', checkpoint_repo: '', phases: [] },
  metadata: { ctx_id: 'ctx_t1', chain_length: 1, lineage_root: 'ctx_t1', trace_id: null, exported_at: TS3, exported_by: AGENT3 },
  integrity: { chain_intact: true, algorithm: 'sha256-envelope', root_hash: 'sha256:'+ih1t, tip_hash: 'sha256:'+ih1t, chain_hash: 'sha256:abc', timestamp_range: { from: TS3, to: TS3 } },
  checkpoint: null,
  server_pubkey: { algorithm: 'Ed25519', public_key: '', use: '', pubkey_url: '' },
  commits: [{ ...receipt1, payload: { output: 'step1' }, agent_id: AGENT3, key_id: KEY3 } as any],
  export_hash: 'sha256:abc',
};

test('verifyBundle: valid bundle passes structure check', () => {
  const r = verifyBundle(bundle1, { strict: false });
  assert(r.structure.chain_intact, `chain broken at ${r.structure.broken_at}`);
});

test('verifyBundle: proof receipt verified in bundle', () => {
  const r = verifyBundle(bundle1, { strict: false });
  assert(r.merkle.proofs_found === 1, `proofs_found=${r.merkle.proofs_found}`);
  assert(r.merkle.proofs_valid === 1, `proofs_valid=${r.merkle.proofs_valid}`);
  assert(r.merkle.ok === true, `merkle.ok=${r.merkle.ok}`);
});

test('verifyBundle: no proofs → merkle.ok is null (not false)', () => {
  const b2 = { ...bundle1, commits: [{ ...bundle1.commits[0], _proof: undefined }] };
  const r  = verifyBundle(b2 as any, { strict: false });
  assertEq(r.merkle.ok, null);
});

// ─── Summary ──────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(44)}`);
const total = passed + failed;
if (failed === 0) {
  console.log(`\x1b[32m✓ All ${total} tests passed\x1b[0m\n`);
  process.exit(0);
} else {
  console.log(`\x1b[31m✗ ${failed}/${total} tests FAILED\x1b[0m\n`);
  process.exit(1);
}

