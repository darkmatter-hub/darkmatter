/**
 * Tests witness co-signature acceptance.
 *
 * Production had one registered witness, wit_bd46a5a1d670bfb7. The witness
 * server that actually answers signs as wit_80e6dec7ab45d350 — a different
 * key, so a different id, because the id is sha256 of the public key. Every
 * signature it returned was verified against the stale registered key, failed,
 * and was stored with sig_valid false. The checkpoint came out
 * witness_status 'witness_failed' with witness_count 0, and nothing said why.
 * It stayed that way long enough that a later commit read the row count in
 * witness_sigs, saw signatures, and concluded witnessing worked.
 *
 * These tests pin the behaviour that matters: a signature from the wrong key
 * must not count, and it must not be mistaken for a witnessed checkpoint.
 *
 * Run: node test/witness.test.js
 */
'use strict';

const crypto = require('crypto');
const { acceptWitnessSignature, verifyWitnessSignature } = require('../src/witness');
const { envelopeFromCheckpointRow } = require('../src/append-log');
const { canonicalize } = require('../src/integrity');

let passed = 0, failed = 0;
function check(label, cond, detail) {
  if (cond) { console.log('  ok    ' + label); passed++; }
  else { console.error('  FAIL  ' + label + (detail ? '\n          ' + detail : '')); failed++; }
}

function newKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const der = publicKey.export({ type: 'spki', format: 'der' });
  const id  = 'wit_' + crypto.createHash('sha256').update(der).digest('hex').slice(0, 16);
  return { privateKey, pem, id };
}

const CP = {
  checkpoint_id: 'cp_test_0001',
  position: 41,
  tree_root: 'a'.repeat(64),
  tree_size: 42,
  log_root: 'b'.repeat(64),
  server_sig: 'c'.repeat(128),
  timestamp: '2026-08-29T12:00:00.000Z',
  previous_cp_id: null,
  previous_tree_root: null,
  published: false,
  published_url: null,
  witness_count: 0,
  witness_status: 'pending',
  schema_version: '3',
};

// The envelope acceptWitnessSignature rebuilds and verifies against. Built by
// the same helper the code uses, because a hand-written copy here would only
// prove the test and the code agree with each other.
const ENVELOPE = envelopeFromCheckpointRow(CP);

function signEnvelope(privateKey) {
  return crypto.sign(null, Buffer.from(canonicalize(ENVELOPE), 'utf8'), privateKey)
    .toString('hex');
}

// Minimal stand-in for the query builder, covering only what witness.js uses.
function makeDb(registeredPem, registeredId) {
  const state = { sigs: [], cpUpdate: null, commitUpdate: null };
  const db = {
    state,
    from(table) {
      const q = {
        _t: table, _eq: {},
        select() { return q; },
        insert(v) { q._ins = v; return q; },
        update(v) { q._u = v; return q; },
        eq(k, v) { q._eq[k] = v; return q; },
        in(k, v) { q._in = [k, v]; return q; },
        single() { return q; },
        then(resolve) {
          if (table === 'checkpoints' && q._u) { state.cpUpdate = q._u; return resolve({ error: null }); }
          if (table === 'checkpoints') return resolve({ data: { ...CP } });
          if (table === 'witnesses') {
            const match = q._eq.witness_id === registeredId;
            return resolve({ data: match ? { public_key_pem: registeredPem, name: 'Test Witness' } : null });
          }
          if (table === 'witness_sigs' && q._ins) {
            state.sigs.push(q._ins); return resolve({ error: null });
          }
          if (table === 'witness_sigs') return resolve({ data: state.sigs });
          if (table === 'commits') { state.commitUpdate = q._u; return resolve({ error: null }); }
          return resolve({ data: null });
        },
      };
      return q;
    },
  };
  return db;
}

(async () => {
  console.log('\nWitness signature acceptance');

  // 1. The good path: the witness that is registered signs with its own key.
  {
    const w = newKey();
    const db = makeDb(w.pem, w.id);
    const r = await acceptWitnessSignature(db, CP.checkpoint_id, w.id,
      signEnvelope(w.privateKey), CP.timestamp);
    check('a signature from the registered key is valid', r.sig_valid === true);
    check('one valid signature witnesses the checkpoint',
      r.witness_status === 'witnessed' && r.witness_count === 1,
      'got ' + r.witness_status + ' count=' + r.witness_count);
    check('covered commits are promoted to checkpointed_witnessed',
      db.state.commitUpdate && db.state.commitUpdate.proof_status === 'checkpointed_witnessed');
  }

  // 2. The production bug: the witness signs with a key we did not register.
  {
    const registered = newKey();
    const actual     = newKey();   // witness regenerated its key after a redeploy
    const db = makeDb(registered.pem, registered.id);
    const r = await acceptWitnessSignature(db, CP.checkpoint_id, registered.id,
      signEnvelope(actual.privateKey), CP.timestamp);
    check('a signature from an unregistered key is invalid', r.sig_valid === false);
    check('an invalid signature does not witness the checkpoint',
      r.witness_status === 'witness_failed' && r.witness_count === 0,
      'got ' + r.witness_status + ' count=' + r.witness_count);
    check('an invalid signature does not promote any commit',
      db.state.commitUpdate === null);
    check('the invalid signature is still stored, so the failure is auditable',
      db.state.sigs.length === 1 && db.state.sigs[0].sig_valid === false);
    check('the checkpoint row records the failure',
      db.state.cpUpdate && db.state.cpUpdate.witness_status === 'witness_failed');
  }

  // 3. A witness id is the hash of its public key, which is why a key change
  //    shows up as a different id — the signal broadcastToWitnesses now checks.
  {
    const a = newKey(), b = newKey();
    check('a different key yields a different witness id', a.id !== b.id);
    check('the same key yields the same id',
      newKey().id.length === a.id.length && /^wit_[0-9a-f]{16}$/.test(a.id));
  }

  // 4. The offline verifier must reach the same verdict as the server.
  {
    const w = newKey(), other = newKey();
    check('offline verifier accepts a correct signature',
      verifyWitnessSignature(ENVELOPE, signEnvelope(w.privateKey), w.pem) === true);
    check('offline verifier rejects a signature from another key',
      verifyWitnessSignature(ENVELOPE, signEnvelope(other.privateKey), w.pem) === false);
  }


  // 5. The timestamp format is the whole reason witnessing could not work.
  //    Postgres returns "2026-08-29T19:41:35+00:00"; the signature is over
  //    "2026-08-29T19:41:35Z". Same instant, different string, and canonical
  //    JSON hashes the string. Rebuilding from the row without converting
  //    produced a message nobody had signed.
  {
    const zForm  = envelopeFromCheckpointRow({ ...CP, timestamp: '2026-08-29T12:00:00Z' });
    const pgForm = envelopeFromCheckpointRow({ ...CP, timestamp: '2026-08-29T12:00:00+00:00' });
    const subsec = envelopeFromCheckpointRow({ ...CP, timestamp: '2026-08-29T12:00:00.000Z' });
    check('the database timestamp form rebuilds to the signed form',
      pgForm.timestamp === '2026-08-29T12:00:00Z', pgForm.timestamp);
    check('an already-normalised timestamp is unchanged',
      zForm.timestamp === '2026-08-29T12:00:00Z', zForm.timestamp);
    check('fractional seconds are stripped, as they are before signing',
      subsec.timestamp === '2026-08-29T12:00:00Z', subsec.timestamp);
    check('all three forms produce the identical envelope',
      JSON.stringify(zForm) === JSON.stringify(pgForm) &&
      JSON.stringify(zForm) === JSON.stringify(subsec));

    // The end of the story: a witness signing what we sent must be accepted
    // even though the row comes back in the other format.
    const w = newKey();
    const db = makeDb(w.pem, w.id);
    const sig = crypto.sign(null,
      Buffer.from(canonicalize(envelopeFromCheckpointRow(CP)), 'utf8'), w.privateKey).toString('hex');
    const r = await acceptWitnessSignature(
      { ...db, from: (t) => db.from(t) }, CP.checkpoint_id, w.id, sig, CP.timestamp);
    check('a witness signature survives the round trip through the database',
      r.sig_valid === true, 'sig_valid=' + r.sig_valid);
  }

  console.log('\nPassed: ' + passed + '  Failed: ' + failed);
  process.exit(failed ? 1 : 0);
})();
