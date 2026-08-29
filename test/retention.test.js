/**
 * Tests retention enforcement.
 *
 * The pricing page said free-tier records are deleted after 30 days and the
 * terms said records are kept permanently. Neither happened: nothing in the
 * codebase deleted anything. This is the job that makes the promise true, and
 * these are the properties it must not get wrong, because it is the only code
 * in the product that destroys customer data.
 *
 * Run: node test/retention.test.js
 */
'use strict';

const crypto = require('crypto');
const { resolveRetention, enforceRetention } = require('../src/retention');
const { verifyCommitChain, hashPayload } = require('../src/integrity');

let passed = 0, failed = 0;
function check(label, cond, detail) {
  if (cond) { console.log('  ok    ' + label); passed++; }
  else { console.error('  FAIL  ' + label + (detail ? '\n          ' + detail : '')); failed++; }
}

const PLAN_META = {
  free:       { retentionDays: 30 },
  pro:        { retentionDays: 365 },
  teams:      { retentionDays: null },   // keep forever
  enterprise: { retentionDays: null },
};

// Minimal stand-in for the query builder, covering only what retention.js uses.
function makeDb(agents, subs, commits) {
  const updates = [];
  const db = {
    updates,
    from(table) {
      const q = {
        _t: table, _eq: {},
        select() { return q; },
        eq(k, v) { q._eq[k] = v; return q; },
        lt(k, v) { q._lt = [k, v]; return q; },
        not(k) { q._notNull = k; return q; },
        in(k, v) { q._in = [k, v]; return q; },
        limit() { return q; },
        update(vals) { q._u = vals; return q; },
        then(resolve) {
          if (table === 'agents') return resolve({ data: agents });
          if (table === 'subscriptions') return resolve({ data: subs });
          if (q._u) {
            updates.push({ ids: q._in[1], vals: q._u });
            for (const id of q._in[1]) {
              const c = commits.find(x => x.id === id);
              if (c) Object.assign(c, q._u);
            }
            return resolve({ error: null });
          }
          let rows = commits.filter(c => c.agent_id === q._eq.agent_id);
          if (q._lt) rows = rows.filter(c => c.timestamp < q._lt[1]);
          if (q._notNull) rows = rows.filter(c => c[q._notNull] !== null);
          return resolve({ data: rows.map(r => ({ id: r.id })) });
        },
      };
      return q;
    },
  };
  return db;
}

const OLD = new Date(Date.now() - 100 * 86400000).toISOString();
const NEW = new Date().toISOString();

function fixture() {
  const agents = [
    { agent_id: 'a-free',   user_id: 'u1', retention_days: null },
    { agent_id: 'a-pro',    user_id: 'u2', retention_days: null },
    { agent_id: 'a-teams',  user_id: 'u3', retention_days: null },
    { agent_id: 'a-custom', user_id: 'u4', retention_days: 7 },
  ];
  const subs = [
    { user_id: 'u2', plan: 'pro',   retention_days: null },
    { user_id: 'u3', plan: 'teams', retention_days: null },
    { user_id: 'u4', plan: 'pro',   retention_days: null },
  ];
  const commits = [
    { id: 'c1', agent_id: 'a-free',   timestamp: OLD, payload: { x: 1 } },
    { id: 'c2', agent_id: 'a-free',   timestamp: NEW, payload: { x: 2 } },
    { id: 'c3', agent_id: 'a-pro',    timestamp: OLD, payload: { x: 3 } },
    { id: 'c4', agent_id: 'a-teams',  timestamp: OLD, payload: { x: 4 } },
    { id: 'c5', agent_id: 'a-custom', timestamp: OLD, payload: { x: 5 } },
    { id: 'c6', agent_id: 'a-free',   timestamp: OLD, payload: null },
  ];
  return { agents, subs, commits };
}

(async () => {
  // ── Which agents expire at all ─────────────────────────────────────────────
  let f = fixture();
  let map = await resolveRetention(makeDb(f.agents, f.subs, f.commits), PLAN_META);
  check('an agent with no subscription falls back to the free window', map.get('a-free') === 30);
  check('a plan window applies when the agent sets none', map.get('a-pro') === 365);
  check('an explicit agent window overrides the plan', map.get('a-custom') === 7);
  // The one that must never default: null means the paid tier keeps records.
  check('a null retention means keep forever, not "use the default"',
    !map.has('a-teams'), 'a-teams would have been purged');

  // ── Dry run changes nothing ───────────────────────────────────────────────
  f = fixture();
  let db = makeDb(f.agents, f.subs, f.commits);
  let r = await enforceRetention(db, PLAN_META, { dryRun: true });
  check('dry run reports what it would do', r.scanned === 2 && r.redacted === 0,
    JSON.stringify({ scanned: r.scanned, redacted: r.redacted }));
  check('dry run writes nothing', db.updates.length === 0 &&
    f.commits.filter(c => c.payload !== null).length === 5);

  // ── A real run redacts exactly the expired rows ───────────────────────────
  f = fixture();
  db = makeDb(f.agents, f.subs, f.commits);
  r = await enforceRetention(db, PLAN_META);
  const survivors = f.commits.filter(c => c.payload !== null).map(c => c.id).sort().join(',');
  check('redacts only rows past their own window', r.redacted === 2, String(r.redacted));
  check('keeps recent, in-window and forever rows', survivors === 'c2,c3,c4', survivors);
  check('does not re-count an already redacted row',
    !db.updates.flatMap(u => u.ids).includes('c6'));

  // ── It must never touch the fields that make a record verifiable ──────────
  const vals = db.updates[0] && db.updates[0].vals;
  check('nulls only content fields',
    vals && Object.keys(vals).sort().join(',') === 'context,encrypted_payload,payload',
    JSON.stringify(vals));
  check('leaves hashes, links and ids alone',
    vals && !('payload_hash' in vals) && !('integrity_hash' in vals) &&
    !('parent_hash' in vals) && !('id' in vals));

  // ── The property the whole design rests on ────────────────────────────────
  // Redacting a record must not break the chain for the records after it,
  // otherwise retention would quietly destroy a customer's evidence.
  const chain = [];
  let parent = null;
  for (let i = 0; i < 4; i++) {
    const payload = { step: i };
    const ph = 'sha256:' + hashPayload(payload);
    const ih = 'sha256:' + crypto.createHash('sha256').update(ph + (parent || 'root'), 'utf8').digest('hex');
    chain.push({ id: 'k' + i, payload, payload_hash: ph, parent_hash: parent, integrity_hash: ih });
    parent = ih;
  }
  check('chain verifies before redaction', verifyCommitChain(chain).intact);

  const redacted = JSON.parse(JSON.stringify(chain));
  redacted[0].payload = null;
  const after = verifyCommitChain(redacted);
  check('chain still verifies after a payload is redacted', after.intact,
    JSON.stringify(after.steps[0]));
  check('the redacted record reports "cannot check", not "broken"',
    after.steps[0].payload_hash_verified === null,
    String(after.steps[0].payload_hash_verified));
  check('records after the redacted one still verify',
    after.steps.slice(1).every(s => s.payload_hash_verified === true));

  // Redaction must not become a way to launder a tampered record.
  const tampered = JSON.parse(JSON.stringify(chain));
  tampered[2].payload = { step: 'altered' };
  check('a genuine tamper still fails', !verifyCommitChain(tampered).intact);

  console.log('\n  Passed: ' + passed + '  Failed: ' + failed);
  process.exit(failed ? 1 : 0);
})();
