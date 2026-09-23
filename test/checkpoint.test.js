/**
 * Tests when a checkpoint is created, and that it links to its predecessor.
 *
 * Two faults lived here for the life of the log.
 *
 * The previous-checkpoint lookup ordered by log_position, a column on commits
 * that has never been on checkpoints. PostgREST rejects the whole request when
 * a filter or sort names a column that does not exist, the call site kept only
 * { data }, and so prevCp was undefined on every run. Every checkpoint was
 * written with previous_cp_id null, each one claiming to be the first, and the
 * link that stops checkpoint history being forked never existed.
 *
 * The scheduler also fired on a timer rather than on activity, so a log holding
 * thirteen records signed 144 checkpoints a day over an unchanged tree, all at
 * the same position. That is what made "the latest checkpoint" ambiguous enough
 * for the public endpoint to serve a sixteen-day-old one.
 *
 * Static guards in smoke.test.js catch the column name. These pin the
 * behaviour: when a checkpoint gets made, and what it points at.
 *
 * Run: node test/checkpoint.test.js
 */
'use strict';

const assert = require('assert');
const { publishCheckpoint } = require('../src/checkpoint');

let passed = 0, failed = 0;

async function test(label, fn) {
  try { await fn(); console.log('  ok    ' + label); passed++; }
  catch (e) { console.error('  FAIL  ' + label + '\n        ' + e.message); failed++; }
}

const TREE = 'a'.repeat(64);
const OTHER_TREE = 'b'.repeat(64);

function entry(treeRoot) {
  return { position: 12, tree_root: treeRoot, tree_size: 13, log_root: 'c'.repeat(64),
           timestamp: new Date().toISOString() };
}

// Minimal stand-in for the Supabase builder: enough chaining to run the
// function under test, and a record of every write it attempted.
function stubClient(tables, calls) {
  return {
    from(table) {
      const b = {
        select() { return b; },
        order()  { return b; },
        limit()  { return b; },
        eq()     { return b; },
        lte()    { return b; },
        in()     { return b; },
        gte()    { return b; },
        neq()    { return b; },
        not()    { return b; },
        insert(row) { calls.push({ op: 'insert', table, row }); return Promise.resolve({ data: null, error: null }); },
        update(row) { calls.push({ op: 'update', table, row }); return b; },
        single()     { return Promise.resolve(tables[table] || { data: null, error: null }); },
        maybeSingle(){ return Promise.resolve(tables[table] || { data: null, error: null }); },
        then(res, rej) { return Promise.resolve(tables[table] || { data: [], error: null }).then(res, rej); },
      };
      return b;
    },
  };
}

function inserted(calls) {
  return calls.filter(c => c.op === 'insert' && c.table === 'checkpoints');
}

// The module logs every signature it makes. Useful in production, and in a CI
// run it buries the one line that matters.
async function quiet(fn) {
  const log = console.log, err = console.error;
  console.log = function () {}; console.error = function () {};
  try { return await fn(); } finally { console.log = log; console.error = err; }
}

(async function run() {
  console.log('\nCheckpoint creation');

  await test('an unchanged tree inside the heartbeat window writes nothing', async () => {
    const calls = [];
    const client = stubClient({
      log_entries: { data: entry(TREE), error: null },
      checkpoints: { data: { checkpoint_id: 'cp_prev', tree_root: TREE,
                             timestamp: new Date(Date.now() - 60 * 1000).toISOString() }, error: null },
    }, calls);
    const r = await quiet(() => publishCheckpoint(client));
    assert.strictEqual(r.reason, 'tree_unchanged_within_heartbeat',
      'signed over an unchanged tree a minute after the last one');
    assert.strictEqual(inserted(calls).length, 0, 'it stored a checkpoint anyway');
  });

  await test('a changed tree is checkpointed immediately', async () => {
    const calls = [];
    const client = stubClient({
      log_entries: { data: entry(OTHER_TREE), error: null },
      checkpoints: { data: { checkpoint_id: 'cp_prev', tree_root: TREE,
                             timestamp: new Date(Date.now() - 60 * 1000).toISOString() }, error: null },
    }, calls);
    await quiet(() => publishCheckpoint(client));
    assert.strictEqual(inserted(calls).length, 1,
      'a new record must produce a checkpoint without waiting for the heartbeat');
  });

  await test('an unchanged tree past the heartbeat is signed again', async () => {
    const calls = [];
    const client = stubClient({
      log_entries: { data: entry(TREE), error: null },
      checkpoints: { data: { checkpoint_id: 'cp_prev', tree_root: TREE,
                             timestamp: new Date(Date.now() - 48 * 3600 * 1000).toISOString() }, error: null },
    }, calls);
    await quiet(() => publishCheckpoint(client));
    assert.strictEqual(inserted(calls).length, 1,
      'liveness evidence stops entirely if a quiet log is never re-signed');
  });

  await test('the checkpoint links to its predecessor', async () => {
    const calls = [];
    const client = stubClient({
      log_entries: { data: entry(OTHER_TREE), error: null },
      checkpoints: { data: { checkpoint_id: 'cp_prev', tree_root: TREE,
                             timestamp: new Date(Date.now() - 60 * 1000).toISOString() }, error: null },
    }, calls);
    await quiet(() => publishCheckpoint(client));
    const row = inserted(calls)[0].row;
    assert.strictEqual(row.previous_cp_id, 'cp_prev',
      'previous_cp_id is ' + row.previous_cp_id + ' — the chain is unlinked again');
    assert.strictEqual(row.previous_tree_root, TREE,
      'previous_tree_root is ' + row.previous_tree_root);
  });

  await test('the first checkpoint of an empty chain links to nothing', async () => {
    const calls = [];
    const client = stubClient({
      log_entries: { data: entry(TREE), error: null },
      checkpoints: { data: null, error: null },
    }, calls);
    await quiet(() => publishCheckpoint(client));
    const row = inserted(calls)[0].row;
    assert.strictEqual(row.previous_cp_id, null);
    assert.strictEqual(row.previous_tree_root, null);
  });

  await test('an unreadable predecessor stops the write instead of orphaning it', async () => {
    const calls = [];
    const client = stubClient({
      log_entries: { data: entry(OTHER_TREE), error: null },
      checkpoints: { data: null, error: { message: 'column checkpoints.log_position does not exist' } },
    }, calls);
    const r = await quiet(() => publishCheckpoint(client));
    assert.strictEqual(r.error, 'previous_checkpoint_unreadable',
      'it carried on and wrote an unlinked checkpoint, which is the original bug');
    assert.strictEqual(inserted(calls).length, 0, 'it stored one anyway');
  });

  console.log('\n  Passed: ' + passed + '  Failed: ' + failed);
  if (failed > 0) process.exitCode = 1;
})();
