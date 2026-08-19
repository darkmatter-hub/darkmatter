/**
 * DarkMatter Security Regression Tests
 * Run: node test/security.test.js   (also invoked from test/smoke.test.js)
 *
 * Every check here corresponds to a security defect that was found and fixed.
 * If a fix is reverted, the matching test fails and names the finding.
 *
 * Findings covered:
 *   F1  POST /api/provision bound an API key to a stranger's existing account
 *   F2  hash chain did not cover nested payload content (replacer-vs-sorter)
 *   F3  POST /api/share/:ctxId computed agentIds and never used it
 *   F4  id-taking routes authenticated the caller but never checked ownership
 *   F5  GET /r/:traceId served any record by id, and erased payload content
 *
 * Style follows test/smoke.test.js: plain assertions, no framework.
 * Route-level checks are static source assertions because these must run in
 * CI with no database and no credentials. Hash-correctness checks (F2) are
 * behavioural — they call src/integrity.js directly.
 */
'use strict';

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const ROOT   = path.join(__dirname, '..');
const SERVER = path.join(ROOT, 'src/server.js');

const integrity = require(path.join(ROOT, 'src/integrity.js'));
const { canonicalize, hashPayload, buildEnvelope, hashEnvelope, verifyChain } = integrity;

// ─────────────────────────────────────────────────────────────────────────────
// F2 KNOWN OUTSTANDING SITE
//
// The F2 fix routed three sites through hashPayload()/canonicalize(). A fourth
// site — the payload hash inside POST /api/fork/:ctxId — still uses the broken
// replacer and was not part of that fix. It is listed here by the variable it
// hashes so the scan below stays green on today's tree while still failing on
// any NEW occurrence anywhere in the file.
//
// DELETE this entry when the fork route is fixed. See the report notes.
// ─────────────────────────────────────────────────────────────────────────────
// Sites still using the broken replacer pattern. This list must stay empty.
// forkPayload was the last entry, fixed 2026-08-19 (src/server.js, /api/fork/:ctxId);
// it had been missed because the pattern spans multiple lines and a
// single-line search did not match it.
const F2_KNOWN_UNFIXED = [];

function run() {
  let passed = 0, failed = 0;

  function test(label, fn) {
    try { fn(); console.log('  ✓ ' + label); passed++; }
    catch (e) { console.error('  ✗ ' + label + '\n    ' + e.message); failed++; }
  }
  function assert(cond, msg) { if (!cond) throw new Error(msg || 'assertion failed'); }

  const server = fs.readFileSync(SERVER, 'utf8');

  // ── source helpers ─────────────────────────────────────────────────────────

  /** The destructured import list from require('./integrity'), or null. */
  const integrityImport = server.match(
    /const\s*\{([^}]*)\}\s*=\s*require\(['"]\.\/integrity['"]\)/);

  /**
   * Body of a top-level route handler, from its `app.<verb>(` signature to the
   * first column-0 `});` (how the handlers in this file actually close),
   * bounded by the next top-level `app.` registration.
   *
   * Slices from `serverCode`, i.e. with comment-only lines blanked. The fixes
   * being locked in are documented by comments that quote the defective code
   * they replaced (the F2 replacer, the F3 agentIds check, the F1 account
   * lookup). Matching against raw source would let those comments satisfy the
   * assertions and every test here would pass vacuously.
   */
  function bodyOf(sig) {
    const i = serverCode.indexOf(sig);
    if (i < 0) return null;
    let end = serverCode.indexOf('\napp.', i + 1);
    if (end < 0) end = serverCode.length;
    const close = serverCode.indexOf('\n});', i);
    if (close > i && close + 4 < end) end = close + 4;
    return serverCode.slice(i, end);
  }

  /**
   * server.js with comment-only lines blanked out, preserving line numbering.
   * Needed because the F2 fix left the broken pattern quoted in an explanatory
   * comment on purpose — assertions about the pattern must see code only.
   */
  const serverCode = (function stripComments() {
    let inBlock = false;
    return server.split('\n').map(function(line) {
      const t = line.trim();
      if (inBlock) { if (t.endsWith('*/')) inBlock = false; return ''; }
      if (t.startsWith('/*')) { if (!t.endsWith('*/')) inBlock = true; return ''; }
      if (t.startsWith('//') || t.startsWith('*')) return '';
      return line;
    }).join('\n');
  })();

  /**
   * Line number (1-based) of a serverCode offset. Comment lines are blanked
   * rather than removed, so line numbering matches the real file.
   */
  function lineAt(idx) { return serverCode.slice(0, idx).split('\n').length; }

  // ═══════════════════════════════════════════════════════════════════════════
  // F2 — HASH CORRECTNESS (behavioural, against src/integrity.js)
  //
  // The defect: JSON.stringify(payload, Object.keys(payload).sort()). The array
  // argument is a REPLACER — a recursive property allowlist — not a key sorter.
  // Built from top-level keys only, every nested object serialized as {}.
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\nF2 hash correctness (integrity.js behavioural)');

  /** The pre-fix hash, reproduced here so the fixtures can be proven meaningful. */
  function brokenHash(p) {
    return crypto.createHash('sha256')
      .update(JSON.stringify(p, Object.keys(p).sort())).digest('hex');
  }

  test('integrity.js exports canonicalize and hashPayload as functions', function() {
    assert(typeof canonicalize === 'function', 'F2 regression: integrity.canonicalize is not a function');
    assert(typeof hashPayload  === 'function', 'F2 regression: integrity.hashPayload is not a function');
  });

  test('hashPayload returns a bare lowercase sha256 hex digest', function() {
    const h = hashPayload({ a: 1 });
    assert(/^[0-9a-f]{64}$/.test(h), 'F2 regression: hashPayload must return 64 lowercase hex chars, got: ' + h);
  });

  test('hashPayload is deterministic across calls', function() {
    const p = { input: 'x', memory: { k: [1, 2, { z: 3 }] } };
    assert(hashPayload(p) === hashPayload(p),
      'F2 regression: hashPayload is not deterministic — the chain cannot be verified');
  });

  test('fixture is valid: the pre-fix hash really did collide on nested content', function() {
    // Guards the guard. If this ever stops colliding the tests below would pass
    // vacuously and would no longer prove anything about the defect.
    const a = { input: 'transfer', memory: { amount: 10,      to: 'alice'    } };
    const b = { input: 'transfer', memory: { amount: 1000000, to: 'attacker' } };
    assert(brokenHash(a) === brokenHash(b),
      'F2 test fixture no longer reproduces the replacer defect — rewrite the fixture');
  });

  test('nested value difference changes the hash', function() {
    const a = { input: 'transfer', memory: { amount: 10,      to: 'alice'    } };
    const b = { input: 'transfer', memory: { amount: 1000000, to: 'attacker' } };
    assert(hashPayload(a) !== hashPayload(b),
      'F2 regression: nested payload content is not covered by the hash — a $10 transfer to alice ' +
      'and a $1,000,000 transfer to attacker hash identically, so tamper-evidence does not hold');
  });

  test('deeply nested (4 levels) difference changes the hash', function() {
    const a = { l1: { l2: { l3: { l4: 'original' } } } };
    const b = { l1: { l2: { l3: { l4: 'tampered'  } } } };
    assert(hashPayload(a) !== hashPayload(b),
      'F2 regression: deeply nested payload content is not covered by the hash');
  });

  test('difference inside an array of objects changes the hash', function() {
    const a = { steps: [{ n: 1, act: 'read'  }, { n: 2, act: 'approve' }] };
    const b = { steps: [{ n: 1, act: 'read'  }, { n: 2, act: 'reject'  }] };
    assert(hashPayload(a) !== hashPayload(b),
      'F2 regression: content inside arrays of objects is not covered by the hash');
  });

  test('array element order changes the hash', function() {
    const a = { steps: [{ n: 1 }, { n: 2 }] };
    const b = { steps: [{ n: 2 }, { n: 1 }] };
    assert(hashPayload(a) !== hashPayload(b),
      'F2 regression: array order is not covered by the hash — replay order can be rewritten silently');
  });

  test('a populated nested object does not hash the same as an empty one', function() {
    // This is the exact signature of the replacer defect: nested objects
    // collapsing to {} before hashing.
    const withContent = { input: 'x', memory: { secret: 'value', amount: 42 } };
    const emptied     = { input: 'x', memory: {} };
    assert(hashPayload(withContent) !== hashPayload(emptied),
      'F2 regression: a payload with a nested object hashes the same as one where that object is ' +
      'empty — nested objects are being serialized as {}');
  });

  test('top-level key order does NOT change the hash (canonicalisation holds)', function() {
    const a = { alpha: 1, beta: 2, gamma: 3 };
    const b = { gamma: 3, alpha: 1, beta: 2 };
    assert(hashPayload(a) === hashPayload(b),
      'F2 regression: key order changed the hash — canonicalisation is broken, ' +
      'independently produced hashes will disagree across SDKs');
  });

  test('nested key order does NOT change the hash (recursive canonicalisation)', function() {
    const a = { outer: { p: 1, q: 2, r: { s: 3, t: 4 } } };
    const b = { outer: { r: { t: 4, s: 3 }, q: 2, p: 1 } };
    assert(hashPayload(a) === hashPayload(b),
      'F2 regression: nested key order changed the hash — canonicalize() is not sorting recursively');
  });

  test('canonicalize emits nested content rather than collapsing to {}', function() {
    const c = canonicalize({ input: 'x', memory: { secret: 'v', amount: 42 } });
    assert(c.indexOf('"secret":"v"') !== -1 && c.indexOf('"amount":42') !== -1,
      'F2 regression: canonicalize() dropped nested keys — got: ' + c);
    assert(c.indexOf('"memory":{}') === -1,
      'F2 regression: canonicalize() serialized a populated nested object as {} — got: ' + c);
  });

  test('null is distinguishable from an absent key', function() {
    assert(hashPayload({ a: 1, b: null }) !== hashPayload({ a: 1 }),
      'F2 regression: an explicit null hashes the same as a missing key — deletions are invisible');
  });

  test('a string value does not hash the same as the equivalent number', function() {
    assert(hashPayload({ amount: '1000' }) !== hashPayload({ amount: 1000 }),
      'F2 regression: type confusion — "1000" and 1000 hash identically');
  });

  // Every field of the documented payload shape must be covered.
  console.log('\nF2 documented payload shape {input, output, memory, variables}');
  const BASE_PAYLOAD = {
    input:     'approve the loan',
    output:    'approved',
    memory:    { applicant: 'alice', amount: 10, risk: { score: 0.2, band: 'low' } },
    variables: { region: 'eu', flags: ['a', 'b'] },
  };
  const MUTATIONS = [
    ['input',                function(p) { p.input = 'reject the loan'; }],
    ['output',               function(p) { p.output = 'rejected'; }],
    ['memory.amount',        function(p) { p.memory.amount = 1000000; }],
    ['memory.risk.score',    function(p) { p.memory.risk.score = 0.99; }],
    ['memory.risk.band',     function(p) { p.memory.risk.band = 'high'; }],
    ['variables.region',     function(p) { p.variables.region = 'us'; }],
    ['variables.flags[1]',   function(p) { p.variables.flags[1] = 'c'; }],
  ];
  const baseHash = hashPayload(BASE_PAYLOAD);
  MUTATIONS.forEach(function(m) {
    test('tampering with ' + m[0] + ' changes the hash', function() {
      const clone = JSON.parse(JSON.stringify(BASE_PAYLOAD));
      m[1](clone);
      assert(hashPayload(clone) !== baseHash,
        'F2 regression: tampering with ' + m[0] + ' is not detected by the payload hash');
    });
  });

  // End-to-end: the same defect seen through the chain verifier.
  console.log('\nF2 tamper detection through verifyChain');

  function commitFixture(payload) {
    const ts = '2026-01-01T00:00:00Z';
    const ph = hashPayload(payload);
    const ih = hashEnvelope(buildEnvelope(ph, null, 'dm_agent', 'default', ts));
    return { id: 'c1', payload: payload, payload_hash: ph, integrity_hash: ih,
             agent_id: 'dm_agent', key_id: 'default', timestamp: ts };
  }

  test('an untampered commit verifies as intact', function() {
    const c = commitFixture({ input: 'transfer', memory: { amount: 10, to: 'alice' } });
    const r = verifyChain([c]);
    assert(r.chain_intact === true,
      'F2 regression: a correctly hashed commit fails verification — broken_at=' + r.broken_at);
  });

  test('nested tampering after commit is caught by verifyChain', function() {
    const c = commitFixture({ input: 'transfer', memory: { amount: 10, to: 'alice' } });
    // Rewrite only nested content, leaving the stored hashes untouched — this
    // is exactly what went undetected before the fix.
    c.payload = { input: 'transfer', memory: { amount: 1000000, to: 'attacker' } };
    const r = verifyChain([c]);
    assert(r.chain_intact === false,
      'F2 regression: verifyChain reports a chain intact after nested payload content was rewritten — ' +
      'the tamper-evidence guarantee does not hold');
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // F2 — static: the broken replacer must not come back in server.js
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\nF2 broken replacer pattern (static, code lines only)');

  // JSON.stringify(x, Object.keys(x).sort()) — may span several lines.
  const REPLACER_RE = /JSON\.stringify\(\s*([A-Za-z_$][\w$]*)\s*,\s*Object\.keys\(\s*\1\s*\)\s*\.sort\(\)\s*\)/g;

  const replacerHits = (function() {
    const hits = []; let m;
    REPLACER_RE.lastIndex = 0;
    while ((m = REPLACER_RE.exec(serverCode)) !== null) {
      hits.push({ variable: m[1], line: lineAt(m.index) });
    }
    return hits;
  })();

  test('explanatory comments are not mistaken for code', function() {
    // The fix deliberately quotes the broken pattern in a comment at the commit
    // route. If comment stripping stopped working, the scan below would report
    // a phantom hit and the real signal would be lost.
    assert(server.indexOf('JSON.stringify(payload, Object.keys(payload).sort())') !== -1,
      'the explanatory comment documenting the F2 defect was removed from src/server.js');
    assert(serverCode.indexOf('JSON.stringify(payload, Object.keys(payload).sort())') === -1,
      'comment stripping failed — the commented example is being scanned as code');
  });

  test('no NEW broken-replacer hash site in src/server.js', function() {
    const unexpected = replacerHits.filter(function(h) {
      return F2_KNOWN_UNFIXED.indexOf(h.variable) === -1;
    });
    assert(unexpected.length === 0,
      'F2 regression: JSON.stringify(x, Object.keys(x).sort()) is a REPLACER, not a sorter — ' +
      'nested content would not be covered by the hash. Use hashPayload()/canonicalize() from ' +
      'src/integrity.js. Found at: ' +
      unexpected.map(function(h) { return h.variable + ' (line ' + h.line + ')'; }).join(', '));
  });

  test('the three fixed F2 sites still route through integrity.js', function() {
    const commitBody = bodyOf("app.post('/api/commit'");
    assert(commitBody, 'POST /api/commit route not found');
    assert(commitBody.indexOf('hashPayload(resolvedPayload)') !== -1,
      'F2 regression: POST /api/commit no longer hashes the payload with hashPayload()');

    const exportBody = bodyOf("app.get('/api/export/:ctxId'");
    assert(exportBody, 'GET /api/export/:ctxId route not found');
    assert(/chainHash[\s\S]{0,200}canonicalize\(stableData\)/.test(exportBody),
      'F2 regression: the export bundle chainHash no longer uses canonicalize(stableData)');

    const chatIdx = serverCode.indexOf('async function commitWorkspaceChat');
    assert(chatIdx > 0, 'commitWorkspaceChat() not found');
    const chatBody = serverCode.slice(chatIdx, chatIdx + 4000);
    assert(chatBody.indexOf('hashPayload(payload)') !== -1,
      'F2 regression: commitWorkspaceChat() no longer hashes the payload with hashPayload()');
  });

  test('every integrity.js helper that server.js calls is actually exported', function() {
    // A rename in integrity.js would leave the destructured binding undefined
    // and break hashing at runtime. node --check does not catch this.
    const m = integrityImport;
    assert(m, "server.js no longer destructures require('./integrity')");
    const names = m[1].split(',').map(function(s) { return s.trim(); }).filter(Boolean);
    assert(names.length > 0, 'no names imported from ./integrity');
    names.forEach(function(name) {
      // Only names that are actually called must exist — unused legacy bindings
      // are reported separately, not failed here.
      const called = new RegExp('\\b' + name + '\\s*\\(').test(serverCode.replace(m[0], ''));
      if (!called) return;
      assert(typeof integrity[name] === 'function',
        'F2 regression: server.js calls ' + name + '() but src/integrity.js does not export it — ' +
        'the binding is undefined and hashing will throw at runtime');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // F4 — OWNERSHIP GUARDS on id-taking routes
  //
  // Every route queries through supabaseService (service role), which bypasses
  // RLS. Authorization must be enforced in application code. The guard must
  // also appear AFTER the req.params destructuring: placing it before is a
  // runtime ReferenceError that node --check does not catch.
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\nF4 ownership guards on id-taking routes');

  test('assertOwnsCommit() helper exists and returns null for non-owners', function() {
    assert(/async function assertOwnsCommit\s*\(/.test(serverCode),
      'F4 regression: assertOwnsCommit() helper is gone — ownership cannot be enforced');
    assert(/async function callerAgentIds\s*\(/.test(serverCode),
      'F4 regression: callerAgentIds() helper is gone');
  });

  const OWNERSHIP_ROUTES = [
    ["app.get('/api/replay/:ctxId'",               'ctxId'],
    ["app.get('/api/export/:ctxId'",               'ctxId'],
    ["app.get('/api/bundle/:ctxId'",               'ctxId'],
    ["app.get('/api/content/:ctxId'",              'ctxId'],
    ["app.get('/api/lineage/:ctxId'",              'ctxId'],
    ["app.get('/api/retention/:ctxId'",            'ctxId'],
    ["app.get('/api/commits/:commitId/signature'", 'commitId'],
  ];

  OWNERSHIP_ROUTES.forEach(function(entry) {
    const sig    = entry[0];
    const idVar  = entry[1];
    const label  = sig.replace(/^app\.\w+\('/, '').replace(/'$/, '');

    test(label + ' calls assertOwnsCommit()', function() {
      const body = bodyOf(sig);
      assert(body, 'route not found: ' + sig);
      assert(body.indexOf('assertOwnsCommit(') !== -1,
        'F4 regression: ' + label + ' has no assertOwnsCommit() call — any valid credential ' +
        'can read any tenant\'s record by id (IDOR)');
    });

    test(label + ' guards on the id from req.params', function() {
      const body = bodyOf(sig);
      assert(body, 'route not found: ' + sig);
      const call = body.match(/assertOwnsCommit\(\s*req\s*,\s*([^)\s]+)\s*\)/);
      assert(call, 'F4 regression: ' + label + ' assertOwnsCommit() is not called as (req, <id>)');
      const arg = call[1];
      assert(arg === idVar || arg === 'req.params.' + idVar,
        'F4 regression: ' + label + ' guards on "' + arg + '" but the route id is "' + idVar +
        '" — the guard is checking the wrong value');
    });

    test(label + ' guard is placed AFTER the req.params destructuring', function() {
      const body = bodyOf(sig);
      assert(body, 'route not found: ' + sig);
      const gIdx  = body.indexOf('assertOwnsCommit(');
      assert(gIdx > -1, 'F4 regression: ' + label + ' has no assertOwnsCommit() call at all');
      const call  = body.match(/assertOwnsCommit\(\s*req\s*,\s*([^)\s]+)\s*\)/);
      const arg   = call ? call[1] : '';
      const dMatch = body.match(/const\s*\{[^}]*\}\s*=\s*req\.params/);

      if (arg.indexOf('req.params.') === 0) {
        // Reads straight off req.params — no temporal dead zone to violate.
        assert(true);
        return;
      }
      assert(dMatch,
        'F4 regression: ' + label + ' guards on the bare identifier "' + arg +
        '" but never destructures req.params — ReferenceError at runtime');
      const dIdx = body.indexOf(dMatch[0]);
      assert(dIdx < gIdx,
        'F4 regression: ' + label + ' calls assertOwnsCommit(req, ' + arg + ') BEFORE ' +
        '"' + dMatch[0] + '" — this is a ReferenceError on every request, so the route is ' +
        'dead and the guard never runs. node --check does not catch this.');
    });

    test(label + ' acts on the guard result (404, not just a bare call)', function() {
      const body = bodyOf(sig);
      assert(body, 'route not found: ' + sig);
      const gIdx = body.indexOf('assertOwnsCommit(');
      assert(gIdx > -1, 'F4 regression: ' + label + ' has no assertOwnsCommit() call at all');
      const prefix = body.slice(Math.max(0, gIdx - 40), gIdx);
      assert(/(if\s*\(\s*!?\s*(await\s+)?$)|(=\s*(await\s+)?$)/.test(prefix),
        'F4 regression: ' + label + ' calls assertOwnsCommit() but discards the result — ' +
        'the same "computed and never used" defect as F3');
      const after = body.slice(gIdx, gIdx + 250);
      assert(after.indexOf('404') !== -1,
        'F4 regression: ' + label + ' does not return 404 when the guard fails. 404 rather than ' +
        '403 so the route does not confirm that someone else\'s id exists.');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // F3 — SHARE OWNERSHIP
  // agentIds was built under a comment claiming the check existed. It didn't.
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\nF3 share ownership');

  const shareBody = bodyOf("app.post('/api/share/:ctxId'");

  test('POST /api/share/:ctxId still computes agentIds', function() {
    assert(shareBody, 'POST /api/share/:ctxId route not found');
    assert(/const\s+agentIds\s*=/.test(shareBody),
      'F3 regression: agentIds is no longer computed in POST /api/share/:ctxId');
  });

  test('POST /api/share/:ctxId USES agentIds (referenced more than once)', function() {
    assert(shareBody, 'POST /api/share/:ctxId route not found');
    const uses = (shareBody.match(/\bagentIds\b/g) || []).length;
    assert(uses > 1,
      'F3 regression: agentIds is computed and then discarded (' + uses + ' reference' +
      (uses === 1 ? '' : 's') + ' found). Any authenticated caller could publish any tenant\'s ' +
      'commit and read it, with full payloads, at the unauthenticated /chain/:shareId and /r/:id routes.');
  });

  test('POST /api/share/:ctxId checks agentIds against the commit\'s agents', function() {
    assert(shareBody, 'POST /api/share/:ctxId route not found');
    assert(/agentIds\.includes\(\s*commit\.(from_agent|to_agent)\s*\)/.test(shareBody),
      'F3 regression: agentIds is referenced but never compared against commit.from_agent / ' +
      'commit.to_agent — ownership is not actually enforced');
  });

  test('POST /api/share/:ctxId enforces ownership BEFORE inserting the share row', function() {
    assert(shareBody, 'POST /api/share/:ctxId route not found');
    const checkIdx  = shareBody.search(/agentIds\.includes\(/);
    const insertIdx = shareBody.indexOf("from('shared_chains')");
    assert(checkIdx > -1,  'F3 regression: no agentIds.includes() ownership check found');
    assert(insertIdx > -1, "shared_chains insert not found in POST /api/share/:ctxId");
    assert(checkIdx < insertIdx,
      'F3 regression: the ownership check runs after the shared_chains insert — the record is ' +
      'published before the caller is authorized');
  });

  test('POST /api/share/:ctxId returns 404 (not 403) on a foreign commit', function() {
    assert(shareBody, 'POST /api/share/:ctxId route not found');
    const checkIdx = shareBody.search(/agentIds\.includes\(/);
    const branch   = shareBody.slice(checkIdx, checkIdx + 250);
    assert(branch.indexOf('404') !== -1,
      'F3 regression: the ownership branch must return 404 — 403 confirms that someone else\'s id exists');
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // F1 — PROVISION must never bind to an existing account
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\nF1 provision must not bind to an existing account');

  const provisionBody = bodyOf("app.post('/api/provision'");

  test('POST /api/provision route exists and is unauthenticated (so it must self-guard)', function() {
    assert(provisionBody, 'POST /api/provision route not found');
    assert(provisionBody.indexOf('requireAuth') === -1 && provisionBody.indexOf('requireApiKey') === -1,
      'provision auth model changed — re-review F1 assumptions');
  });

  test('POST /api/provision returns 409 for an already-registered email', function() {
    assert(provisionBody, 'POST /api/provision route not found');
    assert(provisionBody.indexOf('409') !== -1,
      'F1 regression: POST /api/provision no longer returns 409 for an already-registered email');
    assert(/already been registered|email_exists/.test(provisionBody),
      'F1 regression: the already-registered branch is gone from POST /api/provision');
  });

  test('POST /api/provision never looks up an existing account', function() {
    assert(provisionBody, 'POST /api/provision route not found');
    assert(provisionBody.indexOf('listUsers(') === -1,
      'F1 regression: POST /api/provision calls listUsers() — this route is unauthenticated, so ' +
      'anyone could POST a stranger\'s address and receive a live API key bound to their account');
    assert(!/users\s*\??\.\s*find\(/.test(provisionBody),
      'F1 regression: POST /api/provision searches the existing user list');
    assert(!/\.auth\.admin\.getUserBy/.test(provisionBody),
      'F1 regression: POST /api/provision looks up an existing account by identifier');
  });

  test('POST /api/provision assigns userId only from the newly created user', function() {
    assert(provisionBody, 'POST /api/provision route not found');
    const assigns = provisionBody.match(/\buserId\s*=\s*[^=][^;\n]*/g) || [];
    assert(assigns.length > 0, 'F1 regression: no userId assignment found in POST /api/provision');
    assigns.forEach(function(a) {
      assert(/authData\s*\.?\s*\??\.?\s*user/.test(a),
        'F1 regression: userId is assigned from something other than the newly created user: "' +
        a.trim() + '" — provisioning may only ever create a NEW account');
    });
  });

  test('POST /api/provision issues no API key on the already-registered path', function() {
    assert(provisionBody, 'POST /api/provision route not found');
    const errIdx = provisionBody.indexOf('if (authError)');
    const newIdx = provisionBody.search(/\buserId\s*=\s*authData/);
    assert(errIdx > -1, 'F1 regression: the authError branch is gone from POST /api/provision');
    assert(newIdx > errIdx,
      'F1 regression: userId is assigned before the authError branch is handled');
    const errBranch = provisionBody.slice(errIdx, newIdx);
    assert(errBranch.indexOf('generateApiKey') === -1,
      'F1 regression: an API key is generated inside the already-registered branch');
    assert(!/\buserId\s*=/.test(errBranch),
      'F1 regression: the already-registered branch assigns userId — it must return 409 and stop');
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // F5 — PUBLIC PROOF GATE on GET /r/:traceId
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\nF5 public proof gate on /r/:traceId');

  const rBody = bodyOf("app.get('/r/:traceId'");

  test('findActiveShare() helper exists', function() {
    assert(/async function findActiveShare\s*\(/.test(serverCode),
      'F5 regression: findActiveShare() helper is gone — the /r/ share gate cannot work');
  });

  test('findActiveShare() rejects expired shares', function() {
    const fIdx = serverCode.indexOf('async function findActiveShare');
    const fn   = serverCode.slice(fIdx, fIdx + 1400);
    assert(fn.indexOf('expires_at') !== -1,
      'F5 regression: findActiveShare() no longer checks expires_at — expired links stay public');
  });

  test('GET /r/:traceId calls findActiveShare()', function() {
    assert(rBody, 'GET /r/:traceId route not found');
    assert(rBody.indexOf('findActiveShare(') !== -1,
      'F5 regression: GET /r/:traceId does not call findActiveShare() — this route is ' +
      'unauthenticated, so every record in the system becomes publicly readable by id');
  });

  test('GET /r/:traceId gates BEFORE reading any commit data', function() {
    assert(rBody, 'GET /r/:traceId route not found');
    const gateIdx   = rBody.indexOf('findActiveShare(');
    const selectIdx = rBody.indexOf("from('commits')");
    assert(gateIdx > -1,   'F5 regression: no findActiveShare() call in GET /r/:traceId');
    assert(selectIdx > -1, "commits query not found in GET /r/:traceId");
    assert(gateIdx < selectIdx,
      'F5 regression: GET /r/:traceId queries commits before checking the share gate');
  });

  test('GET /r/:traceId returns 404 when no active share exists', function() {
    assert(rBody, 'GET /r/:traceId route not found');
    const gateIdx = rBody.indexOf('findActiveShare(');
    const after   = rBody.slice(gateIdx, gateIdx + 500);
    assert(/if\s*\(\s*!\s*shareRow\s*\)/.test(after),
      'F5 regression: the result of findActiveShare() is not checked — the gate is inert');
    assert(after.indexOf('404') !== -1,
      'F5 regression: GET /r/:traceId does not return 404 when the record was never shared');
  });

  test('GET /r/:traceId returns the whole payload, not a cherry-picked allowlist', function() {
    assert(rBody, 'GET /r/:traceId route not found');
    assert(/payload:\s*c\.payload\b/.test(rBody),
      'F5 regression: GET /r/:traceId no longer returns the stored payload directly');
    [['convTitle', /convTitle:\s*c\.payload/],
     ['_source',   /_source:\s*c\.payload/],
     ['platform',  /platform:\s*c\.payload/]].forEach(function(pair) {
      assert(!pair[1].test(rBody),
        'F5 regression: the payload allowlist is back — "' + pair[0] + '" is being cherry-picked ' +
        'into a synthetic payload object. Non chat-shaped records (a loan decision, a trade) ' +
        'render as an empty object under a "chain intact" banner, which defeats the proof.');
    });
  });

  // ── advisory notes (do not fail the build) ─────────────────────────────────
  if (F2_KNOWN_UNFIXED.length) {
    console.log('\n  ! F2 OUTSTANDING: ' + replacerHits
      .filter(function(h) { return F2_KNOWN_UNFIXED.indexOf(h.variable) !== -1; })
      .map(function(h) { return h.variable + ' at src/server.js:' + h.line; })
      .join(', ') + ' still uses the broken replacer (allowlisted in F2_KNOWN_UNFIXED).');
  }
  (function deadIntegrityImports() {
    const m = integrityImport;
    if (!m) return;
    const dead = m[1].split(',').map(function(s) { return s.trim(); })
      .filter(Boolean).filter(function(n) { return integrity[n] === undefined; });
    if (dead.length) {
      console.log('  ! server.js imports ' + dead.join(', ') +
        " from ./integrity, which does not export them (currently unused, so dormant).");
    }
  })();

  return { passed: passed, failed: failed };
}

module.exports = { run: run };

if (require.main === module) {
  console.log('\nDarkMatter security regression suite');
  const r = run();
  console.log('\n' + '-'.repeat(50));
  console.log('Passed: ' + r.passed + '  Failed: ' + r.failed + '  Total: ' + (r.passed + r.failed));
  if (r.failed > 0) { console.error('\n✗ SOME TESTS FAILED'); process.exit(1); }
  else { console.log('\n✓ ALL TESTS PASSED'); }
}
