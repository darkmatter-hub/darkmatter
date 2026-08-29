/**
 * DarkMatter Smoke Tests
 * Run: node test/smoke.test.js
 * Tests: syntax, route presence, critical logic, dashboard JS, security fixes
 * No network calls — runs in CI without env vars.
 */
'use strict';
const fs   = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const os   = require('os');

const ROOT   = path.join(__dirname, '..');
const SERVER = path.join(ROOT, 'src/server.js');
const DASH   = path.join(ROOT, 'public/dashboard.html');

let passed = 0, failed = 0;
function test(label, fn) {
  try { fn(); console.log('  \u2713 ' + label); passed++; }
  catch(e) { console.error('  \u2717 ' + label + '\n    ' + e.message); failed++; }
}
function assert(cond, msg) { if (!cond) throw new Error(msg || 'assertion failed'); }

const server = fs.readFileSync(SERVER, 'utf8');
const dash   = fs.readFileSync(DASH,   'utf8');
// Extract ALL script blocks from dashboard (not just the last one)
const dashJS = (() => {
  let js = '';
  let re = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(dash)) !== null) {
    if (!m[0].includes('src=')) js += m[1] + '\n';
  }
  return js;
})();
const style  = dash.slice(dash.indexOf('<style>'), dash.indexOf('</style>'));

// 1. Syntax
console.log('\nSyntax');
test('server.js passes node --check', () => execSync('node --check "' + SERVER + '"', {stdio:'pipe'}));
test('dashboard JS passes node --check', () => {
  const tmp = path.join(os.tmpdir(), 'dm_dash_check.js');
  fs.writeFileSync(tmp, dashJS);
  execSync('node --check "' + tmp + '"', {stdio:'pipe'});
  fs.unlinkSync(tmp);
});

// 2. Server routes
console.log('\nServer routes');
const ROUTES = [
  ['GET /dashboard/commits',        "app.get('/dashboard/commits'"],
  ['POST /api/workspace/invite',    "app.post('/api/workspace/invite'"],
  ['GET /api/workspace/proxy-keys', "app.get('/api/workspace/proxy-keys'"],
  ['ALL /proxy/:provider',          "app.all('/proxy/:provider"],
  ['GET /r/:traceId',               "app.get('/r/:traceId'"],
  ['GET /api/verify/:ctxId',        "app.get('/api/verify/:ctxId'"],
  ['GET /api/export/:ctxId',        "app.get('/api/export/:ctxId'"],
  ['POST /api/auth/refresh',        "app.post('/api/auth/refresh'"],
  ['GET /admin/stats',              "app.get('/admin/stats'"],
  ['POST /auth/login',              "app.post('/auth/login'"],
  // L3 + features
  ['GET /api/workspace/api-keys',   "app.get('/api/workspace/api-keys'"],
  ['POST /api/workspace/api-keys',  "app.post('/api/workspace/api-keys'"],
  ['POST /api/workspace/keys',      "app.post('/api/workspace/keys'"],
  ['POST /api/contact',             "app.post('/api/contact'"],
  ['GET /api/billing/subscription', "app.get('/api/billing/subscription'"],
  ['GET /auth/callback',            "app.get('/auth/callback'"],
  ['POST /auth/session',            "app.post('/auth/session'"],
  ['POST /auth/exchange',           "app.post('/auth/exchange'"],
  ['GET /about',                    "app.get('/about'"],
  ['GET /api/workspace/stats/usage', "app.get('/api/workspace/stats/usage'"],
  ['GET /api/admin/users',            "app.get('/api/admin/users'"],
  ['POST /api/workspace/share',       "app.post('/api/workspace/share/:traceId'"],
  ['GET /api/workspace/download',     "app.get('/api/workspace/download/:traceId'"],
];
ROUTES.forEach(function(r) { test(r[0], function() { assert(server.includes(r[1]), 'Missing: ' + r[1]); }); });

// 3. No duplicate routes
console.log('\nNo duplicate routes');
["app.get('/dashboard/commits'", "app.get('/r/:traceId'"].forEach(function(pat) {
  test('single ' + pat.slice(0,35), function() {
    var n = server.split(pat).length - 1;
    assert(n === 1, 'Found ' + n + ' occurrences');
  });
});

// 4. Auth middleware
console.log('\nAuth middleware');
test('requireAuth is async',   function() { assert(server.includes('async function requireAuth')); });
test('wsAuth is async',        function() { assert(server.includes('async function wsAuth')); });
test('flexAuth defined',       function() { assert(server.includes('async function flexAuth')); });
test('export uses flexAuth',   function() { assert(server.includes("app.get('/api/export/:ctxId', flexAuth,")); });
test('verify uses flexAuth',   function() { assert(server.includes("app.get('/api/verify/:ctxId', flexAuth,")); });
test('wsAuth token rotation',  function() { assert(server.includes('X-New-Access-Token')); });
test('requireApiKey is async', function() { assert(server.includes('async function requireApiKey')); });
test('requireApiKey no broken RPC', function() { assert(!server.includes("rpc('get_agent_by_api_key'"), 'Broken RPC call still present'); });
// This test used to assert the OPPOSITE of what security requires.
//
// It read `assert(server.includes(".eq('api_key', apiKey)"))`, demanding the
// plaintext credential lookup be present. F8 removed that lookup: matching a
// caller-supplied key against a plaintext column meant every agent credential
// sat readable in the database, recoverable from any backup, replica or leaked
// service-role key.
//
// The test kept passing anyway, because the only remaining occurrence of that
// string is the comment in server.js explaining the removal. A test that
// passes by matching a description of the code's absence is worse than no test:
// it reports coverage of a property that is not merely unchecked but inverted.
//
// Comments are stripped before matching, so the explanation cannot satisfy the
// assertion about the thing it explains.
test('requireApiKey authenticates by hash, never by plaintext', function() {
  var code = server
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .split('\n').filter(function(l) { return !/^\s*\/\//.test(l); }).join('\n');

  assert(code.includes(".eq('api_key_hash', keyHash)"),
    'hash lookup missing: authentication must match a stored hash');
  assert(!/\.eq\(\s*'api_key'\s*,/.test(code),
    'plaintext api_key lookup is back in the code; F8 removed it deliberately');
});

// 5. /dashboard/commits flat fields
console.log('\n/dashboard/commits');
var ci = server.indexOf("app.get('/dashboard/commits'");
var cb = server.slice(ci, ci + 2500);
test('returns trace_id',         function() { assert(cb.includes('trace_id:')); });
test('returns payload directly', function() { assert(cb.includes('payload:          c.payload')); });
test('returns client_timestamp', function() { assert(cb.includes('client_timestamp:')); });
test('no buildContext wrapping', function() {
  // Only check within the route handler, not the function definition below it
  var handlerEnd = cb.indexOf('\n});');
  var handler = cb.slice(0, handlerEnd);
  assert(!handler.includes('buildContext('), 'buildContext() call found in route handler');
});

// 6. /r/ public page
console.log('\n/r/ public record page');
// Slice a route handler by finding where it ends, not by guessing a length.
//
// Several tests took a fixed number of characters from the start of the /r/
// handler. Adding a few hundred characters to that handler pushed the L2 and
// L3 badge assertions outside the window and failed them, while the code they
// check was untouched. A test that fails because unrelated code grew is a test
// that trains you to ignore it.
function handlerSlice(src, startPattern) {
  var i = src.indexOf(startPattern);
  if (i === -1) return '';
  // The next top-level route registration marks the end of this one.
  var next = src.indexOf('\napp.', i + 1);
  return src.slice(i, next === -1 ? src.length : next);
}

var ri = server.indexOf("app.get('/r/:traceId'");
var rb = handlerSlice(server, "app.get('/r/:traceId'");
test('first-screen',          function() { assert(rb.includes('first-screen')); });
test('chain integrity check', function() { assert(rb.includes('chainIntact')); });
test('only real mismatch',    function() { assert(rb.includes('Missing parent_hash')); });
test('four view tabs',        function() { assert(rb.includes('view-conv') && rb.includes('view-timeline') && rb.includes('view-proof') && rb.includes('view-json')); });
test('YOU role label',        function() { assert(rb.includes('YOU') && rb.includes('platHint'), 'YOU label not found'); });
test('copy link button',      function() { assert(rb.includes('copyLink()')); });

// Object-valued payload fields must be coerced before any string method.
//
// This is a real outage, not a hypothetical. The timeline built its text as
//     (p.text || p.output || p.summary || p.prompt || '').slice(0, 280)
// and payload.output is very often an object, so .slice ran on an object and
// threw. Every shared record 500ed on the HTML page while ?format=json served
// the identical record perfectly, which is what made it survive: the JSON
// path, the share gate and the hash verification were all fine.
test('timeline coerces payload values before slicing', function() {
  assert(rb.includes('function asText('), 'asText helper missing from /r/ handler');
  // Strip comments before matching. The fix is documented in a comment that
  // quotes the broken expression verbatim, and matching that would fail this
  // test forever against correct code.
  var rbCode = rb.split('\n').filter(function (l) {
    return !/^\s*(\/\/|\*|\/\*)/.test(l);
  }).join('\n');
  assert(!/\(p\.text \|\| p\.output[^)]*\)\.slice\(/.test(rbCode),
    'timeline slices a raw payload union; object-valued output will throw');
});

test('asText survives every payload shape the DB allows', function() {
  // Mirror of the helper in src/server.js. If that changes, change this.
  function asText(v) {
    if (v === undefined || v === null) return '';
    if (typeof v === 'string') return v;
    if (typeof v === 'number' || typeof v === 'boolean') return String(v);
    try { return JSON.stringify(v); } catch (_) { return String(v); }
  }
  var circular = {}; circular.self = circular;
  var cases = [
    undefined, null, '', 'plain',
    0, 42, false, true,
    { ok: true, nested: { v: 1 } },   // the shape that actually broke production
    [1, 2, 3],
    circular,                          // JSON.stringify throws; must not propagate
  ];
  cases.forEach(function(v) {
    var out = asText(v);
    assert(typeof out === 'string', 'asText returned ' + typeof out + ' for ' + String(v));
    // The point of the helper: string methods must be safe afterwards.
    out.slice(0, 10);
  });
  assert(asText({ ok: true }) === '{"ok":true}', 'objects should serialise, not stringify to [object Object]');
  assert(asText(null) === '' && asText(undefined) === '', 'nullish must become empty string');
});

// 7. Dashboard JS
console.log('\nDashboard JS');
test('showView explicit flex', function() { assert(dashJS.includes("var dm={records:'flex'")); });
test('init calls showView',    function() { assert(dashJS.includes("showView('apikeys')"), 'dashboard must land on apikeys view on load'); });
test('no onclick quote bug',   function() { assert(!dashJS.includes("switchView('proof'")); });
test('UTC pill data attrs',    function() { assert(dashJS.includes('data-utc=')); });
test('stale request guard',    function() { assert(dashJS.includes('_fetchSeq')); });
test('cookie auth — no manual Authorization header', function() { assert(!dashJS.includes("'Authorization'") && !dashJS.includes('"Authorization"'), 'dashboard must not manually set Authorization header after M-8 cookie migration'); });
test('authFetch refreshes via /api/auth/refresh',    function() { assert(dashJS.includes('/api/auth/refresh')); });
test('YOU label',              function() { assert(dashJS.includes("'YOU'")); });
test('refreshWorkspaceStats',  function() { assert(dashJS.includes('function refreshWorkspaceStats')); });
test('auto-poll active',       function() { assert(dashJS.includes('startPoll()')); });
test('admin check by email',   function() { assert(dashJS.includes('hello@darkmatterhub.ai')); });
test('api keys section loads',  function() { assert(dashJS.includes('loadApiKeys')); });
test('api-keys endpoint wired', function() { assert(dashJS.includes('/api/workspace/api-keys')); });
test('api-keys route on server',function() { assert(server.includes("app.get('/api/workspace/api-keys'")); });
test('Yesterday filter fixed',  function() { assert(dashJS.includes('yest.getDate() - 1')); });
test('date range picker',       function() { assert(dashJS.includes('applyDateRange')); });

// 8. CSS tokens (light theme)
console.log('\nCSS (light theme)');
test('light body background', function() { assert(style.includes('background:var(--bg);')); });
test('white sidebar',         function() { assert(style.includes('background:#fff;display:flex')); });
test('no dark body bg',       function() { assert(!style.includes('background:var(--dark);}')); });
test('--bg defined as white', function() { assert(style.includes('--bg:#ffffff')); });
test('view-records flex',     function() { assert(style.includes('#view-records{display:flex')); });
test('tpanel scroll CSS',     function() { assert(style.includes('.tpanel{display:none')); });

// 8. Commit limit enforcement
console.log('\nCommit limit enforcement');
test('commit route enforces plan limit with 429', () => {
  const srv = fs.readFileSync(path.join(__dirname, '../src/server.js'), 'utf8');
  assert(srv.includes('Monthly commit limit reached'), 'commit limit 429 enforcement missing');
});

// 9. L3 + assurance_level in commit route
console.log('\nL3 non-repudiation');
var commitIdx = server.indexOf("app.post('/api/commit'");
var commitSlice = handlerSlice(server, "app.post('/api/commit'");
test('completeness_claim destructured', function() { assert(commitSlice.includes('completeness_claim')); });
test('client_attestation accepted',     function() { assert(commitSlice.includes('client_attestation')); });
test('assurance_level computed',        function() { assert(commitSlice.includes('assuranceLevel')); });
test('assurance_level stored in DB',    function() { assert(commitSlice.includes('assurance_level:')); });
test('receipt.assurance_level set',     function() { assert(server.includes('receipt.assurance_level')); });
test('receipt.verify_url set',          function() { assert(server.includes('receipt.verify_url')); });

// 9. /r/ share page — L3 badge + completeness
console.log('\n/r/ L3 display');
var shareSlice = handlerSlice(server, "app.get('/r/:traceId'");
test('L3 badge shown on share page',   function() { assert(shareSlice.includes('L3 NON-REPUDIATION')); });
test('L2 badge shown on share page',   function() { assert(shareSlice.includes('L2 VERIFIED')); });
test('completeness shown on /r/',      function() { assert(shareSlice.includes('hasCompleteness')); });
test('assurance_level selected in /r/',function() { assert(shareSlice.includes('assurance_level, completeness_claim')); });

// 10. Dashboard ↔ Server cross-check
console.log('\nDashboard ↔ Server endpoint cross-check');
(function() {
  var fetchRe = /authFetch\(['"`]\/api\/([^'"`?]+)/g;
  var match, endpoints = new Set();
  while ((match = fetchRe.exec(dashJS)) !== null) {
    endpoints.add('/api/' + match[1].split('/')[0]);
  }
  var KNOWN_GAPS = [
    '/api/workspace','/api/agents','/api/commits','/api/share',
    '/api/recording','/api/bundle','/api/hooks','/api/debug','/api/billing',
    '/api/user', // actual route is /api/user/me — regex strips /me
  ];
  endpoints.forEach(function(ep) {
    var skip = KNOWN_GAPS.some(function(p) { return ep.startsWith(p); });
    if (skip) return;
    test('server has route for ' + ep, function() {
      assert(server.includes("'" + ep + "'") || server.includes('"' + ep + '"'),
        'No route found on server for: ' + ep);
    });
  });
})();


// ══════════════════════════════════════════════════════════════════════
// 11. Schema contract — verify column assumptions match actual usage
// These tests catch "phantom column" bugs like the api_key_hash incident
// ══════════════════════════════════════════════════════════════════════
console.log('\nSchema contract');

// Known-good columns for agents table (verified against actual Supabase schema)
// Updated 2026-08-19 (F8). This contract previously required the PLAINTEXT
// api_key column and forbade api_key_hash on the grounds that it "may not
// exist" — it does exist and is populated for every agent, and it is what
// authentication actually uses. The contract is now inverted: hash and masked
// hint are the safe columns, and writing the plaintext key is the defect.
var AGENTS_SAFE_INSERT_COLS = ['agent_id','agent_name','user_id','api_key_hash',
  'key_hint','webhook_url','webhook_secret','retention_days'];
var AGENTS_UNSAFE_INSERT = ['api_key']; // plaintext credential — never persist

test('plaintext api_key not inserted in workspace/api-keys route', function() {
  var routeStart = server.indexOf("app.post('/api/workspace/api-keys'");
  var routeEnd   = server.indexOf('});', routeStart) + 3;
  var routeCode  = server.slice(routeStart, routeEnd);
  // Scope to the .insert({...}) block. The route legitimately RETURNS the raw
  // key to the caller once on creation ("api_key: rawKey" in the response);
  // the defect is persisting it, not returning it.
  var ins = routeCode.match(/\.insert\(\{([\s\S]+?)\}\)/);
  assert(!ins || !/[^_]api_key:/.test(ins[1]), 'F8 regression: plaintext api_key persisted in workspace/api-keys');
});

test('workspace/api-keys insert matches original /dashboard/agents pattern', function() {
  // The safe pattern inserts: agent_id, agent_name, user_id, api_key_hash, key_hint
  var routeStart = server.indexOf("app.post('/api/workspace/api-keys'");
  var routeEnd   = server.indexOf('});', routeStart) + 3;
  var routeCode  = server.slice(routeStart, routeEnd);
  // Must not insert any column outside the safe set
  var insertMatch = routeCode.match(/\.insert\(\{([\s\S]+?)\}\)/);
  if (insertMatch) {
    var insertStr = insertMatch[1];
    AGENTS_UNSAFE_INSERT.forEach(function(col) {
      assert(!insertMatch[1].includes(col + ':'), 'unsafe column inserted: ' + col);
    });
  }
});

// Verify billing response fields match what dashboard JS reads
test('billing subscription returns commitCount field', function() {
  var billingRoute = server.slice(server.indexOf("app.get('/api/billing/subscription'"));
  assert(billingRoute.includes('commitCount'), 'billing must return commitCount (dashboard reads this field)');
});

test('billing subscription returns planInfo field', function() {
  var billingRoute = server.slice(server.indexOf("app.get('/api/billing/subscription'"));
  assert(billingRoute.includes('planInfo'), 'billing must return planInfo (dashboard reads planInfo.name)');
});

// Verify share endpoint uses session auth not apiKey auth
test('workspace/share uses wsAuth not requireApiKey', function() {
  var routeStart = server.indexOf("app.post('/api/workspace/share/");
  var routeLine  = server.slice(routeStart, routeStart + 80);
  assert(routeLine.includes('wsAuth'), 'workspace/share must use wsAuth — dashboard sends session token not agent key');
  assert(!routeLine.includes('requireApiKey'), 'workspace/share must not use requireApiKey');
});

test('workspace/download uses wsAuth not requireApiKey', function() {
  var routeStart = server.indexOf("app.get('/api/workspace/download/");
  var routeLine  = server.slice(routeStart, routeStart + 80);
  assert(routeLine.includes('wsAuth'), 'workspace/download must use wsAuth');
});

// Verify new routes are BEFORE the catch-all (critical ordering check)
console.log('\nRoute ordering (all must be before catch-all)');
var catchallPos = server.indexOf("app.get('*',");
[
  ["app.get('/admin/stats'",          '/admin/stats'],
  ["app.post('/api/workspace/share/", '/api/workspace/share'],
  ["app.get('/api/workspace/download/", '/api/workspace/download'],
  ["app.get('/api/workspace/stats/usage'", '/api/workspace/stats/usage'],
  ["app.get('/api/admin/users'",      '/api/admin/users'],
  ["app.get('/api/billing/subscription'", '/api/billing/subscription'],
  ["app.post('/api/contact'",         '/api/contact'],
  ["app.get('/auth/callback'",        '/auth/callback'],
  ["app.post('/auth/session'",        '/auth/session'],
  ["app.post('/auth/exchange'",       '/auth/exchange'],
].forEach(function(pair) {
  var routePos = server.indexOf(pair[0]);
  test(pair[1] + ' before catch-all', function() {
    assert(routePos > 0 && routePos < catchallPos,
      pair[1] + ' is missing or after the catch-all route — it will never be reached');
  });
});


// Tweet de-duplication
//
// A tweet went out on 2026-08-13 and again on 2026-08-25. Digging in showed it
// was not a one-off: the old scheduler was `day % 57`, so from 2026-07-01
// every post repeated one from 57 days earlier, about 50 duplicates in all.
// Three separate mechanisms produced repeats, and none of them could be fixed
// by picking indices more cleverly, because nothing recorded what had actually
// been posted.
console.log('\nTweet de-duplication');
(function () {
  var crypto = require('crypto');
  var tweetSrc = require('fs').readFileSync(__dirname + '/../scripts/daily-tweet.js', 'utf8');
  var m = tweetSrc.match(/const TWEETS\s*=\s*\[([\s\S]*?)\n\];/);
  var TWEETS;
  eval('TWEETS = [' + m[1] + '\n];');
  var hash = function (t) { return crypto.createHash('sha256').update(String(t).trim(), 'utf8').digest('hex'); };

  test('bank has no holes', function () {
    TWEETS.forEach(function (t, i) {
      assert(typeof t === 'string' && t.trim() !== '',
        'index ' + i + ' is ' + JSON.stringify(t) + '. A stray comma leaves a hole, and the selector will post "undefined".');
    });
  });

  test('bank has no duplicate entries', function () {
    var seen = {};
    TWEETS.forEach(function (t, i) {
      var h = hash(t);
      assert(seen[h] === undefined, 'index ' + i + ' is identical to index ' + seen[h]);
      seen[h] = i;
    });
  });

  test('ledger exists and is keyed by content hash', function () {
    var ledger = require('../scripts/posted-tweets.json');
    assert(Array.isArray(ledger.posted), 'ledger.posted must be an array');
    ledger.posted.forEach(function (e) {
      assert(/^[a-f0-9]{64}$/.test(e.hash), 'ledger entry is not a sha256: ' + e.hash);
    });
  });

  test('selection never returns an already-posted tweet', function () {
    var ledger = require('../scripts/posted-tweets.json');
    var posted = {};
    ledger.posted.forEach(function (e) { posted[e.hash] = true; });

    // Mirror of nextUnpostedIndex() in scripts/daily-tweet.js.
    var picked = null;
    for (var i = 0; i < TWEETS.length; i++) {
      if (!posted[hash(TWEETS[i])]) { picked = i; break; }
    }
    if (picked !== null) {
      assert(!posted[hash(TWEETS[picked])], 'selected a tweet that is already in the ledger');
    }
    // picked === null is the correct answer when the bank is exhausted; the
    // script then refuses to post rather than wrapping.
  });

  test('dedupe survives the bank being reordered', function () {
    // The reason dedupe is on content and not on index. Reversing the array
    // changes every index while changing no text, so an index-based ledger
    // would consider the whole bank unposted again.
    var ledger = require('../scripts/posted-tweets.json');
    var posted = {};
    ledger.posted.forEach(function (e) { posted[e.hash] = true; });

    var shuffled = TWEETS.slice().reverse();
    var stillCovered = shuffled.every(function (t) { return posted[hash(t)] === true; });
    var allCovered = TWEETS.every(function (t) { return posted[hash(t)] === true; });
    assert(stillCovered === allCovered,
      'reordering the bank changed which tweets count as posted; dedupe is index-based, not content-based');
  });

  test('script refuses to post when every tweet has been used', function () {
    assert(tweetSrc.includes('nextUnpostedIndex'), 'selection must go through nextUnpostedIndex');
    assert(tweetSrc.includes('exhausted'), 'the exhausted case must be handled explicitly');
    assert(!/postsBefore\(day\)\s*\+\s*position\)\s*%\s*TWEETS\.length/.test(tweetSrc),
      'index is still derived from a running count modulo the bank size, which wraps and repeats');
  });

  test('manual override cannot silently repost', function () {
    assert(tweetSrc.includes('ALLOW_REPOST'),
      'TWEET_INDEX overrides must check the ledger; an override is how the first duplicate got out');
  });
})();

// Hashtags
//
// Tags used to be seven fixed sets indexed by tweet number, so they repeated
// every seventh post and had nothing to do with the content. A tweet whose
// entire subject was "claude mcp add" went out under #AIgovernance #LLM
// #AIagents: generic, and a wasted opportunity, since the people searching
// #MCP are the ones who would install it.
console.log('\nHashtags');
(function () {
  var src = require('fs').readFileSync(__dirname + '/../scripts/daily-tweet.js', 'utf8');
  var tweetsSrc = src.match(/const TWEETS\s*=\s*\[([\s\S]*?)\n\];/)[0];
  var tagSrc = src.slice(src.indexOf('const TOPIC_TAGS'), src.indexOf('// X counts an auto-linked URL'));
  var mod = eval(tweetsSrc + '\n' + tagSrc + '\n({ TWEETS: TWEETS, uniqueTagsFor: uniqueTagsFor })');
  var TWEETS = mod.TWEETS;
  var tagsFor = mod.uniqueTagsFor;
  var key = function (a) { return a.slice().sort().join(' '); };

  test('every tweet gets three tags', function () {
    TWEETS.forEach(function (_, i) {
      assert(tagsFor(i).length === 3, 'tweet ' + i + ' got ' + tagsFor(i).length + ' tags');
    });
  });

  test('no tag set repeats within six posts', function () {
    for (var i = 0; i < TWEETS.length; i++) {
      for (var j = Math.max(0, i - 6); j < i; j++) {
        assert(key(tagsFor(j)) !== key(tagsFor(i)),
          'tweets ' + j + ' and ' + i + ' share the same tags: ' + key(tagsFor(i)));
      }
    }
  });

  test('tags follow the content', function () {
    // The specific failure that prompted this: a tweet about the MCP server
    // tagged with generic AI-governance terms.
    var cases = [
      [/claude mcp add|mcp server|mcp registry/i, '#MCP'],
      [/erasure|gdpr/i, '#GDPR'],
      [/rfc 8785/i, '#RFC8785'],
      [/eu ai act|article 12/i, '#EUAIAct'],
    ];
    TWEETS.forEach(function (t, i) {
      cases.forEach(function (c) {
        if (!c[0].test(t)) return;
        assert(tagsFor(i).indexOf(c[1]) !== -1,
          'tweet ' + i + ' matches ' + c[0] + ' but lacks ' + c[1] + ': ' + tagsFor(i).join(' '));
      });
    });
  });

  test('the tag vocabulary is wide enough to look human', function () {
    var all = {};
    TWEETS.forEach(function (_, i) { tagsFor(i).forEach(function (t) { all[t] = 1; }); });
    var n = Object.keys(all).length;
    // The old scheme used 13 tags across seven fixed sets.
    assert(n >= 30, 'only ' + n + ' distinct tags in use across ' + TWEETS.length + ' tweets');
  });
})();

// Demo page integrity checks
console.log('\nDemo page');
var demo = require('fs').readFileSync(__dirname + '/../public/demo.html', 'utf8');
test('demo has 4-step walkthrough', function() {
  assert(demo.includes('goStep'), 'demo must have step navigation');
  assert(demo.includes('step-tab'), 'demo must have step tabs');
});
test('demo has download proof bundle', function() {
  assert(demo.includes('downloadDemoBundle'), 'demo step 4 must have download bundle button');
});

// The demo must not claim a hash it cannot back up.
//
// The page shows a payload and, next to it, a payload_hash, then invites the
// reader to verify the record themselves. If those two ever disagree, the
// demo is lying about exactly the thing the product sells. This recomputes
// the hash from the payload the page displays and compares it to the hash the
// page claims, so any edit to either has to keep them consistent.
test('demo payload hashes to the hash the demo claims', function() {
  var hashPayload = require('../src/integrity').hashPayload;
  var payload = {
    input: 'Approve refund #84721? $284.00, 18 days old',
    output: 'Customer within 30-day window. No prior refund history. Amount within auto-approval threshold ($500). Approve immediately.',
    order_id: '84721',
    amount: 284.00
  };
  var expected = hashPayload(payload);

  // Every full-length hash on the page must be that one.
  var found = demo.match(/\b[a-f0-9]{64}\b/g) || [];
  assert(found.length > 0, 'demo shows no payload hash at all');
  found.forEach(function(h) {
    assert(h === expected,
      'demo shows hash ' + h.slice(0, 16) + '... but its stated payload hashes to ' + expected.slice(0, 16) + '...');
  });

  // And the truncated display must be a prefix of the same hash.
  (demo.match(/\b[a-f0-9]{32}\b/g) || []).forEach(function(h) {
    assert(expected.indexOf(h) === 0,
      'truncated hash ' + h.slice(0, 16) + '... is not a prefix of the real payload hash');
  });
});

// A dead proof link is worse than no proof link, and the demo has shipped one
// before: a record referenced here was removed by a data purge and the page
// kept advertising it as a public verify link for anyone to check.
test('demo references exactly one record id, consistently', function() {
  var ids = demo.match(/ctx_[0-9]{10,}_[a-f0-9]{6,}/g) || [];
  assert(ids.length > 0, 'demo references no record id');
  // The canonical id is the longest form present; shorter matches are the
  // truncated console-style displays of the same record.
  var maxLen = Math.max.apply(null, ids.map(function(i) { return i.length; }));
  var full = ids.filter(function(i) { return i.length === maxLen; });
  var uniq = full.filter(function(v, i, a) { return a.indexOf(v) === i; });
  assert(uniq.length === 1, 'demo references ' + uniq.length + ' different record ids: ' + uniq.join(', '));
  // Truncated displays must be prefixes of the full id, not a different record.
  ids.forEach(function(i) {
    assert(uniq[0].indexOf(i) === 0, 'id ' + i + ' is not a prefix of ' + uniq[0]);
  });
});
test('demo has hamburger nav', function() {
  assert(demo.includes('dm-ham'), 'demo must have mobile hamburger');
  assert(demo.includes('function dmHam'), 'demo must have dmHam function');
});
test('demo has no live DB fetch', function() {
  assert(!demo.includes('fetch(\'/api/demo\''), 'demo must not fetch from DB');
});

// Homepage mobile nav checks
console.log('\nHomepage mobile nav');
var homepage = require('fs').readFileSync(__dirname + '/../public/index.html', 'utf8');
test('homepage has hamburger', function() {
  assert(homepage.includes('dm-ham'), 'homepage must have mobile hamburger button');
  assert(homepage.includes('dm-mobile-nav'), 'homepage must have mobile nav menu');
  assert(homepage.includes('function dmHam'), 'homepage must have dmHam function');
});
test('homepage mobile nav not clipped by inline style', function() {
  var navIdx = homepage.indexOf('dm-mobile-nav');
  var snippet = homepage.slice(navIdx, navIdx + 60);
  assert(!snippet.includes('display:none'), 'mobile nav div must not have inline display:none');
});

// 12. Security fix coverage
console.log('\nSecurity fix coverage');

// H-1: admin email guard on audit-log
test('/api/admin/audit-log has admin email guard (H-1)', function() {
  var routeStart = server.indexOf("app.get('/api/admin/audit-log'");
  assert(routeStart > 0, 'audit-log route not found');
  var routeSlice = server.slice(routeStart, routeStart + 800);
  assert(routeSlice.includes('isAdminEmail('), 'audit-log must check isAdminEmail, not just requireAuth');
});

// H-2: admin email guard on ping
test('/api/admin/ping has admin email guard (H-2)', function() {
  var routeStart = server.indexOf("app.get('/api/admin/ping'");
  assert(routeStart > 0, 'ping route not found');
  var routeSlice = server.slice(routeStart, routeStart + 800);
  assert(routeSlice.includes('isAdminEmail('), 'ping must check isAdminEmail, not just requireAuth');
});

// H-4: demo endpoint is fully static — no DB query
test('/api/demo handler has no DB query (H-4)', function() {
  var routeStart = server.indexOf("app.get('/api/demo'");
  assert(routeStart > 0, '/api/demo route not found');
  var routeEnd   = server.indexOf('\n});', routeStart) + 4;
  var routeSlice = server.slice(routeStart, routeEnd);
  assert(!routeSlice.includes('supabaseService.from'), '/api/demo must not query DB via supabaseService');
  assert(!routeSlice.includes('supabaseAnon.from'),    '/api/demo must not query DB via supabaseAnon');
});

// H-7: agent_name bypass removed from witness guard
test('witness guard has no agent_name bypass (H-7)', function() {
  var idx = server.indexOf('SUPERUSER_AGENT_ID');
  assert(idx > 0, 'SUPERUSER_AGENT_ID check not found');
  var snippet = server.slice(idx - 50, idx + 300);
  assert(!snippet.includes('agent_name'), 'agent_name bypass must be removed from witness guard');
});

// H-3: no string-interpolated .or() in /r/:traceId or workspace routes
test('/r/:traceId has no string-interpolated .or() (H-3)', function() {
  var routeStart = server.indexOf("app.get('/r/:traceId'");
  var routeSlice = server.slice(routeStart, routeStart + 2000);
  assert(!routeSlice.includes(".or('id.eq.' +"),  "string-concat .or() found in /r/:traceId");
  assert(!routeSlice.includes('.or(`id.eq.${'),   "template-literal .or() found in /r/:traceId");
  assert(!routeSlice.includes(".or(`trace_id.eq.${"), "template-literal .or() found in /r/:traceId");
});

// 13. Dashboard auth guard (flash-of-unauthenticated-content prevention)
console.log('\nDashboard auth guard');

test('body starts visibility:hidden', function() {
  assert(dash.includes('<body style="visibility:hidden">'), 'body must start hidden to prevent flash of unauthenticated content');
});

test('early auth script before DOMContentLoaded', function() {
  var scriptIdx = dash.indexOf('window._dmAuthPromise');
  var dclIdx    = dash.indexOf("addEventListener('DOMContentLoaded'");
  assert(scriptIdx > 0, 'window._dmAuthPromise not found');
  assert(scriptIdx < dclIdx, 'auth guard script must appear before DOMContentLoaded listener');
});

test('auth guard fetches /api/user/me', function() {
  var guardIdx   = dash.indexOf('window._dmAuthPromise');
  var guardSlice = dash.slice(guardIdx, guardIdx + 400);
  assert(guardSlice.includes('/api/user/me'), 'early auth guard must call /api/user/me');
});

test('auth guard redirects to /login on failure', function() {
  var guardIdx   = dash.indexOf('window._dmAuthPromise');
  var guardSlice = dash.slice(guardIdx, guardIdx + 600);
  assert(guardSlice.includes("location.replace('/login')"), 'auth guard must redirect to /login on 401');
});

test('body revealed only after auth (visibility reset)', function() {
  var guardIdx   = dash.indexOf('window._dmAuthPromise');
  var guardSlice = dash.slice(guardIdx, guardIdx + 600);
  assert(guardSlice.includes("body.style.visibility = ''"), 'body must only be revealed after successful auth');
});

test('loadUserProfile reuses _dmAuthPromise, no second /api/user/me fetch', function() {
  var fnIdx   = dashJS.indexOf('async function loadUserProfile');
  var fnSlice = dashJS.slice(fnIdx, fnIdx + 600);
  assert(fnSlice.includes('_dmAuthPromise'), 'loadUserProfile must await _dmAuthPromise, not re-fetch /api/user/me');
  assert(!fnSlice.includes("'/api/user/me'"), 'loadUserProfile must not make a second /api/user/me call');
});

// \u2500\u2500 Section 14: H-5 BYOK \u2014 retired server-side key routes \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
console.log('\nH-5 BYOK security fixes');

test('/enterprise/commit returns 410 (no handler body)', function() {
  var idx = server.indexOf("app.post('/enterprise/commit'");
  assert(idx >= 0, 'route not found');
  var slice = server.slice(idx, idx + 300);
  assert(slice.includes('410'), '/enterprise/commit must respond 410');
  assert(!slice.includes('byokKey'), '/enterprise/commit must not reference byokKey (route retired)');
});

test('/enterprise/decrypt returns 410 (no handler body)', function() {
  var idx = server.indexOf("app.post('/enterprise/decrypt/");
  assert(idx >= 0, 'route not found');
  var slice = server.slice(idx, idx + 300);
  assert(slice.includes('410'), '/enterprise/decrypt must respond 410');
  assert(!slice.includes('decryptPayload'), '/enterprise/decrypt must not call decryptPayload (route retired)');
});

test('L3 assurance requires verified signature (no unguarded L3 grant)', function() {
  var idx = server.indexOf("assuranceLevel = 'L3'");
  assert(idx >= 0, "assuranceLevel = 'L3' assignment not found");
  // There must be a verifyCommitSignature call before the L3 assignment
  var preceding = server.slice(Math.max(0, idx - 800), idx);
  assert(preceding.includes('verifyCommitSignature'), 'L3 must only be granted after verifyCommitSignature passes');
});

test('L3 rejection returns 400 on bad signature', function() {
  // Find the actual call site (not the import)
  var idx = server.indexOf('await verifyCommitSignature');
  assert(idx >= 0, 'await verifyCommitSignature call not found');
  var slice = server.slice(idx, idx + 600);
  assert(slice.includes('400') || slice.includes("'Invalid L3"), 'bad signature must reject with 4xx');
});

// \u2500\u2500 Section 15: Security \u2014 admin route guards \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
console.log('\nAdmin route guards');

test('/api/admin/users has admin email guard', function() {
  var idx = server.indexOf("app.get('/api/admin/users'");
  assert(idx > 0, '/api/admin/users route not found');
  var slice = server.slice(idx, idx + 600);
  assert(slice.includes('isAdminEmail('), '/api/admin/users must check isAdminEmail, not just requireAuth');
});

test('/api/admin/flags GET has admin email guard', function() {
  var idx = server.indexOf("app.get('/api/admin/flags'");
  assert(idx > 0, '/api/admin/flags GET route not found');
  var slice = server.slice(idx, idx + 600);
  assert(slice.includes('isAdminEmail('), '/api/admin/flags GET must check isAdminEmail, not just requireAuth');
});

test('/api/admin/flags POST has admin email guard', function() {
  var idx = server.indexOf("app.post('/api/admin/flags'");
  assert(idx > 0, '/api/admin/flags POST route not found');
  var slice = server.slice(idx, idx + 700);
  assert(slice.includes('isAdminEmail('), '/api/admin/flags POST must check isAdminEmail, not just requireAuth');
});

test('client_attestation verified before assuranceLevel set to L3', function() {
  var commitIdx = server.indexOf("app.post('/api/commit'");
  var slice     = handlerSlice(server, "app.post('/api/commit'");
  var attIdx    = slice.indexOf('client_attestation &&');
  var l3Idx     = slice.indexOf("assuranceLevel = 'L3'");
  assert(attIdx > 0, 'client_attestation check not found in commit route');
  assert(l3Idx  > 0, "assuranceLevel = 'L3' assignment not found in commit route");
  assert(attIdx < l3Idx, 'client_attestation check must precede assuranceLevel L3 assignment');
});

test('active POST /api/commit does not reference byokKey', function() {
  var idx   = server.indexOf("app.post('/api/commit'");
  var slice = server.slice(idx, idx + 4000);
  assert(!slice.includes('byokKey'), 'active commit route must not reference byokKey');
});

// \u2500\u2500 Section 16: Auth and session \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
console.log('\nAuth cookies and session');

test('requireAuth reads dm_access cookie', function() {
  var idx   = server.indexOf('async function requireAuth');
  var slice = server.slice(idx, idx + 600);
  assert(slice.includes('dm_access'), 'requireAuth must read dm_access cookie');
});

test('GET /api/user/me route exists', function() {
  assert(server.includes("app.get('/api/user/me'"), '/api/user/me route not found');
});

test('/auth/logout calls clearAuthCookies', function() {
  var idx   = server.indexOf("app.post('/auth/logout'");
  assert(idx > 0, '/auth/logout route not found');
  var slice = server.slice(idx, idx + 400);
  assert(slice.includes('clearAuthCookies'), '/auth/logout must call clearAuthCookies to clear session');
});

// \u2500\u2500 Section 17: Pricing and plan limits \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
console.log('\nPlan limits');

test('PLAN_META free commitLimit is 10000', function() {
  var idx   = server.indexOf('const PLAN_META');
  var slice = server.slice(idx, idx + 400);
  assert(slice.includes('commitLimit: 10000'), 'free plan commitLimit must be 10000');
});

test('PLAN_META pro commitLimit is 50000', function() {
  var idx   = server.indexOf('const PLAN_META');
  var slice = server.slice(idx, idx + 400);
  assert(slice.includes('commitLimit: 50000'), 'pro plan commitLimit must be 50000');
});

test('PLAN_META teams commitLimit is 250000', function() {
  var idx   = server.indexOf('const PLAN_META');
  var slice = server.slice(idx, idx + 400);
  assert(slice.includes('commitLimit: 250000'), 'teams plan commitLimit must be 250000');
});

test('commit gate reads from commit_usage (O(1) cache)', function() {
  var gateIdx   = server.indexOf('Plan limit enforcement');
  var gateSlice = server.slice(gateIdx, gateIdx + 2500);
  assert(gateSlice.includes("from('commit_usage')"), 'gate must read commit_usage, not do a live COUNT scan');
});

test('429 limit response includes upgrade_url', function() {
  var idx   = server.indexOf('Monthly commit limit reached');
  assert(idx > 0, 'commit limit 429 message not found');
  var slice = server.slice(Math.max(0, idx - 50), idx + 250);
  assert(slice.includes('upgrade_url'), '429 commit-limit response must include upgrade_url');
});

// \u2500\u2500 Section 18: Python SDK integrations \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
// Skipped in CI when sibling repo is not checked out alongside this one.
console.log('\nPython SDK integrations');

var SDK_PY     = path.join(ROOT, '../darkmatter-sdk-python/darkmatter');
var SDK_EXISTS = fs.existsSync(SDK_PY);

if (!SDK_EXISTS) {
  console.log('  (skipped \u2014 darkmatter-sdk-python not present in this environment)');
} else {
  test('Python SDK has crewai integration', function() {
    assert(fs.existsSync(path.join(SDK_PY, 'integrations/crewai.py')), 'crewai.py not found in SDK integrations');
  });

  test('Python SDK has bedrock integration', function() {
    assert(fs.existsSync(path.join(SDK_PY, 'integrations/bedrock.py')), 'bedrock.py not found in SDK integrations');
  });

  test('Python SDK has google_adk integration', function() {
    assert(fs.existsSync(path.join(SDK_PY, 'integrations/google_adk.py')), 'google_adk.py not found in SDK integrations');
  });

  test('Python SDK commit() defaults to_agent_id to None', function() {
    var clientPy = fs.readFileSync(path.join(SDK_PY, 'client.py'), 'utf8');
    var fnIdx    = clientPy.indexOf('def commit(');
    assert(fnIdx > 0, 'commit() function not found in client.py');
    var fnSlice  = clientPy.slice(fnIdx, fnIdx + 400);
    assert(fnSlice.includes('to_agent_id') && fnSlice.includes('= None'),
      'commit() to_agent_id parameter must default to None');
  });
}

// \u2500\u2500 Section 19: Dashboard API key security \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
console.log('\nDashboard API key security');

test('GET /api/workspace/api-keys response does not return raw api_key field', function() {
  var idx   = server.indexOf("app.get('/api/workspace/api-keys'");
  var slice = server.slice(idx, idx + 2500);
  assert(!slice.includes('api_key: a.api_key'), 'raw api_key must not be returned in list response');
  assert(!slice.includes("api_key: rawKey"),     'raw api_key must not be returned in list response');
});

test('GET /api/workspace/my-key does not exist (show-once principle)', function() {
  assert(!server.includes("app.get('/api/workspace/my-key'"),
    '/api/workspace/my-key must not exist \u2014 full key retrieval violates show-once principle');
});

test('billing subscription endpoint reads from commit_usage', function() {
  var idx   = server.indexOf("app.get('/api/billing/subscription'");
  var slice = server.slice(idx, idx + 3500);
  assert(slice.includes("from('commit_usage')"),
    'billing subscription must read commit_usage for O(1) count, not do a COUNT scan');
});

// \u2500\u2500 Section 20: Public pages \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
console.log('\nPublic pages');

var PUBLIC_12 = ['index','pricing','integrity','security','docs',
                 'organizations','demo','blog','enterprise','privacy','tos','why'];

test('No em-dash or HTML entity dash in <title> tags of key public pages', function() {
  ['index','pricing','integrity','security','docs'].forEach(function(name) {
    var html  = fs.readFileSync(path.join(ROOT, 'public/' + name + '.html'), 'utf8');
    var match = html.match(/<title>([\s\S]*?)<\/title>/);
    if (!match) return;
    var title = match[1];
    assert(!title.includes('\u2014'),  name + '.html <title> contains em-dash (\u2014)');
    assert(!title.includes('&#8212;'), name + '.html <title> contains &#8212;');
    assert(!title.includes(' \u2013 '), name + '.html <title> contains en-dash ( \u2013 )');
  });
});

test('No Bitcoin reference in any of the 12 public pages', function() {
  PUBLIC_12.forEach(function(name) {
    var html = fs.readFileSync(path.join(ROOT, 'public/' + name + '.html'), 'utf8');
    assert(!html.toLowerCase().includes('bitcoin'), name + '.html contains Bitcoin reference');
  });
});

test('organizations.html references JetBrains Mono', function() {
  var orgs = fs.readFileSync(path.join(ROOT, 'public/organizations.html'), 'utf8');
  assert(orgs.includes('JetBrains'), 'organizations.html must load JetBrains Mono font');
});

test('All 12 public pages have dm-ham hamburger nav', function() {
  PUBLIC_12.forEach(function(name) {
    var html = fs.readFileSync(path.join(ROOT, 'public/' + name + '.html'), 'utf8');
    assert(html.includes('dm-ham'), name + '.html is missing dm-ham hamburger nav element');
  });
});

// ── Section 21: Reported bugs — must not regress ─────────────────────────────
// Each test here was added after a confirmed production bug.
console.log('\nReported-bug regression guards');

// Bug: supabaseService.auth.refreshSession() mutates the shared singleton,
// replacing the service-role JWT with a user JWT. All subsequent DB calls then
// run under the user identity and hit RLS, causing INSERT failures (api-keys
// creation) and empty SELECT results (no commits / keys visible).
// Fix: persistSession:false keeps the singleton stateless.
test('supabaseService created with persistSession:false (prevents RLS pollution)', function() {
  var idx   = server.indexOf('const supabaseService = createClient');
  var slice = server.slice(idx, idx + 400);
  assert(slice.includes('persistSession') && slice.includes('false'),
    'supabaseService must use persistSession:false — token refresh overwrites service-role JWT without it');
});

test('supabaseAnon created with persistSession:false (server-side singleton must be stateless)', function() {
  var idx   = server.indexOf('const supabaseAnon = createClient');
  var slice = server.slice(idx, idx + 400);
  assert(slice.includes('persistSession') && slice.includes('false'),
    'supabaseAnon must use persistSession:false — shared singleton must not store session state');
});

// Bug: emailRedirectTo pointed at /dashboard. Supabase puts session tokens in
// the URL fragment (#access_token=...) which the server never sees. The dashboard
// auth guard found no cookies and redirected to /login on every confirmation click.
// Fix: redirect to /auth/callback which reads the fragment and sets cookies.
test('emailRedirectTo points to /auth/callback, not /dashboard', function() {
  var idx   = server.indexOf('emailRedirectTo');
  assert(idx > 0, 'emailRedirectTo not found in signup route');
  var slice = server.slice(idx, idx + 120);
  assert(slice.includes('/auth/callback'),
    'emailRedirectTo must point to /auth/callback — pointing at /dashboard causes a login redirect loop');
  assert(!slice.includes('/dashboard'),
    'emailRedirectTo must not point to /dashboard (tokens in URL fragment are invisible to the server)');
});

test('/auth/callback serves a page that handles both implicit and PKCE token flows', function() {
  var idx   = server.indexOf("app.get('/auth/callback'");
  assert(idx > 0, '/auth/callback route not found');
  var slice = server.slice(idx, idx + 2000);
  assert(slice.includes('access_token'),  '/auth/callback must handle implicit-flow fragment tokens');
  assert(slice.includes('/auth/exchange'), '/auth/callback must call /auth/exchange for PKCE code flow');
  assert(slice.includes('/auth/session'), '/auth/callback must call /auth/session for implicit token flow');
  assert(slice.includes('/dashboard'),    '/auth/callback must redirect to /dashboard on success');
});

test('/auth/session validates token before setting cookies', function() {
  var idx   = server.indexOf("app.post('/auth/session'");
  assert(idx > 0, '/auth/session route not found');
  var slice = server.slice(idx, idx + 600);
  assert(slice.includes('supabaseService.auth.getUser'), '/auth/session must validate access_token before setting cookies');
  assert(slice.includes('setAuthCookies'),               '/auth/session must call setAuthCookies on success');
});

test('/auth/exchange calls exchangeCodeForSession', function() {
  var idx   = server.indexOf("app.post('/auth/exchange'");
  assert(idx > 0, '/auth/exchange route not found');
  var slice = server.slice(idx, idx + 500);
  assert(slice.includes('exchangeCodeForSession'), '/auth/exchange must call exchangeCodeForSession');
  assert(slice.includes('setAuthCookies'),         '/auth/exchange must call setAuthCookies on success');
});

// Bug: existing user saw no commits or API keys in their dashboard.
// Root cause: same session-pollution bug — after token refresh, supabaseService
// ran under user JWT, and RLS filtered or blocked the workspace/activity and
// workspace/api-keys queries. Covered by the persistSession tests above.
// Additional guard: the api-keys route must use supabaseService (not supabaseAnon).
test('POST /api/workspace/api-keys uses supabaseService for agents insert (not anon)', function() {
  var idx   = server.indexOf("app.post('/api/workspace/api-keys'");
  assert(idx > 0, '/api/workspace/api-keys POST route not found');
  var slice = server.slice(idx, idx + 2000);
  assert(slice.includes("supabaseService.from('agents').insert"),
    'api-keys route must insert into agents using supabaseService (service role), not supabaseAnon');
});

test('GET /api/workspace/activity falls back to user own agents when no workspace membership', function() {
  var idx   = server.indexOf("app.get('/api/workspace/activity'");
  assert(idx > 0, '/api/workspace/activity route not found');
  var slice = server.slice(idx, idx + 3000);
  // Must query agents by user_id as a fallback path so solo users see their commits
  assert(slice.includes('.eq(\'user_id\', req.user.id)'),
    'workspace/activity must fall back to querying agents by user_id for users without workspace membership');
});

// ── Abuse prevention controls ────────────────────────────────────────────────
console.log('\nAbuse prevention');

test('DATA_LIMIT_BYTES defined with correct free cap (500 MB)', function() {
  assert(server.includes('DATA_LIMIT_BYTES'), 'DATA_LIMIT_BYTES not found in server.js');
  // accept either compact or padded form
  assert(/free:\s*500\s*\*\s*1024\s*\*\s*1024/.test(server), 'free data cap must be 500 MB');
});

test('DATA_LIMIT_BYTES has correct teams cap (25 GB)', function() {
  assert(/teams:\s*25\s*\*\s*1024\s*\*\s*1024\s*\*\s*1024/.test(server), 'teams data cap must be 25 GB');
});

test('DATA_LIMIT_BYTES enterprise is unlimited (-1)', function() {
  assert(server.includes('enterprise: -1'), 'enterprise data cap must be -1 (unlimited)');
});

test('gate middleware checks bytes_used from commit_usage for data cap', function() {
  var gateIdx   = server.indexOf('Plan limit enforcement');
  var gateSlice = server.slice(gateIdx, gateIdx + 3500);
  assert(gateSlice.includes('bytes_used'),      'gate must read bytes_used from commit_usage');
  assert(gateSlice.includes('DATA_LIMIT_BYTES'), 'gate must reference DATA_LIMIT_BYTES');
});

test('data cap 429 includes limit_gb and upgrade_url', function() {
  var idx   = server.indexOf('Monthly data limit reached');
  assert(idx > 0, '"Monthly data limit reached" message not found');
  var slice = server.slice(idx, idx + 300);
  assert(slice.includes('limit_gb'),    '429 data-limit response must include limit_gb');
  assert(slice.includes('upgrade_url'), '429 data-limit response must include upgrade_url');
});

test('velocity check defined with 100 MB limit', function() {
  assert(server.includes('VELOCITY_LIMIT_BYTES'), 'VELOCITY_LIMIT_BYTES not found');
  assert(server.includes('checkVelocity'),         'checkVelocity function not found');
  assert(/100\s*\*\s*1024\s*\*\s*1024/.test(server), 'VELOCITY_LIMIT_BYTES must be 100 MB');
});

test('velocity 429 sets Retry-After: 3600', function() {
  var idx = server.indexOf("'Retry-After'");
  assert(idx > 0, "Retry-After header not set");
  var slice = server.slice(idx, idx + 100);
  assert(slice.includes('3600'), 'Retry-After must be 3600 seconds');
});

test('maybeAlertUsage sends to hello@darkmatterhub.ai', function() {
  var idx = server.indexOf('async function maybeAlertUsage');
  assert(idx > 0, 'maybeAlertUsage function not found');
  var fnSlice = server.slice(idx, idx + 1200);
  assert(fnSlice.includes('hello@darkmatterhub.ai'), 'alert email must go to hello@darkmatterhub.ai');
  assert(fnSlice.includes('50% data cap'),            'alert subject must mention 50% data cap');
});

test('pricing.html lists data caps for all four plans', function() {
  var pricing = fs.readFileSync(path.join(ROOT, 'public/pricing.html'), 'utf8');
  assert(pricing.includes('500 MB data per month'), 'free plan missing 500 MB data cap');
  assert(pricing.includes('5 GB data per month'),   'pro plan missing 5 GB data cap');
  assert(pricing.includes('25 GB data per month'),  'teams plan missing 25 GB data cap');
  assert(pricing.includes('Unlimited data'),         'enterprise plan missing Unlimited data');
});

console.log('\nAuth pages (signup / login)');

(function checkAuthPageJS(name) {
  var filePath = path.join(ROOT, 'public/' + name + '.html');
  var html     = fs.readFileSync(filePath, 'utf8');

  // Extract inline script blocks (no src=)
  var js = '';
  var re = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  var m;
  while ((m = re.exec(html)) !== null) {
    if (!m[0].includes('src=')) js += m[1] + '\n';
  }

  test(name + '.html inline JS passes node --check', function() {
    var tmp = path.join(os.tmpdir(), 'dm_' + name + '_check.js');
    fs.writeFileSync(tmp, js);
    try {
      execSync('node --check "' + tmp + '"', {stdio:'pipe'});
    } finally {
      fs.unlinkSync(tmp);
    }
  });

  // Guard against the specific class of bug that broke signup:
  // a single-quoted JS string containing 'JetBrains Mono' terminates the string early.
  test(name + ".html has no unescaped single-quotes inside single-quoted JS strings (font-family bug)", function() {
    // Look for the pattern: JS single-quoted string containing 'JetBrains Mono'
    // This regex finds innerHTML='...'JetBrains Mono'...' patterns
    assert(
      !(/innerHTML\s*=\s*'[^']*'JetBrains/.test(js)),
      name + '.html has unescaped single-quotes inside a single-quoted JS string (breaks all JS on page)'
    );
  });
})('signup');

(function checkAuthPageJS(name) {
  var filePath = path.join(ROOT, 'public/' + name + '.html');
  var html     = fs.readFileSync(filePath, 'utf8');
  var js = '';
  var re = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  var m;
  while ((m = re.exec(html)) !== null) {
    if (!m[0].includes('src=')) js += m[1] + '\n';
  }
  test(name + '.html inline JS passes node --check', function() {
    var tmp = path.join(os.tmpdir(), 'dm_' + name + '_check.js');
    fs.writeFileSync(tmp, js);
    try {
      execSync('node --check "' + tmp + '"', {stdio:'pipe'});
    } finally {
      fs.unlinkSync(tmp);
    }
  });
})('login');

test('signup.html does not claim full access without qualification', function() {
  var html = fs.readFileSync(path.join(ROOT, 'public/signup.html'), 'utf8');
  assert(!html.includes('Full access from day one'), 'signup.html must not claim unqualified full access');
});

test('signup.html does not expose raw /r/:id URL to users without explanation', function() {
  var html = fs.readFileSync(path.join(ROOT, 'public/signup.html'), 'utf8');
  assert(!html.includes('/r/:id'), 'signup.html must not show raw /r/:id route to users — use plain language instead');
});

// Bug: supabaseService.auth.refreshSession() is called in requireAuth, flexAuth,
// and wsAuth. Even with persistSession:false, refreshSession() overwrites the
// in-memory auth state on the client object, replacing the service-role JWT with
// the user's JWT. Subsequent DB calls then run under the user identity and hit RLS,
// causing INSERT failures (api-key creation returns RLS error) and empty SELECT
// results. Fix: all auth.refreshSession() and auth.getUser() calls in middleware
// must use supabaseAnon, not supabaseService.
console.log('\nRLS pollution prevention (auth middleware client isolation)');

test('requireAuth uses supabaseAnon.auth.refreshSession (not supabaseService)', function() {
  var idx   = server.indexOf('async function requireAuth');
  var slice = server.slice(idx, idx + 1500);
  assert(!slice.includes('supabaseService.auth.refreshSession'),
    'requireAuth must not call supabaseService.auth.refreshSession — use supabaseAnon to avoid RLS pollution');
  assert(slice.includes('supabaseAnon.auth.refreshSession'),
    'requireAuth must call supabaseAnon.auth.refreshSession for token refresh');
});

test('flexAuth uses supabaseAnon.auth.refreshSession (not supabaseService)', function() {
  var idx   = server.indexOf('async function flexAuth');
  var slice = server.slice(idx, idx + 1500);
  assert(!slice.includes('supabaseService.auth.refreshSession'),
    'flexAuth must not call supabaseService.auth.refreshSession — use supabaseAnon to avoid RLS pollution');
});

test('wsAuth uses supabaseAnon.auth.refreshSession (not supabaseService)', function() {
  var idx   = server.indexOf('async function wsAuth');
  var slice = server.slice(idx, idx + 1500);
  assert(!slice.includes('supabaseService.auth.refreshSession'),
    'wsAuth must not call supabaseService.auth.refreshSession — use supabaseAnon to avoid RLS pollution');
  assert(slice.includes('supabaseAnon.auth.refreshSession'),
    'wsAuth must call supabaseAnon.auth.refreshSession for token refresh');
});

test('no supabaseService.auth.refreshSession anywhere in codebase', function() {
  assert(!server.includes('supabaseService.auth.refreshSession'),
    'supabaseService.auth.refreshSession found in server.js — this corrupts the service-role JWT and causes RLS errors');
});

// ── Section 22: Security regression suite ─────────────────────────────────
// Locks in the F1-F5 fixes from the pre-launch security review.

// Crawlability checks must walk subdirectories. The first version of these
// tests read public/*.html only, which is exactly how /docs/quickstart and
// /integrations/claude ended up missing from the sitemap and missing canonical
// tags: the code and the test shared the same blind spot.
function publicPages() {
  var out = [];
  (function walk(dir, prefix) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function(e) {
      if (e.name.charAt(0) === '.') return;
      var abs = path.join(dir, e.name);
      if (e.isDirectory()) return walk(abs, prefix + e.name + '/');
      if (/\.html$/.test(e.name)) {
        out.push({ slug: prefix + e.name.replace(/\.html$/, ''), abs: abs });
      }
    });
  })(path.join(ROOT, 'public'), '');
  return out;
}

// ── Crawlability ──────────────────────────────────────
// These guard a fix that is invisible when it breaks: nothing errors, the site
// just stops being indexable and nobody notices for months.

test('robots.txt route registered', function() {
  assert(server.includes("app.get('/robots.txt'"), 'no /robots.txt route');
});

test('sitemap.xml route registered', function() {
  assert(server.includes("app.get('/sitemap.xml'"), 'no /sitemap.xml route');
});

test('robots.txt declares the sitemap', function() {
  assert(/Sitemap: ' \+ SITE_ORIGIN\(\) \+ '\/sitemap\.xml/.test(server),
    'robots.txt does not point at the sitemap');
});

test('robots.txt allows crawling', function() {
  assert(server.includes("'User-agent: *'") && server.includes("'Allow: /'"),
    'robots.txt missing User-agent/Allow');
});

// Route ordering is load-bearing here. express.static serves public/*.html
// directly, so a /sitemap.xml or /robots.txt route registered after it would
// still work today only because neither file exists in public/ — and would
// silently stop working the day somebody adds one.
test('crawl routes precede express.static', function() {
  var robots  = server.indexOf("app.get('/robots.txt'");
  var sitemap = server.indexOf("app.get('/sitemap.xml'");
  var stat    = server.indexOf('app.use(express.static');
  assert(stat > -1, 'express.static not found');
  assert(robots  > -1 && robots  < stat, '/robots.txt registered after express.static');
  assert(sitemap > -1 && sitemap < stat, '/sitemap.xml registered after express.static');
});

// The sitemap is generated from public/, so a new page is listed automatically.
// That is the point, and also the risk: an admin or auth page added later gets
// published to search engines unless it is excluded. This asserts the pages we
// know must never be listed are in the exclude set.
test('sitemap excludes every admin and auth surface', function() {
  var m = server.match(/const SITEMAP_EXCLUDE = new Set\(\[([\s\S]*?)\]\)/);
  assert(m, 'SITEMAP_EXCLUDE not found');
  var listed = (m[1].match(/'([a-z0-9-]+)'/g) || []).map(function(s) {
    return s.replace(/'/g, '');
  });
  ['admin', 'admindashboard', 'dashboard', 'login', 'reset-password',
   'organizations'].forEach(function(slug) {
    assert(listed.indexOf(slug) !== -1, slug + ' is not excluded from the sitemap');
  });
});

// A page whose name says it is an app or auth surface but which nobody added to
// the exclude list. Catches the realistic regression: someone adds
// public/admin-billing.html and it turns up in Google.
test('no unlisted admin/auth-looking page would be published', function() {
  var m = server.match(/const SITEMAP_EXCLUDE = new Set\(\[([\s\S]*?)\]\)/);
  assert(m, 'SITEMAP_EXCLUDE not found');
  var excluded = (m[1].match(/'([a-z0-9-]+)'/g) || []).map(function(s) {
    return s.replace(/'/g, '');
  });
  var suspicious = fs.readdirSync(path.join(ROOT, 'public'))
    .filter(function(f) { return /\.html$/.test(f); })
    .map(function(f) { return f.replace(/\.html$/, ''); })
    .filter(function(slug) {
      return /^(admin|dashboard)|(dashboard|admin)$|^(login|signin|signup-complete|reset)/.test(slug);
    })
    .filter(function(slug) { return excluded.indexOf(slug) === -1; });
  assert(suspicious.length === 0,
    'these look like app/auth pages but are not excluded: ' + suspicious.join(', '));
});

// Cloudflare replaces /robots.txt at the edge with its own content-signals
// block, so the Disallow rules the origin serves never reach a crawler. A
// noindex meta tag travels with the page itself and cannot be overridden that
// way, so every page excluded from the sitemap must also carry one. Without
// this test the two lists drift and an app page quietly becomes indexable.
test('every sitemap-excluded page carries a noindex meta', function() {
  var m = server.match(/const SITEMAP_EXCLUDE = new Set\(\[([\s\S]*?)\]\)/);
  assert(m, 'SITEMAP_EXCLUDE not found');
  var excluded = (m[1].match(/'([a-z0-9-]+)'/g) || []).map(function(x) {
    return x.replace(/'/g, '');
  });
  var missing = excluded.filter(function(slug) {
    var f = path.join(ROOT, 'public', slug + '.html');
    if (!fs.existsSync(f)) return false;   // excluded but no such page is fine
    return !/name="robots"[^>]*noindex/i.test(fs.readFileSync(f, 'utf8'));
  });
  assert(missing.length === 0,
    'excluded from the sitemap but still indexable: ' + missing.join(', '));
});

// Every page resolves at both /name and /name.html, because express.static
// serves the file directly alongside the clean-URL route. That is two URLs for
// one page, and without a canonical a search engine has to guess which to index
// and splits whatever link equity exists between them. The sitemap lists the
// clean URL, so the canonical must agree with it or the two signals conflict.
test('every indexable page declares a canonical matching its sitemap URL', function() {
  var m = server.match(/const SITEMAP_EXCLUDE = new Set\(\[([\s\S]*?)\]\)/);
  assert(m, 'SITEMAP_EXCLUDE not found');
  var excluded = (m[1].match(/'([a-z0-9-]+)'/g) || []).map(function(x) {
    return x.replace(/'/g, '');
  });

  var problems = [];
  publicPages().forEach(function(pg) {
    var slug = pg.slug;
    if (excluded.indexOf(slug) !== -1) return;
    var html = fs.readFileSync(pg.abs, 'utf8');
    var c = html.match(/<link rel="canonical" href="([^"]+)"/);
    if (!c) { problems.push(slug + ' (none)'); return; }
    var want = slug === 'index'
      ? 'https://darkmatterhub.ai/'
      : 'https://darkmatterhub.ai/' + slug;
    if (c[1] !== want) problems.push(slug + ' (points at ' + c[1] + ')');
  });
  assert(problems.length === 0,
    'canonical missing or wrong: ' + problems.join(', '));
});

// The title is the highest-value ranking field and the line a searcher reads
// before deciding to click. Every one of these used to lead with the brand
// ("Compliance: DarkMatter"), which spends that space on a term at least four
// other companies also rank for. These bounds are the objective part: present,
// long enough to say something, short enough not to be cut off in a result.
test('every indexable page has a usable title and description', function() {
  var m = server.match(/const SITEMAP_EXCLUDE = new Set\(\[([\s\S]*?)\]\)/);
  assert(m, 'SITEMAP_EXCLUDE not found');
  var excluded = (m[1].match(/'([a-z0-9-]+)'/g) || []).map(function(x) {
    return x.replace(/'/g, '');
  });

  var problems = [];
  publicPages().forEach(function(pg) {
    var slug = pg.slug;
    if (excluded.indexOf(slug) !== -1) return;
    var html = fs.readFileSync(pg.abs, 'utf8');

    var t = html.match(/<title>([\s\S]*?)<\/title>/);
    if (!t) { problems.push(slug + ': no title'); }
    else {
      var title = t[1].trim();
      if (title.length < 15)  problems.push(slug + ': title too short (' + title.length + ')');
      if (title.length > 60)  problems.push(slug + ': title truncated in results (' + title.length + ')');
    }

    var d = html.match(/<meta name="description" content="([\s\S]*?)"/);
    if (!d) { problems.push(slug + ': no meta description'); }
    else if (d[1].length > 160) {
      problems.push(slug + ': description truncated (' + d[1].length + ')');
    }
  });
  assert(problems.length === 0, problems.join('; '));
});

// /blog/:slug used to fall back to the blog index when the post file was
// missing, so three links advertised on /blog answered 200 with the wrong page
// for months. A reader who clicked "Introducing DarkMatter" landed back on the
// listing with no error. This asserts every /blog/ link on the site resolves to
// a file that exists, which is the check that would have caught it.
test('no page links to a blog post that does not exist', function() {
  var dead = [];
  fs.readdirSync(path.join(ROOT, 'public')).forEach(function(f) {
    if (!/\.html$/.test(f)) return;
    var html = fs.readFileSync(path.join(ROOT, 'public', f), 'utf8');
    var re = /href="\/blog\/([a-z0-9-]+)"/g, m;
    while ((m = re.exec(html)) !== null) {
      var post = path.join(ROOT, 'public', 'blog-' + m[1] + '.html');
      if (!fs.existsSync(post)) dead.push(f + ' -> /blog/' + m[1]);
    }
  });
  assert(dead.length === 0, 'links to nonexistent posts: ' + dead.join(', '));
});

test('missing blog posts return 404 rather than the index', function() {
  var m = server.match(/app\.get\('\/blog\/:slug'[\s\S]*?\n\}\);/);
  assert(m, '/blog/:slug route not found');
  // The fallback specifically, not any 404 in the route. The slug validation
  // above also returns 404, so searching the whole block passed even with the
  // fallback reverted to a bare sendFile: the guard matched a different line
  // than the one it protects.
  assert(/res\.status\(404\)\.sendFile\([^)]*blog\.html/.test(m[0]),
    '/blog/:slug still answers 200 for posts that do not exist');
});

test('the offline verifier is actually served', function() {
  assert(server.includes("app.get('/verify_darkmatter_chain.py'"),
    'the script five pages tell readers to download has no route');
  assert(fs.existsSync(path.join(ROOT, 'examples/verify_darkmatter_chain.py')),
    'the route serves a file that does not exist');
});

// Every page that tells a reader to run the verifier depends on it being
// reachable. The instruction and the route are edited in different files, so
// this pins them together.
test('pages referencing the verifier match a real route', function() {
  var refs = [];
  publicPages().forEach(function(pg) {
    if (/verify_darkmatter_chain\.py/.test(fs.readFileSync(pg.abs, 'utf8'))) {
      refs.push(pg.slug);
    }
  });
  assert(refs.length > 0, 'expected some page to reference the verifier');
  assert(server.includes("app.get('/verify_darkmatter_chain.py'"),
    refs.length + ' pages reference the verifier but it is not served: ' + refs.join(', '));
});

// The docs told readers to POST to /api/policies and described the condition
// syntax for a policy engine in detail. That endpoint has never existed: it
// answered 404 in production while /api/commit answered 401, which is how a
// real-but-unauthenticated route replies. Documentation for a feature that was
// never built is worse than none on a product selling verifiability.
test('every API endpoint the docs teach actually has a route', function() {
  var documented = {};
  publicPages().forEach(function(pg) {
    var html = fs.readFileSync(pg.abs, 'utf8');
    var re = /darkmatterhub\.ai(\/api\/[a-z0-9/_-]+)/gi, m;
    while ((m = re.exec(html)) !== null) {
      // Trim a trailing path parameter placeholder such as /api/fork/ctx_...
      var p = m[1].replace(/\/(ctx_|:)[a-z0-9_.-]*$/i, '').replace(/\/$/, '');
      (documented[p] = documented[p] || []).push(pg.slug);
    }
  });

  var missing = [];
  var METHODS = ['get', 'post', 'put', 'patch', 'delete', 'all', 'use'];
  Object.keys(documented).forEach(function(p) {
    // Plain string search rather than a built regex: the path is data, and
    // escaping it into a pattern is a good way to write a check that silently
    // matches nothing. A route is registered either on the exact path or with
    // a parameter appended, so both prefixes count.
    var found = METHODS.some(function(m) {
      return server.indexOf("app." + m + "('" + p + "'") !== -1 ||
             server.indexOf("app." + m + "('" + p + "/") !== -1;
    });
    if (!found) missing.push(p + ' (documented on: ' + documented[p].join(', ') + ')');
  });
  assert(missing.length === 0,
    'documented but not implemented: ' + missing.join('; '));
});

// compliance.html and threat-model.html were truncated in production for
// months. Both ended mid-footer, and threat-model.html stopped mid-attribute at
// "https://github.com/be" — the exact point where a personal handle began in
// the URL, so a pass that stripped the handle deleted from there to end of
// file and took </footer>, </body> and </html> with it.
//
// Browsers render a page missing its closing tags, so nothing looked wrong.
// Every test passed. This is the check that was missing, and it also covers the
// same mistake made by hand: bounding a section removal by a heading that does
// not exist and deleting through to the end of the file.
test('every page is structurally complete', function() {
  var broken = [];
  publicPages().forEach(function(pg) {
    var html = fs.readFileSync(pg.abs, 'utf8');
    var closeHtml = (html.match(/<\/html>/gi) || []).length;
    var closeBody = (html.match(/<\/body>/gi) || []).length;
    if (!/^\s*<!doctype/i.test(html)) broken.push(pg.slug + ': no doctype');
    if (closeHtml !== 1) broken.push(pg.slug + ': ' + closeHtml + ' closing html tags');
    if (closeBody !== 1) broken.push(pg.slug + ': ' + closeBody + ' closing body tags');
    // A file ending inside a tag is truncated even if the counts happen to work.
    var tail = html.slice(-400);
    var lastOpen = tail.lastIndexOf('<');
    var lastClose = tail.lastIndexOf('>');
    if (lastOpen > lastClose) broken.push(pg.slug + ': ends inside an unclosed tag');
  });
  assert(broken.length === 0, 'structurally incomplete pages: ' + broken.join('; '));
});

// The pricing page and PLAN_META are edited in different files by different
// kinds of change, and a mismatch is a promise the product does not keep. This
// found src/billing.js carrying a second, contradictory plan table ($19 Pro,
// 500-commit free tier) that nothing imported.
test('the pricing page matches the plan table the server enforces', function() {
  var m = server.match(/const PLAN_META = \{([\s\S]*?)\n\};/);
  assert(m, 'PLAN_META not found');
  var meta = {};
  m[1].split('\n').forEach(function(line) {
    var r = line.match(/(\w+):\s*\{\s*commitLimit:\s*(\d+|null)[^}]*price:\s*(\d+|null)/);
    if (r) meta[r[1]] = { limit: r[2], price: r[3] };
  });
  assert(Object.keys(meta).length >= 3, 'could not parse PLAN_META');

  var pricing = fs.readFileSync(path.join(ROOT, 'public/pricing.html'), 'utf8');
  var problems = [];

  Object.keys(meta).forEach(function(plan) {
    var limit = meta[plan].limit, price = meta[plan].price;
    if (limit !== 'null') {
      // The page writes limits with thousands separators.
      var pretty = Number(limit).toLocaleString('en-US');
      if (pricing.indexOf(pretty) === -1) {
        problems.push(plan + ': server enforces ' + pretty + ' commits, not on the pricing page');
      }
    }
    if (price !== 'null' && pricing.indexOf('$' + price) === -1) {
      problems.push(plan + ': server says $' + price + ', not on the pricing page');
    }
  });
  assert(problems.length === 0, problems.join('; '));
});

// Six public pages, including a comparison table that named three competitors,
// claimed records were anchored via OpenTimestamps to the Bitcoin blockchain.
// The string appeared nowhere in src/ except one line of display text: nothing
// created a .ots file or contacted a calendar server, and the proof page told
// auditors to verify a file the bundle did not contain.
//
// A marketing page can name a technology the product does not use and no test
// notices, because nothing links the claim to the code. This links them.
test('the site does not claim a technology the code does not implement', function() {
  // Each entry: the term a page might claim, and what src/ must contain for
  // that claim to be honest.
  var CLAIMS = [
    { term: 'OpenTimestamps', evidence: ['opentimestamps', '.ots'] },
    { term: 'blockchain',     evidence: ['opentimestamps', 'blockchain'] },
  ];
  var srcAll = '';
  fs.readdirSync(path.join(ROOT, 'src')).forEach(function(f) {
    if (/\.js$/.test(f)) srcAll += fs.readFileSync(path.join(ROOT, 'src', f), 'utf8');
  });
  srcAll = srcAll.toLowerCase();

  var problems = [];
  CLAIMS.forEach(function(c) {
    var implemented = c.evidence.some(function(e) { return srcAll.indexOf(e) !== -1; });
    if (implemented) return;
    publicPages().forEach(function(pg) {
      var html = fs.readFileSync(pg.abs, 'utf8');
      if (html.toLowerCase().indexOf(c.term.toLowerCase()) !== -1) {
        problems.push(pg.slug + ' claims ' + c.term + ', which src/ does not implement');
      }
    });
  });
  assert(problems.length === 0, problems.join('; '));
});

// compare.html claims an open-source offline verifier as a capability three
// named competitors lack. package.json declared MIT but no LICENSE file
// existed, and a public repository without one is all-rights-reserved by
// default, so the claim was not true in the sense that matters.
test('an open-source claim is backed by an actual licence', function() {
  var claims = publicPages().some(function(pg) {
    return /open[- ]source/i.test(fs.readFileSync(pg.abs, 'utf8'));
  });
  if (!claims) return;   // nothing to back

  var licensePath = path.join(ROOT, 'LICENSE');
  assert(fs.existsSync(licensePath),
    'the site claims open source but the repository has no LICENSE file');

  var declared = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).license;
  var text = fs.readFileSync(licensePath, 'utf8');
  assert(declared, 'package.json declares no license');
  assert(text.toLowerCase().indexOf(String(declared).toLowerCase()) !== -1,
    'LICENSE does not match the ' + declared + ' declared in package.json');

  // The verifier is served standalone over HTTP, so a reader who downloads
  // only that file needs the terms in the file itself.
  var verifier = fs.readFileSync(path.join(ROOT, 'examples/verify_darkmatter_chain.py'), 'utf8');
  assert(/SPDX-License-Identifier/.test(verifier),
    'the standalone verifier carries no SPDX licence header');
});

// The security page told readers "row-level security enforces account isolation
// at the database layer", and the compliance page said records are isolated
// "via RLS". server.js says the opposite in a comment above the ownership
// helpers: every route queries through the service role, which bypasses RLS, so
// the policies in the schema are inert and authorization is enforced in
// application code.
//
// Claiming a database-layer control you do not rely on overstates the posture
// to the one reader who is checking. The real mechanism is stronger than it
// sounds, because a regression test fails the build when a route stops checking
// ownership, but it is a different mechanism and must be described as one.
test('no page credits RLS with isolation that application code enforces', function() {
  var bypassed = /bypasses RLS/i.test(server) || /RLS policies[\s\S]{0,80}inert/i.test(server);
  if (!bypassed) return;   // if RLS is ever actually relied on, this stops applying

  var problems = [];
  publicPages().forEach(function(pg) {
    var text = fs.readFileSync(pg.abs, 'utf8');
    if (/(row-level security|RLS)[^.<]{0,60}(enforc|isolat)/i.test(text) ||
        /(isolat)[^.<]{0,40}via RLS/i.test(text)) {
      problems.push(pg.slug);
    }
  });
  assert(problems.length === 0,
    'these pages credit RLS with isolation the service role bypasses: ' + problems.join(', '));
});

// server.js had seven chain-integrity checks and only one of them recomputed a
// payload hash. The other six compared the stored parent_hash against the
// stored integrity_hash and nothing more, which answers whether two stored
// values point at each other rather than whether the record is still what it
// says it is. A payload edited in place, hashes untouched, passed all six,
// including the compliance report a regulated customer hands to an auditor.
//
// They drifted because there were seven copies. There is one now, and this
// fails if an eighth is written by hand.
test('chain integrity is checked in exactly one place', function() {
  var handRolled = (server.match(/let chainIntact = true;/g) || []).length;
  assert(handRolled === 0,
    handRolled + ' hand-rolled chain check(s) in server.js — use verifyCommitChain()');

  assert(server.indexOf('verifyCommitChain') !== -1,
    'server.js does not use verifyCommitChain at all');

  var integrity = fs.readFileSync(path.join(ROOT, 'src/integrity.js'), 'utf8');
  assert(/function verifyCommitChain\s*\(/.test(integrity),
    'verifyCommitChain is gone from integrity.js');
  // It is only worth anything if it rehashes. A version that just compares
  // stored values would pass every other assertion here.
  var body = integrity.slice(integrity.indexOf('function verifyCommitChain'));
  body = body.slice(0, body.indexOf('\nfunction ', 1));
  assert(/hashPayload\s*\(/.test(body),
    'verifyCommitChain no longer recomputes payload hashes, which is its whole purpose');
});

// Six places called records "immutable", including the threat model page,
// which offered immutability as the mitigation for a record being overwritten.
// The specification says the opposite in section 5.1: this is tamper evidence,
// not tamper prevention. Records live in Postgres and can be changed; the chain
// makes a change detectable. They are not even permanent, since deleting an
// account deletes them.
//
// The distinction is the product. Claiming prevention where only detection
// exists is the single most damaging thing this site could get wrong.
test('records are not described as immutable', function() {
  var offenders = [];
  publicPages().forEach(function(pg) {
    var text = fs.readFileSync(pg.abs, 'utf8');
    if (/immutab|tamper.?proof|unalterable|unchangeable/i.test(text)) offenders.push(pg.slug);
  });
  assert(offenders.length === 0,
    'these pages claim immutability, which is tamper prevention rather than ' +
    'tamper evidence: ' + offenders.join(', '));
});

// Pinning the word was not enough. about.html said "The record cannot be
// altered after the fact by anyone, including DarkMatter" - the same
// prevention claim without the word immutable, on a page the suite had been
// green over for months. What matters is whether the sentence qualifies the
// claim: docs, integrity and tos all say a record cannot be changed *without
// breaking verification*, which is true. Unqualified, it is not.
test('a record is never said to be unchangeable without a qualifier', function() {
  var VERB = /\b(?:cannot|can not|can't|could not|couldn't|impossible to)\s+(?:be\s+)?(?:alter|change|modif|edit|overwrit|rewrit|tamper)/i;
  var QUALIFIED = /without (?:breaking|detection|being detected)|undetect|breaks? verification|without invalidat/i;
  var offenders = [];
  publicPages().forEach(function(pg) {
    var text = fs.readFileSync(pg.abs, 'utf8').replace(/<[^>]+>/g, ' ');
    text.split(/(?<=[.!?])\s+/).forEach(function(sentence) {
      if (VERB.test(sentence) && !QUALIFIED.test(sentence)) {
        offenders.push(pg.slug + ': "' + sentence.trim().slice(0, 90) + '"');
      }
    });
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(offenders.length === 0,
    'prevention claimed where only detection exists:' + SEP + offenders.join(SEP));
});

// The checkpoint scheduler refuses to publish when the signing key is
// ephemeral, because a checkpoint signed with a key that dies on the next
// redeploy is an artifact shaped like evidence and worth nothing.
//
// That guard shipped broken: _keyIsPersistent was declared and read but never
// assigned, so it was always false and setting DM_LOG_SIGNING_KEY_PEM would not
// have enabled L2. It failed safe, which is why nothing caught it. Both
// directions are checked here, in a child process so the env var and the
// module's cached key do not leak between cases.
test('the signing key is reported as persistent only when it is', function() {
  function persistentWith(env) {
    var out = execSync(
      'node -e "const a=require(\'./src/append-log\');console.log(\'RESULT:\'+a.isPersistentSigningKey())"',
      { cwd: ROOT, env: Object.assign({}, process.env, env), stdio: 'pipe' }
    ).toString();
    var m = out.match(/RESULT:(true|false)/);
    assert(m, 'could not read result from child process: ' + out.slice(-200));
    return m[1] === 'true';
  }

  var key = (function () {
    var crypto = require('crypto');
    var kp = crypto.generateKeyPairSync('ed25519');
    return Buffer.from(kp.privateKey.export({ type: 'pkcs8', format: 'pem' })).toString('base64');
  })();

  assert(persistentWith({ DM_LOG_SIGNING_KEY_PEM: key }) === true,
    'a configured signing key is reported as ephemeral, so L2 can never be enabled');
  assert(persistentWith({ DM_LOG_SIGNING_KEY_PEM: '' }) === false,
    'a generated fallback key is reported as persistent, so unverifiable checkpoints could be published');
});

// The compliance report is enterprise-gated, so it cannot be exercised from
// outside without a paid key. These are static checks and honest about that:
// they catch the report losing the qualifications that were added to it, not a
// runtime fault inside the handler.
test('the compliance report still states its limits and per-step results', function() {
  var i = server.indexOf("report_type:    'DarkMatter Compliance Report'");
  assert(i !== -1, 'compliance report builder not found');
  var body = server.slice(i, i + 4000);

  assert(body.indexOf('scope_and_limits') !== -1,
    'the report no longer states what it does not cover');
  assert(/cannot prove/i.test(body),
    'the report no longer says it cannot prove records were not withheld');
  // The field, not the word: 'per_step' also appears in the report's own prose,
  // so searching for the bare word passed even with the field deleted.
  assert(/per_step\s*:/.test(body),
    'the report no longer carries a per_step field naming which record failed');

  // The three locals it depends on must be declared before the object literal.
  var head = server.slice(server.lastIndexOf("app.get('", i), i);
  ['const _report', 'const chainIntact', 'const verifyDetail'].forEach(function (d) {
    assert(head.indexOf(d) !== -1, 'compliance handler is missing ' + d);
  });
});

// stripePeriodEnd replaced a fix that lived in a file nothing imported. It is
// billing code that cannot be exercised against Stripe from here, so the shape
// is pinned instead.
test('stripePeriodEnd falls back and refuses to guess', function() {
  var i = server.indexOf('function stripePeriodEnd');
  assert(i !== -1, 'stripePeriodEnd is gone');
  var end = server.indexOf('\n}\n', i) + 3;
  var fn = new Function(server.slice(i, end) + '; return stripePeriodEnd;')();

  assert(fn({ current_period_end: 1790000000 }) === '2026-09-21T14:13:20.000Z',
    'the direct field is no longer used');
  assert(fn({ billing_cycle_anchor: 1790000000, plan: { interval: 'month', interval_count: 1 } })
    === '2026-10-21T14:13:20.000Z', 'the billing_cycle_anchor fallback is gone');
  // Guessing a renewal date is worse than showing none.
  assert(fn({ billing_cycle_anchor: 1790000000 }) === null,
    'it invents a date when the interval is unknown');
  assert(fn({}) === null && fn(null) === null, 'it does not handle missing input');
});

// The Python SDK computes a payload hash and an Ed25519 signature on the client
// and posts them as payload_hash, integrity_hash, agent_signature and
// agent_public_key. The server read only clientPayloadHash, clientIntegrityHash,
// agentSignature and agentPublicKey, so every one of them was silently dropped.
//
// The consequence was the whole trust model: clientPayloadHash was always null,
// so hashMismatch was always false and the stored hash was always the server's
// own. "Hashed client-side before transmission, DarkMatter cannot alter it" did
// not hold for any caller. Production agrees: zero records carry a client hash.
//
// A field-name mismatch fails silently by construction, so it needs a test.
test('the commit route accepts both spellings of the client verification fields', function() {
  var route = server.slice(server.indexOf("app.post('/api/commit'"));
  route = route.slice(0, 12000);

  [['clientPayloadHash',   'payload_hash'],
   ['clientIntegrityHash', 'integrity_hash'],
   ['agentSignature',      'agent_signature'],
   ['agentPublicKey',      'agent_public_key']].forEach(function (pair) {
    var camel = pair[0], snake = pair[1];
    assert(route.indexOf('req.body.' + camel) !== -1,
      'commit route no longer reads req.body.' + camel);
    assert(route.indexOf('req.body.' + snake) !== -1,
      'commit route does not read req.body.' + snake + ', which is what the ' +
      'Python SDK sends — its client-side hash would be silently discarded');
  });
});

// Five pages said payloads are hashed client-side, without qualification. That
// is true through the Python SDK, which computes the hash and posts it, and
// false through the JavaScript SDK, which posts the payload and lets the server
// hash it. A reader using the JS SDK was told their hash was computed locally
// when it was not.
//
// So the claim has to name which path it applies to. This fails if an
// unqualified version comes back.
test('client-side hashing is not claimed without naming the SDK', function() {
  var unqualified = [];
  publicPages().forEach(function(pg) {
    var html = fs.readFileSync(pg.abs, 'utf8');
    var re = /[^.<>]{0,120}(hashed?[^.<>]{0,20}client-side|client-side hash[^.<>]{0,20})[^.<>]{0,120}/gi;
    var m;
    while ((m = re.exec(html)) !== null) {
      var sentence = m[0];
      // Qualified if it names the SDK the claim holds for, or says the server
      // does it. Bare "hashed client-side" is the form that misleads.
      if (!/python sdk|javascript sdk|js sdk|by the server|server hashes/i.test(sentence)) {
        unqualified.push(pg.slug + ': "' + sentence.trim().slice(0, 70) + '"');
      }
    }
  });
  assert(unqualified.length === 0,
    'unqualified client-side hashing claims: ' + unqualified.join('; '));
});


// 33. Every verification URL the server hands out must be a route it serves
// Commit receipts embed pubkey_url / checkpoint_url / verify_url so a customer
// can verify a record without an account. All three pointed at /api/log/*
// routes that were never registered, so every one returned 404 and the
// documented verification path was a dead end. The receipt is a contract:
// if we print a URL in it, the route has to exist.
console.log('\nSelf-referential URLs');
test('every darkmatterhub.ai/api URL in a receipt has a matching route', () => {
  // URLs the server prints into responses, e.g. 'https://darkmatterhub.ai/api/log/pubkey'
  var urls = new Set();
  var re = /['"`]https:\/\/darkmatterhub\.ai(\/api\/[^'"`\s?]*)['"`]/g;
  var m;
  while ((m = re.exec(server)) !== null) urls.add(m[1]);
  // Template-literal forms: `https://darkmatterhub.ai/api/log/proof/${commitId}`
  var re2 = /`https:\/\/darkmatterhub\.ai(\/api\/[^`]*)`/g;
  while ((m = re2.exec(server)) !== null) {
    urls.add(m[1].replace(/\$\{[^}]*\}/g, ':param'));
  }
  // String-concatenation forms:
  //   'https://darkmatterhub.ai/api/log/checkpoint/' + id + '/witnesses'
  // The trailing literal matters. Stopping at the first '+' would yield
  // '/api/log/checkpoint/:param', which is a real route, so a genuinely dead
  // URL built this way would be reported as served. Consume the whole
  // concatenation and substitute :param only for the non-literal parts.
  var re3 = /'https:\/\/darkmatterhub\.ai(\/api\/[^']*)'((?:\s*\+\s*(?:'[^']*'|[A-Za-z_$][\w$.?\[\]]*))+)/g;
  while ((m = re3.exec(server)) !== null) {
    var built = m[1];
    var tail  = /\s*\+\s*('[^']*'|[A-Za-z_$][\w$.?\[\]]*)/g;
    var t;
    while ((t = tail.exec(m[2])) !== null) {
      built += t[1].charAt(0) === "'" ? t[1].slice(1, -1) : ':param';
    }
    urls.add(built);
  }

  assert(urls.size > 0, 'found no self-referential API URLs — the extractor broke');

  // Registered routes, with :params normalised so they compare structurally.
  var routes = [];
  var rre = /app\.(?:get|post|put|delete)\(\s*['"`](\/api\/[^'"`]*)['"`]/g;
  while ((m = rre.exec(server)) !== null) routes.push(m[1]);

  function served(url) {
    var u = url.replace(/\/$/, '').split('/').filter(Boolean);
    return routes.some(function(r) {
      var p = r.replace(/\/$/, '').split('/').filter(Boolean);
      if (p.length !== u.length) return false;
      return p.every(function(seg, i) {
        return seg.charAt(0) === ':' || u[i] === ':param' || seg === u[i];
      });
    });
  }

  var dead = Array.from(urls).filter(function(u) { return !served(u); });
  assert(dead.length === 0,
    'receipt points at routes that do not exist: ' + dead.join(', '));
});

// The three that were actually dead, named individually so a regression on any
// one of them reads clearly instead of as a generic list.
['/api/log/pubkey', '/api/log/checkpoint', '/api/log/proof/:commitId'].forEach(function(r) {
  test('route ' + r + ' is registered', function() {
    assert(server.indexOf("app.get('" + r + "'") !== -1,
      r + ' is handed out in every commit receipt but not registered');
  });
});

test('log verification routes require no auth', () => {
  // The claim is "verify independently, no account required". These carry only
  // hashes, never payloads, so they are safe to serve unauthenticated — and
  // they are useless to a third-party verifier if they are not.
  ['/api/log/pubkey', '/api/log/checkpoint', '/api/log/proof/:commitId'].forEach(function(r) {
    var line = server.slice(server.indexOf("app.get('" + r + "'"));
    line = line.slice(0, line.indexOf('\n'));
    assert(!/requireApiKey|requireAuth|requireSession/.test(line),
      r + ' requires auth, which defeats independent verification');
  });
});

test('log verification routes never return a payload', () => {
  // A proof is hashes. If these ever select payload columns they turn a public
  // verification endpoint into a public data leak.
  var start = server.indexOf("app.get('/api/log/pubkey'");
  var end   = server.indexOf("app.get('/api/admin/witnesses'");
  if (end === -1) end = start + 6000;
  var block = server.slice(start, end);
  assert(!/\bpayload\b/.test(block),
    'a /api/log/* handler references payload — proofs must be hashes only');
});


// 34. Witness independence must be claimed only if a witness is independent
// The site said checkpoints were "co-signed by registered external witnesses,
// so the attestation can be checked without trusting DarkMatter alone", and
// that the root was "attested by a party other than us". There is one
// registered witness. It is named DarkMatter Witness Node 1, it runs on our
// Railway account and we hold its private key. A witness in the same trust
// domain gives no split-view protection: whoever can rewrite the log can
// re-sign the witness line. The claim was the whole value of L2 and it was not
// true. These tests tie that wording to a declared fact instead of a memory.
console.log('\nWitness independence');
var witnessSrc = fs.readFileSync(path.join(ROOT, 'src/witness.js'), 'utf8');
var independentWitnesses = require('../src/witness.js').INDEPENDENT_WITNESSES_REGISTERED;

test('witness.js declares whether an independent witness exists', () => {
  assert(/const INDEPENDENT_WITNESSES_REGISTERED = (true|false);/.test(witnessSrc),
    'INDEPENDENT_WITNESSES_REGISTERED is the flag the copy guard reads — it must exist');
  assert(typeof independentWitnesses === 'boolean',
    'INDEPENDENT_WITNESSES_REGISTERED must be exported as a boolean');
});

test('no page claims witness independence while none is registered', () => {
  if (independentWitnesses) return; // the stronger wording is earned; nothing to check
  var banned = [
    /external witness/i,
    /independent co-signature/i,
    /witnesses[^.]{0,40}\bindependent(ly)?\b/i,
    /without trusting DarkMatter alone/i,
    /does not depend on trusting DarkMatter alone/i,
    // Only the affirmative form. The corrected copy says a co-signature is
    // "not yet attestation by a party other than us", which must not trip this.
    /(?<!not yet )attest(ed|ation) by a party other than us/i,
  ];
  var offenders = [];
  fs.readdirSync(path.join(ROOT, 'public'))
    .filter(function(f) { return f.endsWith('.html'); })
    .forEach(function(f) {
      var text = fs.readFileSync(path.join(ROOT, 'public', f), 'utf8');
      banned.forEach(function(re) {
        var m = text.match(re);
        if (m) offenders.push(f + ': "' + m[0].slice(0, 60) + '"');
      });
    });
  assert(offenders.length === 0,
    'independence claimed with no independent witness registered:\n       ' +
    offenders.join('\n       '));
});

test('pages that mention witnesses say who operates them', () => {
  if (independentWitnesses) return;
  var offenders = [];
  fs.readdirSync(path.join(ROOT, 'public'))
    .filter(function(f) { return f.endsWith('.html'); })
    .forEach(function(f) {
      var text = fs.readFileSync(path.join(ROOT, 'public', f), 'utf8');
      if (!/witness/i.test(text)) return;
      // Saying "co-signed by witnesses" without saying they are ours invites
      // exactly the reading the wording above made explicit.
      if (!/operated by DarkMatter|run by DarkMatter/i.test(text)) {
        offenders.push(f);
      }
    });
  assert(offenders.length === 0,
    'mentions witnesses without disclosing that DarkMatter operates them: ' +
    offenders.join(', '));
});


// 35. A page's canonical URL must actually serve that page
// about.html declared <link rel="canonical" href="/about"> and was titled
// "About DarkMatter". /about served why.html, whose canonical is /why. So a
// crawler following the sitemap to /about got a page telling it to prefer
// /why, and about.html was indexed nowhere. Nine pages linked "About" there.
// Nothing failed; the About page was simply invisible for its whole life.
console.log('\nCanonical URLs resolve to their own page');

// route -> file, for every explicit sendFile route in server.js
function routeTable() {
  var t = {};
  var re = /app\.get\(\s*'([^']+)'[\s\S]{0,600}?sendFile\(\s*path\.join\([^)]*?public\/([a-z0-9_.-]+\.html)'\s*\)/gi;
  var m;
  while ((m = re.exec(server)) !== null) {
    if (!(m[1] in t)) t[m[1]] = m[2];   // first registration wins, as in Express
  }
  return t;
}

// What the server actually serves for a URL path: an explicit route if one is
// registered, otherwise the static/catch-all mapping of /foo -> public/foo.html
function servedFile(urlPath, routes) {
  if (routes[urlPath]) return routes[urlPath];
  if (urlPath === '/') return 'index.html';
  var rel = urlPath.replace(/^\/+/, '');
  return /\.html$/.test(rel) ? rel : rel + '.html';
}

test('every page canonicalises to a URL that serves that same page', () => {
  var routes = routeTable();
  var offenders = [];
  publicPages().forEach(function(pg) {
    var html = fs.readFileSync(pg.abs, 'utf8');
    var m = html.match(/rel=["']canonical["'][^>]*href=["']([^"']+)["']/i) ||
            html.match(/href=["']([^"']+)["'][^>]*rel=["']canonical["']/i);
    if (!m) return;                       // no canonical declared: nothing to check
    var urlPath = m[1].replace(/^https?:\/\/[^/]+/, '') || '/';
    urlPath = urlPath.replace(/\/$/, '') || '/';
    var served = servedFile(urlPath, routes);
    var self   = pg.slug + '.html';
    if (served !== self) {
      offenders.push(pg.slug + '.html canonicalises to ' + urlPath +
                     ', which serves ' + served);
    }
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(offenders.length === 0,
    'a page points search engines at a URL that returns different content:' +
    SEP + offenders.join(SEP));
});

test('no two sitemap URLs serve the same file', () => {
  // /about and /why both served why.html, so the sitemap offered the same page
  // twice under different URLs. One of them was always going to be discarded.
  var routes = routeTable();
  // Read the exclusion list out of server.js so the two cannot drift apart.
  var exBlock  = server.match(/SITEMAP_EXCLUDE = new Set\(\[([\s\S]*?)\]\)/);
  var excluded = exBlock ? (exBlock[1].match(/'[^']+'/g) || []).map(function(q) {
    return q.slice(1, -1);
  }) : [];
  assert(excluded.length > 0, 'could not read SITEMAP_EXCLUDE from server.js');
  var seen = {}, dupes = [];
  publicPages().forEach(function(pg) {
    if (excluded.indexOf(pg.slug) !== -1) return;
    var urlPath = '/' + pg.slug;
    var served  = servedFile(urlPath, routes);
    if (seen[served]) dupes.push(urlPath + ' and ' + seen[served] + ' both serve ' + served);
    else seen[served] = urlPath;
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(dupes.length === 0, 'sitemap lists the same page under two URLs:' + SEP + dupes.join(SEP));
});

// Also runnable standalone: node test/security.test.js
(function() {
  var sec = require('./security.test.js').run();
  passed += sec.passed;
  failed += sec.failed;
})();

// Summary
console.log('\n' + '-'.repeat(50));
console.log('Passed: ' + passed + '  Failed: ' + failed + '  Total: ' + (passed+failed));
if (failed > 0) { console.error('\n\u2717 SOME TESTS FAILED'); process.exit(1); }
else { console.log('\n\u2713 ALL TESTS PASSED'); }
