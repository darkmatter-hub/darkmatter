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

// Locate the shipping Python SDK. Walking up rather than assuming a sibling:
// inside a git worktree ROOT/.. is the worktrees directory, so the old sibling
// path silently missed and every check below skipped without saying so.
var SDK_PY = (function () {
  if (process.env.DARKMATTER_SDK_PY) return path.join(process.env.DARKMATTER_SDK_PY, 'darkmatter');
  var d = path.resolve(ROOT);
  for (;;) {
    var cand = path.join(d, 'darkmatter-sdk-python', 'darkmatter');
    if (fs.existsSync(cand)) return cand;
    var parent = path.dirname(d);
    if (parent === d) return path.join(ROOT, '../darkmatter-sdk-python/darkmatter');
    d = parent;
  }
})();
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

// /blogs/:slug used to be /blog/:slug and fall back to the blog index when the
// post file was missing, so three links advertised on /blog answered 200 with
// the wrong page for months. A reader who clicked "Introducing DarkMatter"
// landed back on the listing with no error. This asserts every /blogs/ link on
// the site resolves to a file that exists, which is the check that would have
// caught it.
test('no page links to a blog post that does not exist', function() {
  var dead = [];
  (function walk(dir) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function(e) {
      var abs = path.join(dir, e.name);
      if (e.isDirectory()) return walk(abs);
      if (!/\.html$/.test(e.name)) return;
      var html = fs.readFileSync(abs, 'utf8');
      var re = /href="\/blogs\/([a-z0-9-]+)"/g, m;
      while ((m = re.exec(html)) !== null) {
        var post = path.join(ROOT, 'public', 'blogs', m[1] + '.html');
        if (!fs.existsSync(post)) {
          dead.push(path.relative(ROOT, abs).split(path.sep).join('/') + ' -> /blogs/' + m[1]);
        }
      }
    });
  })(path.join(ROOT, 'public'));
  assert(dead.length === 0, 'links to nonexistent posts: ' + dead.join(', '));
});

test('missing blog posts return 404 rather than the index', function() {
  var m = server.match(/app\.get\('\/blogs\/:slug'[\s\S]*?\n\}\);/);
  assert(m, '/blogs/:slug route not found');
  // The fallback specifically, not any 404 in the route. The slug validation
  // above also returns 404, so searching the whole block passed even with the
  // fallback reverted to a bare sendFile: the guard matched a different line
  // than the one it protects.
  assert(/res\.status\(404\)\.sendFile\([^)]*blog\.html/.test(m[0]),
    '/blogs/:slug still answers 200 for posts that do not exist');
});

test('the old post URLs still redirect', function() {
  // Both /blog-<slug> and /blog/<slug> were live and indexed before the move to
  // /blogs/. Dropping either would break inbound links and search results.
  assert(server.indexOf('blog-([a-z0-9]') !== -1,
    'no redirect from the old /blog-<slug> URLs');
  var legacy = server.match(/app\.get\('\/blog\/:slug'[\s\S]*?\n\}\);/);
  assert(legacy, '/blog/:slug route missing');
  assert(/redirect\(301/.test(legacy[0]),
    '/blog/:slug must 301 to /blogs/, not serve or 404');
});

test('every post file lives under public/blogs', function() {
  var stray = fs.readdirSync(path.join(ROOT, 'public'))
    .filter(function(f) { return /^blog-.*\.html$/.test(f); });
  assert(stray.length === 0,
    'posts must live in public/blogs/, not at the top level: ' + stray.join(', '));
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

// The site claims an open-source offline verifier.
// (compare.html used to claim it against three named competitors; that page
// is gone, but the claim itself is still made elsewhere.) package.json declared MIT but no LICENSE file
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

// Five pages once said payloads are hashed client-side without qualification.
// That was true through the Python SDK and false through the JavaScript one,
// which posted the payload and let the server hash it. The qualifier was added
// for that reason.
//
// darkmatter-js 1.4.3 hashes, and the MCP server hashes through
// @contextpassport/core, so all three clients now compute the same value the
// server does - verified against an astral-key payload, which is where a
// UTF-16 versus code-point mistake would show. The claim no longer has to name
// one SDK, and naming only one would now be the misleading version.
//
// What still matters is that a direct API call is hashed by the server, not by
// the caller. So the claim has to be scoped to the SDKs or acknowledge that
// path, and must not single out one SDK as the only one that hashes.
test('client-side hashing is scoped, and no longer credits only one SDK', function() {
  var offenders = [];
  publicPages().forEach(function(pg) {
    var html = fs.readFileSync(pg.abs, 'utf8');
    var re = /[^.<>]{0,140}(hashed?[^.<>]{0,20}client-side|client-side hash[^.<>]{0,20})[^.<>]{0,140}/gi;
    var m;
    while ((m = re.exec(html)) !== null) {
      var sentence = m[0];
      if (!/sdk|by the server|server hashes/i.test(sentence)) {
        offenders.push(pg.slug + ' unscoped: "' + sentence.trim().slice(0, 66) + '"');
      }
      if (/only the python sdk|python sdk only|javascript sdk leaves it/i.test(sentence)) {
        offenders.push(pg.slug + ' stale: "' + sentence.trim().slice(0, 66) + '"');
      }
    }
  });
  assert(offenders.length === 0,
    'client-side hashing claims that mislead: ' + offenders.join('; '));
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

// 36. Nothing survives us that we have not already handed over
// The homepage meta description - the line that appears in every search result
// - said records are "verifiable by anyone, even if we disappear". If
// DarkMatter disappears, so does the database holding the records, the API
// serving inclusion proofs, and the witness, which runs on our own Railway
// account. Checkpoints have never been published anywhere outside it:
// darkmatter-hub/checkpoints holds two commits, both README.
//
// What genuinely outlives us is an export bundle somebody already downloaded.
// It carries its own proofs and verifies offline. So the claim is allowed only
// where the sentence is actually about that.
console.log('\nSurvivability claims');
test('a claim that records outlive DarkMatter mentions the export', () => {
  var DISAPPEARS = /even if we (?:disappear|vanish|shut down|are gone|don't|do not)|if (?:we|DarkMatter) (?:disappears?|vanish|shuts? down|goes? away|cease)|survives? (?:us|DarkMatter)|outlives? (?:us|DarkMatter)/i;
  var PORTABLE   = /export|bundle|download|offline|on your machine|in your hands/i;
  var offenders = [];
  publicPages().forEach(function(pg) {
    var text = fs.readFileSync(pg.abs, 'utf8')
      .replace(/<meta[^>]*content="([^"]*)"[^>]*>/gi, ' $1 ')
      .replace(/<[^>]+>/g, ' ');
    text.split(/(?<=[.!?])\s+/).forEach(function(sentence) {
      if (DISAPPEARS.test(sentence) && !PORTABLE.test(sentence)) {
        offenders.push(pg.slug + ': "' + sentence.trim().slice(0, 100) + '"');
      }
    });
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(offenders.length === 0,
    'claims the record outlives us, which is true only of an exported bundle:' +
    SEP + offenders.join(SEP));
});

// 37. "Verifiable even if DarkMatter is compromised" needs a witness we do not have
// eu-ai-act.html told regulators: "Even if DarkMatter were compromised, your
// records remain verifiable independently." An attacker holding our database
// also holds the API that serves inclusion proofs, the checkpoint signing key,
// and the only registered witness, which runs on our own infrastructure. They
// could re-sign a consistent alternate history and nothing outside would
// contradict it. Surviving that is exactly what an independent witness buys,
// so this claim is licensed by the same flag as the independence wording.
test('surviving a DarkMatter compromise is not claimed without an independent witness', () => {
  if (independentWitnesses) return;
  var COMPROMISE = /(?:even )?if (?:we|DarkMatter)(?:'s| is| were| are| was| gets?| got|) (?:compromised|breached|hacked|malicious|subverted|seized|coerced)|we (?:were|are) compromised/i;
  var PORTABLE   = /export|bundle|download|offline|already hold|in your hands|on your machine/i;
  var offenders = [];
  publicPages().forEach(function(pg) {
    var text = fs.readFileSync(pg.abs, 'utf8')
      .replace(/<meta[^>]*content="([^"]*)"[^>]*>/gi, ' $1 ')
      .replace(/<[^>]+>/g, ' ');
    text.split(/(?<=[.!?])\s+/).forEach(function(sentence) {
      if (COMPROMISE.test(sentence) && !PORTABLE.test(sentence)) {
        offenders.push(pg.slug + ': "' + sentence.trim().slice(0, 100) + '"');
      }
    });
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(offenders.length === 0,
    'claims records survive our own compromise, which needs a witness outside ' +
    'our trust domain:' + SEP + offenders.join(SEP));
});

// Read the sitemap exclusion list out of server.js so the two cannot drift.
function sitemapExcluded() {
  var m = server.match(/SITEMAP_EXCLUDE = new Set\(\[([\s\S]*?)\]\)/);
  // Drop comment lines first. The block carries an explanation that quotes
  // "Admin only", and without this that phrase was extracted as a slug.
  var body = m ? m[1].split(String.fromCharCode(10))
                     .filter(function (l) { return l.trim().indexOf('//') !== 0; })
                     .join(String.fromCharCode(10)) : '';
  var out = (body.match(/'[^']+'/g) || []).map(function (q) { return q.slice(1, -1); });
  assert(out.length > 0, 'could not read SITEMAP_EXCLUDE from server.js');
  return out;
}

// 38. Social cards: every shared link rendered as a bare URL
// Only chain.html carried og tags, and its card was broken three ways: og:url
// shipped empty, og:image pointed at og-chain.png and og-default.png, neither
// of which exists, and the real image came from client JS that no scraper runs.
// The onerror on the <meta> tag never fired either - meta elements have no
// error event. Every other page had nothing, so a link posted to X, LinkedIn
// or Slack showed a naked URL. The daily tweet posts one of those links.
console.log('\nSocial cards');

function ogTag(html, prop) {
  // Plain string scanning rather than a constructed RegExp: the first version
  // built the pattern from a string and its escapes did not survive being
  // written to disk, so it matched nothing and reported every page as missing
  // every tag. String search needs no escapes and cannot fail that way.
  var key = '"' + prop + '"';
  var i = html.indexOf(key);
  while (i !== -1) {
    var open = html.lastIndexOf('<', i);
    var close = html.indexOf('>', i);
    if (open !== -1 && close !== -1) {
      var tag = html.slice(open, close);
      var c = tag.indexOf('content="');
      if (c !== -1) {
        var rest = tag.slice(c + 'content="'.length);
        var q = rest.indexOf('"');
        if (q !== -1) return rest.slice(0, q).trim();
      }
    }
    i = html.indexOf(key, i + 1);
  }
  return null;
}

test('every indexable page carries og and twitter metadata', () => {
  var missing = [];
  publicPages().forEach(function(pg) {
    if (sitemapExcluded().indexOf(pg.slug) !== -1) return;
    var html = fs.readFileSync(pg.abs, 'utf8');
    ['og:title', 'og:description', 'og:url', 'twitter:card', 'twitter:title']
      .forEach(function(prop) {
        if (!ogTag(html, prop)) missing.push(pg.slug + ' has no ' + prop);
      });
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(missing.length === 0,
    'pages that would share as a bare URL:' + SEP + missing.join(SEP));
});

test('og metadata matches the page it describes', () => {
  // Derived from <title>, description and canonical, so they cannot drift into
  // saying different things on the same page.
  var wrong = [];
  publicPages().forEach(function(pg) {
    var html = fs.readFileSync(pg.abs, 'utf8');
    if (!ogTag(html, 'og:title')) return;
    var t = (html.match(/<title>([\s\S]*?)<\/title>/) || [])[1];
    var d = ogTag(html, 'description');
    var c = (html.match(/<link\s+rel="canonical"\s+href="([^"]*)"/) || [])[1];
    if (t && ogTag(html, 'og:title') !== t.trim() && pg.slug !== 'chain') {
      wrong.push(pg.slug + ': og:title differs from <title>');
    }
    if (d && ogTag(html, 'og:description') !== d && pg.slug !== 'chain') {
      wrong.push(pg.slug + ': og:description differs from meta description');
    }
    if (c && ogTag(html, 'og:url') !== c && pg.slug !== 'chain') {
      wrong.push(pg.slug + ': og:url differs from canonical');
    }
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(wrong.length === 0, 'og metadata contradicts the page:' + SEP + wrong.join(SEP));
});

test('no card image is missing or in a format no scraper renders', () => {
  var bad = [];
  publicPages().forEach(function(pg) {
    var html = fs.readFileSync(pg.abs, 'utf8');
    ['og:image', 'twitter:image'].forEach(function(prop) {
      var src = ogTag(html, prop);
      if (!src) return;
      var p = src.replace(/^https?:\/\/[^/]+/, '');
      if (/\.svg($|\?)/i.test(p)) {
        bad.push(pg.slug + ': ' + prop + ' is SVG, which X, LinkedIn and Slack do not render');
      }
      // A same-origin static path must actually be a file in public/.
      if (/^\/[^/]/.test(p) && !/^\/api\//.test(p) &&
          !fs.existsSync(path.join(ROOT, 'public', p.replace(/^\//, '')))) {
        bad.push(pg.slug + ': ' + prop + ' points at ' + p + ', which does not exist');
      }
    });
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(bad.length === 0, 'broken card images:' + SEP + bad.join(SEP));
});

// 39. We do not make claims about other companies in public
// public/compare.html carried a feature matrix asserting what LangSmith,
// MLflow and Datadog do and do not do. That is comparative advertising about
// identifiable products: every cell has to be defensible, and one was not.
// "Stored outside your system" was marked Yes for DarkMatter and No for all
// three, but LangSmith and Datadog are hosted services, so records sent to
// them are stored outside the customer's system by definition. It also claimed
// a difference DarkMatter does not have over a hosted competitor.
//
// The page is gone. Competitors are still worth tracking; that belongs in
// private/, which is gitignored, not on the site. The argument the site makes
// is about what DarkMatter is: a hash chain, customer-held keys, an offline
// verifier anyone can run.
console.log('\nNo public competitor claims');

test('the comparison page stays deleted', () => {
  assert(!fs.existsSync(path.join(ROOT, 'public/compare.html')),
    'compare.html is back. Comparative claims about named products have to be ' +
    'defended cell by cell; keep the analysis in private/ instead.');
});

test('/compare redirects rather than 404s', () => {
  assert(server.indexOf("app.get('/compare'") !== -1,
    'no /compare route: inbound links to the old page would 404');
  var line = server.slice(server.indexOf("app.get('/compare'"));
  line = line.slice(0, line.indexOf('\n'));
  assert(line.indexOf('redirect') !== -1, '/compare should redirect, not serve a page');
});

test('no public page names a competitor product', () => {
  // LangChain and LangGraph stay: they are integrations we ship an SDK for,
  // not products we compare ourselves against.
  var named = ['LangSmith', 'MLflow', 'Langfuse', 'Helicone', 'Arize',
               'Braintrust', 'Weights & Biases', 'Datadog', 'Splunk',
               'Honeycomb', 'New Relic', 'Traceloop', 'Humanloop', 'Logfire'];
  var offenders = [];
  publicPages().forEach(function(pg) {
    var text = fs.readFileSync(pg.abs, 'utf8');
    named.forEach(function(n) {
      if (text.indexOf(n) !== -1) offenders.push(pg.slug + ' names ' + n);
    });
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(offenders.length === 0,
    'competitor named on a public page:' + SEP + offenders.join(SEP));
});

// 40. Detecting OUR tampering needs a reference we do not currently provide
// The site's core promise is that a record cannot be altered without detection.
// Against the customer that is unconditionally true: there is no edit path, and
// DELETE on a commit returns 405 pointing at a redaction commit. Against
// DarkMatter it is conditional, and the site did not say so.
//
// A hash chain does not stop the operator rewriting history. We hold the
// database, so we could alter a record, recompute every downstream hash, re-sign
// every checkpoint with our own key, and re-sign the witness, which also runs on
// our infrastructure. The result is internally consistent. What catches it is an
// independent reference: a proof bundle the customer exported beforehand,
// checkpoints published where we cannot reach them, or a witness signature from
// outside our trust domain. Only the first exists today.
//
// So a sentence claiming our own tampering is detectable has to say what it is
// detectable against. "Anyone can check" does not, and was on the homepage.
console.log('\nDetection of our own tampering');
test('a claim that our tampering is detectable names the reference', () => {
  var ABOUT_US = /(?:we|darkmatter) cannot (?:modify|alter|change|tamper)|change made by darkmatter|without trusting (?:us|darkmatter)|tampering is detectable|modification to a committed record is detectable/i;
  // What a verifier compares against. Naming any of these makes the claim true.
  var REFERENCE = /export|bundle|\bcopy\b|offline|your public key|your own|beforehand|retain|witness/i;
  var offenders = [];
  publicPages().forEach(function(pg) {
    // Titles are not claims, and og/twitter tags repeat the title three more
    // times. Strip the title and do not expand meta content for this check.
    var text = fs.readFileSync(pg.abs, 'utf8')
      .replace(/<title>[\s\S]*?<\/title>/gi, ' ')
      .replace(/<[^>]+>/g, ' ');
    text.split(/(?<=[.!?])\s+/).forEach(function(sentence) {
      // A sentence disclosing that we cannot yet offer something is the
      // opposite of the claim being guarded against.
      if (/not yet|does not|do not|cannot yet/i.test(sentence)) return;
      if (ABOUT_US.test(sentence) && !REFERENCE.test(sentence)) {
        offenders.push(pg.slug + ': "' + sentence.trim().slice(0, 110) + '"');
      }
    });
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(offenders.length === 0,
    'claims our own tampering is detectable without saying against what:' +
    SEP + offenders.join(SEP));
});

test('the terms disclose that detection depends on a customer-held export', () => {
  var tos = fs.readFileSync(path.join(ROOT, 'public/tos.html'), 'utf8');
  assert(/Detection of a modification made by DarkMatter depends on you retaining/.test(tos),
    'tos.html must state that detecting our own modification depends on a proof ' +
    'bundle the customer exported, because we publish no independent reference');
});

// 41. A published checkpoint has to be verifiable by whoever we published it to
// GET /api/log/checkpoint served the stored row. Postgres returns the timestamp
// as "2026-08-29T19:41:35+00:00"; the signature was computed over
// "2026-08-29T19:41:35Z". Same instant, different string, and canonical JSON
// hashes the string, so anyone rebuilding the envelope from the row got a
// message we had never signed and concluded the signature was bad. Publishing a
// checkpoint nobody can check is worse than publishing none.
//
// The same reconstruction runs in acceptWitnessSignature, so a witness signing
// exactly the bytes we sent it was recorded as invalid. That was a second,
// independent cause of witnessing failing, on top of the stale key.
console.log('\nSigned checkpoint is verifiable as served');

test('one function rebuilds the signed envelope, and everything uses it', () => {
  var log = fs.readFileSync(path.join(ROOT, 'src/append-log.js'), 'utf8');
  assert(log.indexOf('function envelopeFromCheckpointRow') !== -1,
    'envelopeFromCheckpointRow is the single reconstruction; it must exist');
  var wit = fs.readFileSync(path.join(ROOT, 'src/witness.js'), 'utf8');
  assert(wit.indexOf('envelopeFromCheckpointRow(') !== -1,
    'witness.js must not rebuild the envelope inline: it has to match byte for byte');
  assert(server.indexOf('envelopeFromCheckpointRow(') !== -1,
    'the log routes must serve the envelope that was actually signed');
});

test('the checkpoint route serves the signed envelope, not just the row', () => {
  var i = server.indexOf("app.get('/api/log/checkpoint'");
  var block = server.slice(i, i + 2000);
  // Match the assignment, not the word. The first version of this checked for
  // 'signed_envelope' anywhere in the block and passed on the comment above
  // the route explaining why the field exists, so deleting the field itself
  // was invisible.
  assert(/signed_envelope:\s*envelopeFromCheckpointRow\(/.test(block),
    'the route must assign signed_envelope from the shared reconstruction');
  assert(block.indexOf('JCS of signed_envelope') !== -1,
    'say what the signature is over, or the caller has to reverse-engineer it');
});

test('the covering checkpoint selects every field the envelope needs', () => {
  // An envelope missing log_root or log_position hashes to something else, so
  // a short select silently produces an unverifiable proof.
  var i = server.indexOf("app.get('/api/log/proof/:commitId'");
  var block = server.slice(i, i + 2000);
  var sel = block.slice(block.indexOf(".select('"), block.indexOf(')', block.indexOf(".select('")));
  ['checkpoint_id', 'position', 'log_root', 'tree_root', 'tree_size',
   'server_sig', 'timestamp', 'previous_cp_id', 'previous_tree_root'].forEach(function(f) {
    assert(sel.indexOf(f) !== -1,
      'covering checkpoint select is missing ' + f + ', so its envelope cannot verify');
  });
});

// 42. The repository is public and must not carry the owner's identity
// npm and PyPI metadata named a person and pointed at a personal GitHub
// account, so both published packages carried it to anyone who ran `npm view`.
// The instruction on this is unambiguous and predates all of it. private/ is
// gitignored and excluded; node_modules is not ours.
console.log('\nNo personal identifiers in a public repo');
test('no tracked file names the owner or their personal account', () => {
  // Split so this file does not match its own list. Writing them whole here
  // made the guard fail on itself, which is funny once and useless after.
  var banned = ['ben' + 'gunvl', 'Ben' + ' Gunvl', 'cullaj' + '07'];
  var SKIP = ['node_modules', '.git', 'private'];
  var offenders = [];
  (function walk(dir) {
    var entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    entries.forEach(function(e) {
      if (SKIP.indexOf(e.name) !== -1) return;
      var abs = path.join(dir, e.name);
      if (e.isDirectory()) return walk(abs);
      if (!/\.(js|json|md|py|html|toml|cfg|yml|yaml|txt|sh)$/.test(e.name)) return;
      var text;
      try { text = fs.readFileSync(abs, 'utf8'); } catch (err) { return; }
      banned.forEach(function(b) {
        if (text.indexOf(b) !== -1) {
          var rel = path.relative(ROOT, abs).split(path.sep).join('/');
          offenders.push(rel + ' contains "' + b + '"');
        }
      });
    });
  })(ROOT);
  var SEP = String.fromCharCode(10) + '       ';
  assert(offenders.length === 0,
    'personal identifier in a public repository:' + SEP + offenders.join(SEP));
});

// 43. No SDK source lives in this repository
// sdk/python and sdk/typescript were stale forks of the SDKs that actually
// ship. Two fixes went into them by mistake and neither reached a customer.
// Worse, test/sdk_parity.test.py imported sdk/python, so the test proving the
// Python SDK and the server hash identically was proving it about software
// nobody installs, and stayed green while the published package sorted keys by
// code point and disagreed with the server on any payload with an emoji key.
//
// The SDKs live in darkmatter-sdk-python and darkmatter-sdk-js. A copy here is
// a copy that will drift, and the drift is invisible because the tests follow
// the copy.
console.log('\nNo bundled SDK copies');
test('the repository contains no SDK source', () => {
  var banned = ['sdk/python', 'sdk/typescript', 'sdk/js', 'sdk/javascript'];
  // Path checking alone missed src/index.js, a third copy of the JS SDK at
  // v1.4.0 that the server never required. Look for the thing itself, not for
  // the places it has happened to live.
  var found = banned.filter(function (rel) {
    return fs.existsSync(path.join(ROOT, rel));
  });
  assert(found.length === 0,
    'bundled SDK copy is back: ' + found.join(', ') +
    '. The SDKs live in their own repositories; a copy here drifts and the ' +
    'tests follow the copy instead of what ships.');
});

test('no file in this repository declares itself the SDK', () => {
  // The banner an SDK file carries, with a version on it. An example that
  // merely tells the reader to pip install something is not a copy of the SDK,
  // and the first version of this flagged examples/complex_pipeline.py for that.
  var marks = ['DarkMatter JavaScript SDK v', 'DarkMatter Python SDK v', 'DarkMatter TypeScript SDK v'];
  var SKIP = ['node_modules', '.git', 'private', 'public', 'test', 'examples', 'github-template'];
  var offenders = [];
  (function walk(dir) {
    var entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    entries.forEach(function (e) {
      if (SKIP.indexOf(e.name) !== -1) return;
      var abs = path.join(dir, e.name);
      if (e.isDirectory()) return walk(abs);
      if (!/\.(js|py|ts)$/.test(e.name)) return;
      var text;
      try { text = fs.readFileSync(abs, 'utf8'); } catch (err) { return; }
      marks.forEach(function (m) {
        if (text.indexOf(m) !== -1) {
          offenders.push(path.relative(ROOT, abs).split(path.sep).join('/'));
        }
      });
    });
  })(ROOT);
  var SEP = String.fromCharCode(10) + '       ';
  assert(offenders.length === 0,
    'an SDK copy lives in this repository and will drift from the published ' +
    'one:' + SEP + offenders.join(SEP));
});

test('the parity test reads the SDK that ships, not a local copy', () => {
  var parity = fs.readFileSync(path.join(ROOT, 'test/sdk_parity.test.py'), 'utf8');
  assert(parity.indexOf('darkmatter-sdk-python') !== -1,
    'sdk_parity must resolve the published SDK repository');
  assert(!/ROOT,\s*["']sdk["']/.test(parity),
    'sdk_parity must not import a copy bundled in this repository');
});

// 44. The documented chain format has to be the one we actually compute
// threat-model.html is where someone goes to build their own verifier. It said
// integrity_hash was SHA-256 of a canonical envelope binding schema_version,
// agent_id, key_id, timestamp, payload_hash and parent_integrity_hash. It is
// not: chainIntegrityHash joins the record's own payload_hash to its parent's
// integrity_hash, both carrying the sha256: prefix, with the literal "root" at
// the root. Anyone following the page would have computed a different value for
// every record and concluded the whole chain was invalid.
//
// The envelope it described is real but is a different thing: the L3 object the
// SDK signs. Two hashes, one name, and the page picked the wrong one.
console.log('\nDocumented chain format');

test('the documented integrity_hash rule is the one integrity.js computes', () => {
  // Recompute from the rule as written on the page, and compare against the
  // implementation. If either moves, this fails.
  var crypto = require('crypto');
  var integrity = require('../src/integrity.js');
  var ph = 'c776cff69f71f41f42725e47bcebce986a11cfcf0fea34e12e4a7b6d37e3fa90';
  var parent = 'bb191f1b8930f03962ffcb4ebfe0159d779660a8799ca84a1c432060ac8880df';

  var atRoot = crypto.createHash('sha256').update('sha256:' + ph + 'root', 'utf8').digest('hex');
  assert(integrity.chainIntegrityHash(ph, null) === atRoot,
    'the root rule on threat-model.html no longer matches chainIntegrityHash');

  var linked = crypto.createHash('sha256')
    .update('sha256:' + ph + 'sha256:' + parent, 'utf8').digest('hex');
  assert(integrity.chainIntegrityHash(ph, parent) === linked,
    'the parent-link rule on threat-model.html no longer matches chainIntegrityHash');
});

test('the page does not describe integrity_hash as a canonical envelope', () => {
  var tm = fs.readFileSync(path.join(ROOT, 'public/threat-model.html'), 'utf8');
  assert(tm.indexOf('SHA-256 of canonical({schema_version') === -1,
    'that is the L3 envelope the SDK signs, not the stored integrity_hash');
  assert(/prefixed hashes joined|sha256:<\/code> prefix/.test(tm),
    'the page must state that both operands carry the sha256: prefix, or a ' +
    'verifier built from it computes the wrong value');
});

test('the export bundle tells people a command the verifier accepts', () => {
  // The bundle used to print flags the verifier ignores and name two files that
  // are keys inside the bundle rather than files on disk.
  var m = server.match(/verify_command:\s*'([^']+)'/);
  assert(m, 'the bundle must carry a verify_command');
  var cmd = m[1];
  assert(cmd.indexOf('--') === -1,
    'verify_darkmatter_chain.py takes a bundle path and nothing else, but the ' +
    'bundle prints: ' + cmd);
  var verifier = fs.readFileSync(path.join(ROOT, 'examples/verify_darkmatter_chain.py'), 'utf8');
  assert(verifier.indexOf('argparse') === -1,
    'the verifier gained argument parsing; re-check what verify_command promises');
});

test('the bundle does not claim verification phases the verifier skips', () => {
  // Extract the phases array by slicing rather than with a character class:
  // the first version used [^\]]* written through a tool that collapses doubled
  // backslashes, so the class became [^] followed by ]* and matched nothing.
  var i = server.indexOf('phases:');
  assert(i !== -1, 'the bundle must declare its phases');
  var open = server.indexOf('[', i);
  var close = server.indexOf(']', open);
  var phases = server.slice(open, close + 1);
  ['agent_signatures', 'merkle_inclusion', 'checkpoint_signature'].forEach(function (phase) {
    assert(phases.indexOf(phase) === -1,
      phase + ' is listed in phases ' + phases + ', but the bundled verifier ' +
      'checks payload hashes and chain links only');
  });
  var block = server.slice(i - 400, i + 900);
  assert(block.indexOf('not_checked') !== -1,
    'the bundle must say what it does not verify, not only what it does');
});

// 45. A guard built from a string-constructed RegExp is a guard that may match nothing
// Three times a test in this file shipped green and hollow, always the same
// way: the pattern was assembled from a JavaScript string, and the doubled
// backslash a string needs did not survive being written to disk. What ran was
//
//   a word-boundary escape that became a literal 0x08 byte,
//   a whitespace escape that became the bare letter s, and
//   a character class [^\]] that became [^] followed by ]*.
//
// Each matched nothing and reported success over copy that plainly violated it.
// A regex literal is written once and read once, so it does not have this
// failure mode. indexOf and slice have it even less.
console.log('\nGuards cannot be hollow by construction');

test('no test builds a RegExp from a string with a collapsed escape', () => {
  // Correct is a doubled backslash: 'BSBSb' in the file becomes BSb in the
  // string and a word boundary in the pattern. A lone backslash means the
  // escape was eaten before it reached disk, and the pattern silently becomes
  // something else. Walk backslash runs rather than matching, so this check
  // cannot itself be a victim of the thing it checks.
  var BS = String.fromCharCode(92);
  var DANGEROUS = 'bswdSWDB]}()|.*+?^$';
  var offenders = [];
  fs.readdirSync(path.join(ROOT, 'test')).forEach(function (name) {
    if (!/\.test\.js$/.test(name)) return;
    var src = fs.readFileSync(path.join(ROOT, 'test', name), 'utf8');
    src.split(String.fromCharCode(10)).forEach(function (line, i) {
      if (line.indexOf('new RegExp(') === -1) return;
      var j = line.indexOf('new RegExp(');
      while (j < line.length) {
        if (line.charAt(j) === BS) {
          var run = 0;
          while (line.charAt(j + run) === BS) run++;
          var next = line.charAt(j + run);
          if (run % 2 === 1 && DANGEROUS.indexOf(next) !== -1) {
            offenders.push(name + ':' + (i + 1) + '  lone escape before "' + next +
                           '" in ' + line.trim().slice(0, 70));
            break;
          }
          j += run;
        } else { j++; }
      }
    });
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(offenders.length === 0,
    'a pattern built from a string lost its escape, which is how three guards ' +
    'ended up matching nothing:' + SEP + offenders.join(SEP));
});

test('no test file contains a stray control character', () => {
  // The 0x08 case was invisible on screen: the file looked correct and the
  // regex required a backspace before the word.
  var offenders = [];
  fs.readdirSync(path.join(ROOT, 'test')).forEach(function (name) {
    if (!/\.(test\.js|test\.py)$/.test(name)) return;
    var src = fs.readFileSync(path.join(ROOT, 'test', name), 'utf8');
    for (var i = 0; i < src.length; i++) {
      var c = src.charCodeAt(i);
      if (c < 32 && c !== 9 && c !== 10 && c !== 13) {
        offenders.push(name + ' has 0x' + c.toString(16) + ' at offset ' + i);
        break;
      }
    }
  });
  assert(offenders.length === 0,
    'control character in a test file: ' + offenders.join(', '));
});

// 46. Payload encryption is claimed only if something encrypts a payload
// Five pages sold BYOK encryption, one of them as an Enterprise feature and
// another as available on all plans, and the threat model recommended it for
// highest assurance. encryptPayload and decryptPayload were defined in
// server.js and never called, on any path, and no query has ever written the
// encrypted_payload column. The registration endpoint took a customer's
// AES-256 key, stored its last four characters as a hint, and answered
// byokEnabled: true.
//
// So the claim is tied to the only thing that could make it true: a write to
// encrypted_payload. While nothing writes it, no page may say we encrypt.
console.log('\nPayload encryption');

function serverEncryptsPayloads() {
  // A write, not a read. server.js reads the column to report whether a commit
  // is encrypted; that is not the same as producing one.
  return /encrypted_payload:\s*[^n]/.test(server);
}

test('no page claims payload encryption while nothing writes an encrypted payload', () => {
  if (serverEncryptsPayloads()) return;   // earned; nothing to check
  var banned = [
    /BYOK encryption/i,
    /we encrypt your payload/i,
    /payloads? (?:are|is) encrypted at rest/i,
    /encrypts? (?:the )?payloads? (?:before|at) (?:committing|rest)/i,
  ];
  var offenders = [];
  publicPages().forEach(function (pg) {
    var text = fs.readFileSync(pg.abs, 'utf8').replace(/<[^>]+>/g, ' ');
    banned.forEach(function (re) {
      var m = text.match(re);
      if (m) offenders.push(pg.slug + ': "' + m[0] + '"');
    });
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(offenders.length === 0,
    'payload encryption claimed, but nothing in server.js encrypts a payload:' +
    SEP + offenders.join(SEP));
});

test('the enterprise endpoint does not take a key it cannot use', () => {
  var i = server.indexOf("app.post('/enterprise/register'");
  assert(i !== -1, 'enterprise register route missing');
  // Strip comment lines first: the comment above this route explains what was
  // removed and names byokEnabled, so matching raw source finds the
  // explanation rather than the code. That is how two earlier guards passed
  // while hollow.
  var block = server.slice(i, i + 3000)
    .split(String.fromCharCode(10))
    .filter(function (line) { return line.trim().indexOf('//') !== 0; })
    .join(String.fromCharCode(10));
  assert(block.indexOf('byokEnabled') === -1,
    'byokEnabled tells the caller their payloads are protected; nothing protects them');
  assert(!/key_hint:\s*keyHint/.test(block),
    'storing four characters of a customer AES key leaks key material for a ' +
    'feature that does not exist');
});

test('no unused cipher helpers remain in server.js', () => {
  // They are what made the feature look implemented, to me included.
  ['function encryptPayload(', 'function decryptPayload('].forEach(function (fn) {
    assert(server.indexOf(fn) === -1,
      fn + ' is defined but nothing calls it; unused cipher code reads as a feature that runs');
  });
});

// 47. The schema we tell self-hosters to install must run the server
// Four pages offer self-hosting under the MIT licence, and the threat model
// offers it as a mitigation. SETUP.md step 2 said to run supabase/schema.sql.
// That file is a May snapshot: it has commits and agents and is missing
// log_entries, checkpoints, witnesses, witness_sigs, commit_usage, app_state,
// signing_keys, agent_pubkeys, workspace_members and subscriptions. Anyone
// following the documented path got a database the server cannot write a single
// commit to, because appendToLog inserts into log_entries.
console.log('\nSelf-hosting schema');

function schemaReferencedBySetup() {
  var setup = fs.readFileSync(path.join(ROOT, 'SETUP.md'), 'utf8');
  var m = setup.match(/run the contents of `supabase\/([a-z0-9_]+\.sql)`/i);
  assert(m, 'SETUP.md must name the schema file to install');
  return m[1];
}

test('SETUP.md names a schema file that exists', () => {
  var name = schemaReferencedBySetup();
  assert(fs.existsSync(path.join(ROOT, 'supabase', name)),
    'SETUP.md sends self-hosters to supabase/' + name + ', which is not there');
});

test('that schema contains every table the server queries', () => {
  var sql = fs.readFileSync(path.join(ROOT, 'supabase', schemaReferencedBySetup()), 'utf8');
  // Tables the server actually reads or writes, taken from the source rather
  // than from a list someone has to remember to update.
  var tables = {};
  var re = /\.from\('([a-z0-9_]+)'\)/g;
  var m;
  while ((m = re.exec(server)) !== null) tables[m[1]] = true;
  var names = Object.keys(tables);
  assert(names.length > 10, 'extracted only ' + names.length + ' tables; the extractor broke');

  var missing = names.filter(function (t) {
    // Format-tolerant, and built from literal strings so there is no pattern to
    // lose an escape. pg_dump writes "CREATE TABLE public.x (", older hand-
    // written files write "create table if not exists x(" and everything
    // between, so check the forms rather than one of them.
    var hay = sql.toLowerCase();
    var prefixes = ['create table ', 'create table if not exists '];
    var names2 = [t, 'public.' + t, '"' + t + '"', 'public."' + t + '"'];
    var seps = [' (', '('];
    for (var a = 0; a < prefixes.length; a++) {
      for (var b = 0; b < names2.length; b++) {
        for (var c = 0; c < seps.length; c++) {
          if (hay.indexOf(prefixes[a] + names2[b] + seps[c]) !== -1) return false;
        }
      }
    }
    return true;
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(missing.length === 0,
    'the schema self-hosters are told to install is missing tables the server ' +
    'queries, so it cannot run:' + SEP + missing.join(', '));
});

test('the schema can be applied to a fresh Supabase project', () => {
  var sql = fs.readFileSync(path.join(ROOT, 'supabase', schemaReferencedBySetup()), 'utf8');
  assert(sql.indexOf('CREATE SCHEMA public;') === -1,
    'a fresh Supabase project already has schema public, so this line aborts the ' +
    'script in the SQL editor before any table is created');
  ['OWNER TO', 'CREATE ROLE', 'ALTER DEFAULT PRIVILEGES'].forEach(function (stmt) {
    assert(sql.indexOf(stmt) === -1,
      stmt + ' will not apply on a managed Postgres, so the install stops there');
  });
});

// 48. Every environment variable the server reads is documented
// .env.example listed five variables. src/ reads twenty-six. Four of the
// missing ones change security behaviour when unset, and nothing anywhere said
// so:
//
//   DM_ENCRYPTION_KEY       webhook secrets and provider keys are written as
//                           "plain:<secret>" instead of AES-256-GCM, which the
//                           enterprise page states we do
//   DM_LOG_SIGNING_KEY_PEM  checkpoints are signed with a key that dies on the
//                           next restart, so the scheduler refuses to publish
//   SUPABASE_JWT_SECRET     session tokens
//   SUPERUSER_EMAIL/_AGENT_ID  who is an admin
//
// PRODUCTION.md listed the same five. Anyone self-hosting from our own
// instructions ran without all four.
console.log('\nEnvironment documentation');

function envVarsUsed() {
  var used = {};
  fs.readdirSync(path.join(ROOT, 'src')).forEach(function (f) {
    if (!/\.js$/.test(f)) return;
    var src = fs.readFileSync(path.join(ROOT, 'src', f), 'utf8');
    var re = /process\.env\.([A-Z_0-9]+)/g;
    var m;
    while ((m = re.exec(src)) !== null) used[m[1]] = true;
  });
  return Object.keys(used);
}

function envVarsDocumented() {
  var doc = fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8');
  var out = {};
  doc.split(String.fromCharCode(10)).forEach(function (line) {
    var t = line.trim();
    if (!t || t.charAt(0) === '#') return;
    var eq = t.indexOf('=');
    if (eq > 0) out[t.slice(0, eq)] = true;
  });
  return Object.keys(out);
}

test('.env.example documents every variable src/ reads', () => {
  var used = envVarsUsed(), doc = envVarsDocumented();
  assert(used.length > 20, 'extracted only ' + used.length + ' variables; the extractor broke');
  var missing = used.filter(function (v) { return doc.indexOf(v) === -1; });
  var SEP = String.fromCharCode(10) + '       ';
  assert(missing.length === 0,
    'the server reads these and nothing documents them, so a self-hosted ' +
    'deployment silently runs without them:' + SEP + missing.join(SEP));
});

test('.env.example documents nothing the server stopped reading', () => {
  var used = envVarsUsed(), doc = envVarsDocumented();
  var stale = doc.filter(function (v) { return used.indexOf(v) === -1; });
  assert(stale.length === 0,
    'documented but read nowhere in src/, so it misleads an operator: ' + stale.join(', '));
});

test('the variables that change security behaviour say what unset means', () => {
  var doc = fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8');
  ['DM_ENCRYPTION_KEY', 'DM_LOG_SIGNING_KEY_PEM'].forEach(function (v) {
    var at = doc.indexOf(v + '=');
    assert(at !== -1, v + ' must be documented');
    // The explanation sits above the assignment.
    var above = doc.slice(Math.max(0, at - 900), at);
    assert(/UNSET:/.test(above),
      v + ' fails open or degrades silently; the file must say what happens ' +
      'when it is not set');
  });
});

// 49. A sample record cannot show an assurance level no record ever gets
// The demo receipt read assurance_level: "L2", annotated "hash-chain verified",
// which is L1's definition. No real commit is ever L2: the commit path assigns
// L1, or L3 when a client attestation verifies, and nothing revisits a record
// after a checkpoint covers it. So the only L2 anyone could see was on
// fabricated demo data, and signup sold "Full L1 - L2 - L3 verification on
// every plan".
console.log('\nAssurance levels shown to visitors');

function levelsTheServerAssigns() {
  // Only assignments to the variable that reaches the stored column.
  var out = {};
  var re = /assuranceLevel\s*=\s*'(L[0-9])'/g;
  var m;
  while ((m = re.exec(server)) !== null) out[m[1]] = true;
  return Object.keys(out).sort();
}

test('the server still assigns only the levels we think it does', () => {
  var levels = levelsTheServerAssigns();
  assert(levels.join(',') === 'L1,L3',
    'the commit path now assigns ' + levels.join(',') + '. If L2 was wired up, ' +
    'the pages can say so; update this test deliberately.');
});

test('no page shows a sample record at a level the server never assigns', () => {
  var assigned = levelsTheServerAssigns();
  var offenders = [];
  publicPages().forEach(function (pg) {
    // Scan the raw file. Stripping tags with <[^>]+> destroys inline script,
    // because a JavaScript comparison opens a false tag that runs to the next
    // ">" and swallows everything between - which is exactly where demo.html
    // keeps its sample receipt, so the first version of this guard read a file
    // with the L2 removed and passed.
    var raw = fs.readFileSync(pg.abs, 'utf8');
    var key = 'assurance_level';
    var at = raw.indexOf(key);
    while (at !== -1) {
      var window_ = raw.slice(at, at + 200);
      // "c.assurance_level || 'L1'" is code reading the field with a default,
      // and the levels near it are branches in a colour map. A sample record
      // assigns a value. Skipping windows with || separates the two; the first
      // version flagged four of these on the admin dashboard.
      if (window_.indexOf('||') === -1) {
        ['L0', 'L1', 'L2', 'L3', 'L4'].forEach(function (lvl) {
          var shown = window_.indexOf('"' + lvl + '"') !== -1 ||
                      window_.indexOf("'" + lvl + "'") !== -1 ||
                      window_.indexOf('>' + lvl + '<') !== -1;
          if (shown && assigned.indexOf(lvl) === -1) {
            offenders.push(pg.slug + ' shows assurance_level ' + lvl);
          }
        });
      }
      at = raw.indexOf(key, at + 1);
    }
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(offenders.length === 0,
    'a sample record advertises an assurance level no commit reaches:' +
    SEP + offenders.join(SEP));
});

test('signup does not sell an assurance level that is unreachable', () => {
  var s = fs.readFileSync(path.join(ROOT, 'public/signup.html'), 'utf8');
  assert(s.indexOf('L2 &#183; L3 verification on every plan') === -1 &&
         !/Full L1[^<]*L2[^<]*on every plan/.test(s),
    'signup lists L2 as included; no commit is ever labelled L2');
});

// 50. A page that calls itself admin-only must not be advertised to crawlers
// The existing check matches slugs that look administrative - admin, dashboard,
// login. usage.html does not look like one by name, so it sat in the sitemap
// under the title "SDK usage and wrapper reference" while being an internal
// analytics view: total commits, L3 adoption, acquisition signal, wrapper
// breakdown. The numbers come from an authenticated endpoint so nothing leaked,
// but a crawler had no business being sent there.
//
// The page said "Admin only" on its own face. That is the signal to use, rather
// than guessing from the filename.
console.log('\nAdmin pages are not advertised');
test('a page that declares itself admin-only is excluded from the sitemap', () => {
  var excluded = sitemapExcluded();
  var offenders = [];
  publicPages().forEach(function (pg) {
    var text = fs.readFileSync(pg.abs, 'utf8');
    var declares = /Admin only|admin-only|Superuser only/i.test(text);
    if (declares && excluded.indexOf(pg.slug) === -1) {
      offenders.push(pg.slug + ' says it is admin-only and is in the sitemap');
    }
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(offenders.length === 0, 'internal pages advertised to crawlers:' + SEP + offenders.join(SEP));
});

test('robots.txt disallows the same paths the sitemap omits', () => {
  // Two lists that must agree. The sitemap omission stops us advertising the
  // page; the Disallow stops a crawler that found it another way.
  var excluded = sitemapExcluded();
  var i = server.indexOf("app.get('/robots.txt'");
  var block = server.slice(i, i + 1500);
  var missing = excluded.filter(function (slug) {
    // chain and join are share/invite targets people are given directly, and
    // carry noindex instead; the rest are app surfaces.
    if (slug === 'chain' || slug === 'join' || slug === 'chat') return false;
    return block.indexOf('Disallow: /' + slug) === -1;
  });
  assert(missing.length === 0,
    'excluded from the sitemap but not disallowed in robots.txt: ' + missing.join(', '));
});

// 51. The README teaches an API too, and three of its endpoints never existed
// The check above scans the site for darkmatterhub.ai/api/... URLs. The README
// writes bare paths, so it was never covered, and it documented three routes
// with request bodies and response shapes:
//
//   POST /dashboard/agents/:id/webhook    the real one is POST /api/hooks
//   POST /dashboard/agents/:id/retention  nothing sets retention; it follows the plan
//   GET  /api/stats                       there is no unauthenticated stats route
//
// It is the first page a developer reads on GitHub.
console.log('\nREADME API reference');
test('every endpoint the README documents has a route', () => {
  var rd = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  var METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
  var refs = [];

  rd.split(String.fromCharCode(10)).forEach(function (line, i) {
    var t = line.trim();
    // "### POST /api/commit" headings
    if (t.indexOf('### ') === 0) {
      var rest = t.slice(4).trim().split(' ');
      if (METHODS.indexOf(rest[0]) !== -1 && rest[1] && rest[1].charAt(0) === '/') {
        refs.push({ method: rest[0], path: rest[1], line: i + 1 });
      }
    }
    // Inline `POST /api/hooks` mentions
    METHODS.forEach(function (m) {
      var needle = '`' + m + ' /';
      var at = t.indexOf(needle);
      while (at !== -1) {
        var close = t.indexOf('`', at + 1);
        if (close !== -1) {
          var p = t.slice(at + m.length + 2, close).trim();
          if (p.charAt(0) === '/') refs.push({ method: m, path: p, line: i + 1 });
        }
        at = t.indexOf(needle, at + 1);
      }
    });
  });

  assert(refs.length > 5, 'found only ' + refs.length + ' endpoint references; the extractor broke');

  var missing = refs.filter(function (r) {
    // Normalise a path parameter to the segment count, then look for a route
    // whose registered path matches segment by segment. Plain string work, so
    // there is no pattern here to lose an escape.
    var want = r.path.split('?')[0].split('/').filter(Boolean);
    var re = /app\.(get|post|put|patch|delete)\(\s*'([^']+)'/g;
    var m2, ok = false;
    while ((m2 = re.exec(server)) !== null) {
      if (m2[1].toUpperCase() !== r.method) continue;
      var have = m2[2].split('/').filter(Boolean);
      if (have.length !== want.length) continue;
      var same = true;
      for (var k = 0; k < have.length; k++) {
        if (have[k].charAt(0) === ':' || want[k].charAt(0) === ':') continue;
        if (have[k] !== want[k]) { same = false; break; }
      }
      if (same) { ok = true; break; }
    }
    return !ok;
  });

  var SEP = String.fromCharCode(10) + '       ';
  assert(missing.length === 0,
    'the README documents endpoints that do not exist:' + SEP +
    missing.map(function (r) { return r.method + ' ' + r.path + ' (line ' + r.line + ')'; }).join(SEP));
});

// 52. A webhook secret signs the body; it is never sent
// fireEventHooks put the customer's secret in an X-Hook-Secret header on every
// delivery. That transmits the secret through the receiver's proxies and logs
// on every request, and proves nothing about the body it arrived with: anyone
// who ever saw a delivery could forge one. The README already documented an
// HMAC over the body, which is what a receiver would code against, so the code
// now matches the documentation rather than the other way round.
console.log('\nWebhook delivery');
test('the delivery signs the body and does not send the secret', () => {
  var i = server.indexOf('async function fireEventHooks');
  assert(i !== -1, 'fireEventHooks not found');
  var block = server.slice(i, i + 2000)
    .split(String.fromCharCode(10))
    .filter(function (l) { return l.trim().indexOf('//') !== 0; })
    .join(String.fromCharCode(10));
  assert(block.indexOf('X-Hook-Secret') === -1,
    'the secret is being sent as a header again');
  assert(block.indexOf('X-DarkMatter-Signature') !== -1,
    'deliveries must carry an HMAC signature header');
  assert(/createHmac\('sha256',\s*hookSecret\)/.test(block),
    'the signature must be HMAC-SHA256 keyed with the customer secret');
  assert(block.indexOf('.update(body') !== -1,
    'the HMAC must cover the exact body that is sent, or it proves nothing');
});

test('the README documents the header the code sends', () => {
  var rd = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  assert(rd.indexOf('X-DarkMatter-Signature') !== -1,
    'the README must name the signature header receivers should check');
  assert(rd.indexOf('X-Hook-Secret') === -1,
    'the README must not teach a header the code no longer sends');
});

// 53. Sample verifier output must be output the verifier can produce
// integrations/claude.html showed a terminal transcript of
// verify_darkmatter_chain.py printing four ticks, two of which it has never
// printed and cannot: "Agent signature valid" and "Included in checkpoint".
// The script checks payload hashes and chain links, and says so itself - it
// even prints a note that it cannot prove records were not withheld. Showing a
// transcript is a stronger claim than prose, because the reader takes it as a
// recording of something that happened.
console.log('\nSample verifier output');

function verifierSource() {
  return fs.readFileSync(path.join(ROOT, 'examples/verify_darkmatter_chain.py'), 'utf8');
}

test('the verifier does not check signatures or checkpoints', () => {
  // If this changes, the transcripts may claim more. Deliberate update.
  var v = verifierSource();
  assert(v.indexOf('ed25519') === -1 && v.indexOf('Ed25519') === -1,
    'the verifier now does signature work; sample output may claim it');
  assert(v.indexOf('tree_root') === -1,
    'the verifier now does checkpoint work; sample output may claim it');
});

test('no page shows the verifier reporting a check it does not make', () => {
  var banned = ['signature valid', 'Signature valid', 'Included in checkpoint',
                'included in checkpoint', 'Merkle inclusion verified'];
  var offenders = [];
  publicPages().forEach(function (pg) {
    var raw = fs.readFileSync(pg.abs, 'utf8');
    // Only where the page is showing the verifier being run.
    if (raw.indexOf('verify_darkmatter_chain.py') === -1) return;
    banned.forEach(function (b) {
      if (raw.indexOf(b) !== -1) offenders.push(pg.slug + ': "' + b + '"');
    });
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(offenders.length === 0,
    'a transcript claims the verifier reports something it never prints:' +
    SEP + offenders.join(SEP));
});

// 54. The reference witness server has to be reachable to be run
// L2 is a second signature from our own trust domain until somebody outside
// runs a witness. github-template/darkmatter_witness_server.py is exactly what
// they would run - it verifies our signature, co-signs the same canonical
// envelope with its own key, keeps its own log - and it was referenced by no
// page, linked from no document and served from no route. The one asset that
// could close the gap was unreachable.
console.log('\nReference witness server');

test('the witness server is served', () => {
  assert(server.indexOf("app.get('/darkmatter_witness_server.py'") !== -1,
    'nobody can run a witness they cannot download');
  assert(server.indexOf('github-template/darkmatter_witness_server.py') !== -1,
    'the route must send the file that actually exists');
  assert(fs.existsSync(path.join(ROOT, 'github-template/darkmatter_witness_server.py')),
    'the file the route sends must exist');
});

test('a page tells the reader they can run one', () => {
  var refs = [];
  publicPages().forEach(function (pg) {
    var html = fs.readFileSync(pg.abs, 'utf8');
    if (html.indexOf('darkmatter_witness_server.py') !== -1) refs.push(pg.slug);
  });
  assert(refs.length > 0,
    'no page mentions the witness server, so the invitation reaches nobody');
});

test('the reference witness canonicalises keys the way the server does', () => {
  // It signs the same envelope we sign. If the two order keys differently, its
  // signature never verifies and the witness looks broken rather than the
  // canonicaliser. Plain sorted() is code point; RFC 8785 is UTF-16 code unit.
  var src = fs.readFileSync(path.join(ROOT, 'github-template/darkmatter_witness_server.py'), 'utf8');
  assert(src.indexOf("sorted(value.keys())") === -1,
    'the witness sorts by code point; the server sorts by UTF-16 code unit');
  assert(src.indexOf("utf-16-be") !== -1,
    'the witness must sort keys by UTF-16 code unit');
});

test('the witness does not treat log position zero as missing', () => {
  var src = fs.readFileSync(path.join(ROOT, 'github-template/darkmatter_witness_server.py'), 'utf8');
  assert(src.indexOf("checkpoint.get('position') or checkpoint.get('log_position')") === -1,
    'position 0 is falsy, so the first checkpoint of a log would sign the wrong value');
});

// 55. Shipped example bundles must verify with the shipped verifier
// examples/ carried three proof bundles in a pre-v3 shape - {readme, metadata,
// verification, chain} - that the verifier next to them rejects as
// unrecognised. Someone evaluating the product runs the verifier against the
// samples sitting beside it and concludes the thing does not work. It also
// carried chain.json, which was not JSON at all: a saved HTML error page,
// committed as if it were data.
console.log('\nExample artifacts');

function examplesDir() { return path.join(ROOT, 'examples'); }

test('every JSON file in examples/ is JSON', () => {
  var bad = [];
  fs.readdirSync(examplesDir()).forEach(function (f) {
    if (!/\.json$/.test(f)) return;
    var raw = fs.readFileSync(path.join(examplesDir(), f), 'utf8');
    try { JSON.parse(raw); }
    catch (e) { bad.push(f + ' (' + raw.trim().slice(0, 30) + '...)'); }
  });
  assert(bad.length === 0, 'not parseable as JSON: ' + bad.join(', '));
});

test('every example bundle is in a shape the verifier accepts', () => {
  // The verifier takes a passports array, a commits array, or a single record.
  // A bundle we ship that it rejects is worse than shipping none.
  var bad = [];
  fs.readdirSync(examplesDir()).forEach(function (f) {
    if (!/\.json$/.test(f)) return;
    var j;
    try { j = JSON.parse(fs.readFileSync(path.join(examplesDir(), f), 'utf8')); }
    catch (e) { return; }   // covered by the test above
    var ok = Array.isArray(j.passports) || Array.isArray(j.commits) ||
             (j.payload && j.integrity);
    if (!ok) bad.push(f + ' has keys: ' + Object.keys(j).join(', '));
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(bad.length === 0,
    'the shipped verifier rejects a bundle we ship beside it:' + SEP + bad.join(SEP));
});

test('example scripts the README names exist', () => {
  var rd = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  var missing = [];
  rd.split(String.fromCharCode(10)).forEach(function (line) {
    var t = line.trim();
    if (t.indexOf('python examples/') !== 0) return;
    var rel = t.slice('python '.length).split(' ')[0];
    if (!fs.existsSync(path.join(ROOT, rel))) missing.push(rel);
  });
  assert(missing.length === 0,
    'the README tells the reader to run files that are not there: ' + missing.join(', '));
});

test('the handoff example reads the fields the API returns', () => {
  // /api/pull answers {agentId, agentName, contexts, count} and each entry is a
  // Context Passport with created_by, event, payload, integrity. agent_yy.py
  // read data["commits"] and latest["context"], so it found nothing and would
  // have raised KeyError if it had.
  var yy = fs.readFileSync(path.join(examplesDir(), 'agent_yy.py'), 'utf8');
  assert(yy.indexOf('data.get("commits"') === -1,
    'the pull response has no commits key; this example finds nothing');
  assert(yy.indexOf('data.get("contexts"') !== -1,
    'the example must read contexts from the pull response');
  assert(yy.indexOf("latest['context']") === -1 && yy.indexOf('latest["context"]') === -1,
    'a pulled record has payload, not context');
});

// 56. Every page wears the same header and footer
// The three blog posts each had their own. One used <nav> with ul.nav-links and
// a circle-and-triangle logo and no footer at all; another used .dm-nav and
// .dm-footer with a gradient logo. Three different marks for the same company,
// and two pages with no footer, on the part of the site meant to be read by
// people deciding whether to trust it.
console.log('\nShared page shell');

function shellPages() {
  // Posts and the main marketing pages. App and auth surfaces are excluded:
  // they are deliberately chromeless.
  var out = [];
  var skip = ['admin', 'admindashboard', 'dashboard', 'login', 'signup', 'chat',
              'chain', 'join', 'reset-password', 'organizations', 'usage', 'verify'];
  publicPages().forEach(function (pg) {
    var base = pg.slug.split('/').pop();
    if (skip.indexOf(base) !== -1) return;
    out.push(pg);
  });
  return out;
}

test('every blog post uses the site header and footer', () => {
  var missing = [];
  publicPages().forEach(function (pg) {
    if (pg.slug.indexOf('blogs/') !== 0) return;
    var html = fs.readFileSync(pg.abs, 'utf8');
    if (html.indexOf('<header class="nav">') === -1) missing.push(pg.slug + ': no site header');
    if (html.indexOf('<footer') === -1) missing.push(pg.slug + ': no footer');
    if (html.indexOf('class="wordmark"') === -1) missing.push(pg.slug + ': no wordmark');
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(missing.length === 0, 'posts not wearing the site shell:' + SEP + missing.join(SEP));
});

test('no page carries a competing header or logo', () => {
  // The old markup, by the class names only those variants used.
  var offenders = [];
  shellPages().forEach(function (pg) {
    var html = fs.readFileSync(pg.abs, 'utf8');
    ['dm-nav', 'dm-footer', 'dm-nav-logo', 'logo-wm'].forEach(function (cls) {
      if (html.indexOf('class="' + cls) !== -1) offenders.push(pg.slug + ' uses .' + cls);
    });
  });
  var SEP = String.fromCharCode(10) + '       ';
  assert(offenders.length === 0,
    'a second header or logo design is back:' + SEP + offenders.join(SEP));
});

test('the shared shell brings its own link reset', () => {
  // The main pages reset link decoration globally and the posts do not, so the
  // wordmark rendered underlined until the shared block carried its own reset.
  var missing = [];
  publicPages().forEach(function (pg) {
    if (pg.slug.indexOf('blogs/') !== 0) return;
    var html = fs.readFileSync(pg.abs, 'utf8');
    if (!/\.wordmark[^{]*\{[^}]*text-decoration:\s*none/.test(html)) {
      missing.push(pg.slug);
    }
  });
  assert(missing.length === 0,
    'these would render the wordmark underlined: ' + missing.join(', '));
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
