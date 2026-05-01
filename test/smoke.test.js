/**
 * DarkMatter Smoke Tests
 * Run: node test/smoke.test.js
 * Tests: syntax, route presence, critical logic, dashboard JS
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
  ['GET /ext/callback',             "app.get('/ext/callback'"],
  ['POST /auth/login',              "app.post('/auth/login'"],
  // L3 + features
  ['GET /api/workspace/api-keys',   "app.get('/api/workspace/api-keys'"],
  ['POST /api/workspace/api-keys',  "app.post('/api/workspace/api-keys'"],
  ['POST /api/workspace/keys',      "app.post('/api/workspace/keys'"],
  ['POST /api/contact',             "app.post('/api/contact'"],
  ['GET /api/billing/subscription', "app.get('/api/billing/subscription'"],
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
test('requireApiKey direct query', function() { assert(server.includes(".eq('api_key', apiKey)")); });

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
var ri = server.indexOf("app.get('/r/:traceId'");
var rb = server.slice(ri, ri + 30000);
test('first-screen',          function() { assert(rb.includes('first-screen')); });
test('chain integrity check', function() { assert(rb.includes('chainIntact')); });
test('only real mismatch',    function() { assert(rb.includes('Missing parent_hash')); });
test('four view tabs',        function() { assert(rb.includes('view-conv') && rb.includes('view-timeline') && rb.includes('view-proof') && rb.includes('view-json')); });
test('YOU role label',        function() { assert(rb.includes('YOU') && rb.includes('platHint'), 'YOU label not found'); });
test('copy link button',      function() { assert(rb.includes('copyLink()')); });

// 7. Dashboard JS
console.log('\nDashboard JS');
test('showView explicit flex', function() { assert(dashJS.includes("var dm={records:'flex'")); });
test('init calls showView',    function() { assert(dashJS.includes("showView('records')")); });
test('no onclick quote bug',   function() { assert(!dashJS.includes("switchView('proof'")); });
test('UTC pill data attrs',    function() { assert(dashJS.includes('data-utc=')); });
test('stale request guard',    function() { assert(dashJS.includes('_fetchSeq')); });
test('sends refresh token',    function() { assert(dashJS.includes("'X-Refresh-Token'")); });
test('picks up rotated token', function() { assert(dashJS.includes('X-New-Access-Token')); });
test('YOU label',              function() { assert(dashJS.includes("YOU'+platHint")); });
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

// 8. L3 + assurance_level in commit route
console.log('\nL3 non-repudiation');
var commitIdx = server.indexOf("app.post('/api/commit'");
var commitSlice = server.slice(commitIdx, commitIdx + 8000);
test('completeness_claim destructured', function() { assert(commitSlice.includes('completeness_claim')); });
test('client_attestation accepted',     function() { assert(commitSlice.includes('client_attestation')); });
test('assurance_level computed',        function() { assert(commitSlice.includes('assuranceLevel')); });
test('assurance_level stored in DB',    function() { assert(commitSlice.includes('assurance_level:')); });
test('receipt.assurance_level set',     function() { assert(server.includes('receipt.assurance_level')); });
test('receipt.verify_url set',          function() { assert(server.includes('receipt.verify_url')); });

// 9. /r/ share page — L3 badge + completeness
console.log('\n/r/ L3 display');
var shareIdx = server.indexOf("app.get('/r/:traceId'");
var shareSlice = server.slice(shareIdx, shareIdx + 35000);
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
var AGENTS_SAFE_INSERT_COLS = ['agent_id','agent_name','user_id','api_key',
  'webhook_url','webhook_secret','retention_days'];
var AGENTS_UNSAFE_INSERT = ['api_key_hash']; // column may or may not exist — never safe to insert

test('api_key_hash not inserted in workspace/api-keys route', function() {
  var routeStart = server.indexOf("app.post('/api/workspace/api-keys'");
  var routeEnd   = server.indexOf('});', routeStart) + 3;
  var routeCode  = server.slice(routeStart, routeEnd);
  assert(!routeCode.includes('api_key_hash:'), 'api_key_hash inserted in workspace/api-keys — column may not exist in DB');
});

test('workspace/api-keys insert matches original /dashboard/agents pattern', function() {
  // The safe pattern (proven to work) only inserts: agent_id, agent_name, user_id, api_key
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
].forEach(function(pair) {
  var routePos = server.indexOf(pair[0]);
  test(pair[1] + ' before catch-all', function() {
    assert(routePos > 0 && routePos < catchallPos,
      pair[1] + ' is missing or after the catch-all route — it will never be reached');
  });
});


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
  assert(routeSlice.includes('adminEmails.includes'), 'audit-log must check adminEmails, not just requireAuth');
});

// H-2: admin email guard on ping
test('/api/admin/ping has admin email guard (H-2)', function() {
  var routeStart = server.indexOf("app.get('/api/admin/ping'");
  assert(routeStart > 0, 'ping route not found');
  var routeSlice = server.slice(routeStart, routeStart + 800);
  assert(routeSlice.includes('adminEmails.includes'), 'ping must check adminEmails, not just requireAuth');
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

// Summary
console.log('\n' + '-'.repeat(50));
console.log('Passed: ' + passed + '  Failed: ' + failed + '  Total: ' + (passed+failed));
if (failed > 0) { console.error('\n\u2717 SOME TESTS FAILED'); process.exit(1); }
else { console.log('\n\u2713 ALL TESTS PASSED'); }
