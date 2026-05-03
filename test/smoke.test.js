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
var rb = server.slice(ri, ri + 60000);
test('first-screen',          function() { assert(rb.includes('first-screen')); });
test('chain integrity check', function() { assert(rb.includes('chainIntact')); });
test('only real mismatch',    function() { assert(rb.includes('Missing parent_hash')); });
test('four view tabs',        function() { assert(rb.includes('view-conv') && rb.includes('view-timeline') && rb.includes('view-proof') && rb.includes('view-json')); });
test('YOU role label',        function() { assert(rb.includes('YOU') && rb.includes('platHint'), 'YOU label not found'); });
test('copy link button',      function() { assert(rb.includes('copyLink()')); });

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
var commitSlice = server.slice(commitIdx, commitIdx + 16000);
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
  assert(slice.includes('adminEmails.includes'), '/api/admin/users must check adminEmails, not just requireAuth');
});

test('/api/admin/flags GET has admin email guard', function() {
  var idx = server.indexOf("app.get('/api/admin/flags'");
  assert(idx > 0, '/api/admin/flags GET route not found');
  var slice = server.slice(idx, idx + 600);
  assert(slice.includes('adminEmails.includes'), '/api/admin/flags GET must check adminEmails, not just requireAuth');
});

test('/api/admin/flags POST has admin email guard', function() {
  var idx = server.indexOf("app.post('/api/admin/flags'");
  assert(idx > 0, '/api/admin/flags POST route not found');
  var slice = server.slice(idx, idx + 700);
  assert(slice.includes('adminEmails.includes'), '/api/admin/flags POST must check adminEmails, not just requireAuth');
});

test('client_attestation verified before assuranceLevel set to L3', function() {
  var commitIdx = server.indexOf("app.post('/api/commit'");
  var slice     = server.slice(commitIdx, commitIdx + 16000);
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

// Summary
console.log('\n' + '-'.repeat(50));
console.log('Passed: ' + passed + '  Failed: ' + failed + '  Total: ' + (passed+failed));
if (failed > 0) { console.error('\n\u2717 SOME TESTS FAILED'); process.exit(1); }
else { console.log('\n\u2713 ALL TESTS PASSED'); }
