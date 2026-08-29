/**
 * Tests the verification logic that runs in the browser on /verify.
 *
 * This exists because that page shipped for a long time doing no verification
 * at all. Its checks were:
 *
 *     function checkIntegrity(b) {
 *       // In production: recompute payload hash and compare
 *       // Demo: pass if required fields present
 *       return !!(b.record_id && b.payload_hash && b.integrity_hash && b.timestamp);
 *     }
 *
 * It reported "the payload hash matches the stored record, no changes
 * detected" without hashing anything, and offered the result as a downloadable
 * artifact. A tool that cannot fail is worse than no tool on a page whose
 * purpose is detecting tampering.
 *
 * The functions are pulled out of public/verify.html rather than copied, so
 * this tests what actually ships. If the block cannot be found the test fails
 * loudly instead of silently checking nothing.
 *
 * Run: node test/verify_page.test.js
 */
'use strict';

const fs   = require('fs');
const path = require('path');
const { canonicalize, hashPayload } = require('../src/integrity');

const PAGE = path.join(__dirname, '../public/verify.html');

let passed = 0, failed = 0;
function check(label, cond, detail) {
  if (cond) { console.log('  ✓ ' + label); passed++; }
  else { console.error('  ✗ ' + label + (detail ? '\n      ' + detail : '')); failed++; }
}

// ── Extract the shipped implementation ───────────────────────────────────────
const html = fs.readFileSync(PAGE, 'utf8');
const script = (html.match(/<script>([\s\S]*?)<\/script>/) || [])[1];
if (!script) { console.error('  ✗ no <script> block in verify.html'); process.exit(1); }

const from = script.indexOf('function jcs(');
const to   = script.indexOf('let VERIFY_RESULT');
if (from === -1 || to <= from) {
  console.error('  ✗ verification block not found in verify.html — did it get removed?');
  process.exit(1);
}
const mod = {};
new Function('crypto', 'TextEncoder', 'module', script.slice(from, to) +
  '\nmodule.jcs=jcs;module.payloadHashOf=payloadHashOf;' +
  'module.computeVerification=computeVerification;module.extractRecords=extractRecords;'
)(globalThis.crypto, TextEncoder, mod);

// A bundle whose hashes are computed, never pasted.
async function makeBundle(n) {
  const recs = [];
  let parent = null;
  for (let i = 0; i < n; i++) {
    const payload = { step: i, note: 'café 中文 \u{1F600}', amount: 284, ok: true };
    const ph = 'sha256:' + hashPayload(payload);   // integrity.js returns bare hex
    const ih = 'sha256:' + require('crypto').createHash('sha256')
      .update(ph + (parent || 'root'), 'utf8').digest('hex');
    recs.push({
      id: 'ctx_' + i, parent_id: i ? 'ctx_' + (i - 1) : null,
      payload, integrity: { payload_hash: ph, parent_hash: parent, integrity_hash: ih },
    });
    parent = ih;
  }
  return { format: 'context-passport-bundle', passports: recs };
}

(async () => {
  // The browser implementation must agree with src/integrity.js, which is
  // itself checked against the Python reference SDK by the conformance suite.
  // Two independent implementations of RFC 8785 in this repo have to match, or
  // a record verified in one place fails in the other.
  const tricky = { z: 1.5, a: null, s: 'café 中文 \u{1F600}',
                   n: 284, nested: { b: [1, 2, { c: true }] } };
  check('browser JCS matches src/integrity.js canonicalize',
    mod.jcs(tricky) === canonicalize(tricky),
    'browser: ' + mod.jcs(tricky) + '\n      server: ' + canonicalize(tricky));
  check('browser payload hash matches src/integrity.js hashPayload',
    (await mod.payloadHashOf(tricky)) === 'sha256:' + hashPayload(tricky),
    await mod.payloadHashOf(tricky));

  const good = await makeBundle(3);
  let r = await mod.computeVerification(good);
  check('an intact chain verifies', r.usable && r.integrityOk && r.lineageOk,
    JSON.stringify(r.errors));
  check('it reports how many records it actually checked', r.count === 3, String(r.count));

  // Each of these is a way a record gets altered in practice.
  const edited = JSON.parse(JSON.stringify(good));
  edited.passports[1].payload.amount = 999999;
  r = await mod.computeVerification(edited);
  check('an edited payload fails', !r.integrityOk, 'integrityOk stayed true');

  const relinked = JSON.parse(JSON.stringify(good));
  relinked.passports[2].integrity.parent_hash = 'sha256:' + '0'.repeat(64);
  r = await mod.computeVerification(relinked);
  check('a broken chain link fails', !r.lineageOk, 'lineageOk stayed true');

  const reordered = JSON.parse(JSON.stringify(good));
  reordered.passports.reverse();
  r = await mod.computeVerification(reordered);
  check('reordered records fail', !(r.integrityOk && r.lineageOk), 'reordering passed');

  const forged = JSON.parse(JSON.stringify(good));
  forged.passports[0].integrity.payload_hash = 'sha256:' + 'a'.repeat(64);
  r = await mod.computeVerification(forged);
  check('an invented payload_hash fails', !r.integrityOk, 'a made-up hash passed');

  // The exact shape the old fake example used. It must no longer be accepted,
  // because nothing in it can be verified.
  r = await mod.computeVerification({
    record_id: 'rec_1', payload_hash: 'sha256:4c2f8a1e93b7a8f3c2e1b9d0472c8d1f',
    integrity_hash: 'sha256:4c2f8a1e93b7f4b1e9d78c3a205134a2', timestamp: '2026-04-13T14:32:17Z',
  });
  check('a bundle with no payload is rejected, not passed', !r.usable, 'still reported usable');

  // No Ed25519 verification happens here, so it must never report a pass.
  r = await mod.computeVerification(good);
  check('signature is never reported as verified', r.signatureOk !== true, String(r.signatureOk));

  // The example the page ships must be one that actually verifies.
  const example = (html.match(/const EXAMPLE_BUNDLE = ([\s\S]*?);\r?\n/) || [])[1];
  check('the shipped example bundle parses', !!example);
  if (example) {
    const parsed = JSON.parse(example);
    r = await mod.computeVerification(parsed);
    check('the shipped example bundle actually verifies',
      r.usable && r.integrityOk && r.lineageOk, JSON.stringify(r.errors));
  }

  console.log('\n  Passed: ' + passed + '  Failed: ' + failed);
  process.exit(failed ? 1 : 0);
})();
