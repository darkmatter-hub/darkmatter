#!/usr/bin/env node
/**
 * Does this service produce records the published standard accepts?
 *
 *   node test/conformance.test.js
 *
 * For months the answer was no, and nothing here noticed. payload_hash was
 * computed three different ways across five write paths, three of them using
 * JSON.stringify rather than RFC 8785, and every path built the chain input by
 * concatenating bare hex where SPEC.md 3.4 concatenates the "sha256:"-prefixed
 * forms. One path folded the commit id in as well.
 *
 * Each path was internally consistent, and this service's own verifier agreed
 * with all of them, so every test passed and the proof page said "Record
 * intact". The records simply were not what the specification describes, and
 * verify_chain in the reference SDKs correctly called them broken. On a product
 * whose whole claim is that a stranger can check a record with the open
 * standard, that is the most expensive kind of bug: everything looks right from
 * the inside.
 *
 * So this file does not check our implementation against itself. The expected
 * values in test/conformance-vectors.json were produced by the Python
 * reference SDK (`context-passport` on PyPI) and are pinned here. If our output
 * drifts from the standard again, these fail.
 *
 * Regenerate the vectors only when the SPECIFICATION changes, never to make a
 * failing test pass. A conformance test you can edit to agree with your code is
 * not a conformance test.
 */

const fs = require('fs');
const path = require('path');
const { hashPayload, chainIntegrityHash, computeChain, prefixed, bare } =
  require('../src/integrity');

const vectorFile = path.join(__dirname, 'conformance-vectors.json');
const { parent_for_child_cases: PARENT, vectors } =
  JSON.parse(fs.readFileSync(vectorFile, 'utf8'));

let passed = 0;
let failed = 0;

function check(name, actual, expected) {
  if (actual === expected) {
    passed++;
    console.log('  ✓ ' + name);
  } else {
    failed++;
    console.log('  ✗ ' + name);
    console.log('      expected (reference SDK): ' + expected);
    console.log('      actual   (this service):  ' + actual);
  }
}

console.log('\nContext Passport conformance');
console.log('Expected values come from the Python reference SDK, not from this codebase.\n');

for (const v of vectors) {
  check(
    v.label + ' — payload_hash',
    prefixed(hashPayload(v.payload)),
    v.payload_hash,
  );
  check(
    v.label + ' — integrity_hash (root)',
    prefixed(chainIntegrityHash(hashPayload(v.payload), null)),
    v.integrity_root,
  );
  check(
    v.label + ' — integrity_hash (with parent)',
    prefixed(chainIntegrityHash(hashPayload(v.payload), bare(PARENT))),
    v.integrity_child,
  );
}

// computeChain is what the write paths call. It must agree with the pieces.
console.log('');
for (const v of vectors.slice(0, 3)) {
  const c = computeChain(v.payload, null);
  check('computeChain agrees — ' + v.label, prefixed(c.payloadHash), v.payload_hash);
  check('computeChain agrees — ' + v.label + ' (integrity)', prefixed(c.integrityHash), v.integrity_root);
}

// The prefix helpers must never double-prefix, which would silently change
// every hash the moment a caller passed an already-prefixed value.
console.log('');
check('prefixed() is idempotent', prefixed(prefixed('abc')), 'sha256:abc');
check('bare() strips exactly once', bare(bare('sha256:abc')), 'abc');
check('bare() leaves unprefixed alone', bare('abc'), 'abc');

console.log('\n' + '-'.repeat(50));
console.log('Passed: ' + passed + '  Failed: ' + failed + '  Total: ' + (passed + failed));
if (failed) {
  console.log('\n✗ This service is producing records the standard does not accept.');
  process.exit(1);
}
console.log('\n✓ Output matches the reference implementation.\n');
