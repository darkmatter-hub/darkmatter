#!/usr/bin/env node
/**
 * Runs DarkMatter against the published Context Passport conformance vectors.
 *
 *   node test/conformance-suite.test.js
 *
 * The vectors in test/conformance-vectors/ are copied verbatim from
 * contextpassport/conformance-tests, which publishes them CC0 so any
 * implementation can run them. The reference harness is Python; DarkMatter is
 * JavaScript, so this is DarkMatter's runner, reading the same files and
 * applying the same `expected` values as everyone else.
 *
 * There is no privileged path here, and that is the point. DarkMatter does not
 * get to define its own conformance, grade itself on vectors it wrote, or claim
 * a level it has not passed. If a vector fails, DarkMatter is wrong. The one
 * thing that must never happen is editing a vector so our implementation
 * passes: the vendor that publishes a standard marking its own homework is
 * worth less than no conformance claim at all.
 *
 * This complements test/conformance.test.js. That one pins our hashing to
 * values the reference SDK produced. This one runs the public suite. Together
 * they answer "do we compute what the spec says" and "do we pass what everyone
 * else is graded on".
 */

const fs = require('fs');
const path = require('path');
const { hashPayload, chainIntegrityHash, prefixed, bare, parsePassport } = require('../src/integrity');

const DIR = path.join(__dirname, 'conformance-vectors');

let passed = 0;
let failed = 0;
let skipped = 0;

function ok(name, cond, detail) {
  if (cond) { passed++; console.log('  ✓ ' + name); }
  else { failed++; console.log('  ✗ ' + name); if (detail) console.log('      ' + detail); }
}

function skip(name, why) {
  skipped++;
  console.log('  - ' + name + '  (not claimed: ' + why + ')');
}

// Verify a chain of Context Passport records the way SPEC.md 3.4 defines it:
// recompute payload_hash from the payload, recompute integrity_hash from that
// and the parent, and require both to match what the record asserts.
function verifyPassportChain(passports) {
  let previous = null;
  for (const p of passports) {
    const integrity = p.integrity || {};
    const expectedPayload = prefixed(hashPayload(p.payload));
    if (prefixed(integrity.payload_hash) !== expectedPayload) return false;

    const parentAsserted = integrity.parent_hash ? bare(integrity.parent_hash) : null;
    if (previous) {
      const parentActual = bare(previous.integrity.integrity_hash);
      if (parentAsserted !== parentActual) return false;
    } else if (parentAsserted !== null) {
      return false;
    }

    const expectedIntegrity = prefixed(chainIntegrityHash(bare(expectedPayload), parentAsserted));
    if (prefixed(integrity.integrity_hash) !== expectedIntegrity) return false;

    previous = p;
  }
  return true;
}

function loadVectors(level) {
  const dir = path.join(DIR, level);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort()
    .map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')));
}

function runVector(v) {
  const name = v.name + ' — ' + v.operation;

  switch (v.operation) {
    case 'verify_chain': {
      const actual = verifyPassportChain(v.input.passports);
      ok(name, actual === v.expected.result,
        'expected ' + v.expected.result + ', got ' + actual + (v.expected.note ? '  [' + v.expected.note + ']' : ''));
      return;
    }

    case 'compare_payload_hashes': {
      // Two representations of the same payload must hash identically, and to
      // the value the vector states.
      // The vector names its payloads payload_a, payload_b, ... rather than
      // supplying an array.
      const hashes = Object.keys(v.input)
        .filter((k) => k.startsWith('payload'))
        .sort()
        .map((k) => prefixed(hashPayload(v.input[k])));
      const allEqual = hashes.every((h) => h === hashes[0]);
      const matches = v.expected.hash ? hashes[0] === v.expected.hash : true;
      ok(name, allEqual && matches && v.expected.result === 'equal',
        'expected ' + v.expected.hash + ', got ' + hashes[0]);
      return;
    }

    case 'parse_should_reject': {
      const parsed = parsePassport(v.input.passport);
      ok(name, parsed.ok === false,
        'expected rejection, got ok=' + parsed.ok + '  errors=' + JSON.stringify(parsed.errors));
      return;
    }

    case 'verify_signature':
    case 'verify_signature_pair_consistency': {
      // Signed conformance requires verify_signature over the specification's
      // signing envelope. DarkMatter signs its own L2/L3 envelope, which binds
      // agent and key identity and is a different structure. Not a pass.
      skip(name, 'DarkMatter signs its own L2/L3 envelope, not the spec envelope');
      return;
    }

    default:
      skip(name, 'unknown operation');
  }
}

console.log('\nDarkMatter against the published Context Passport conformance vectors');
console.log('Vectors copied verbatim from contextpassport/conformance-tests (CC0).\n');

console.log('Core (vectors/required)');
loadVectors('required').forEach(runVector);

console.log('\nSigned (vectors/signed)');
loadVectors('signed').forEach(runVector);

console.log('\n' + '-'.repeat(58));
console.log('Passed: ' + passed + '  Failed: ' + failed + '  Not claimed: ' + skipped);

if (failed) {
  console.log('\n✗ DarkMatter fails vectors it should pass. Fix DarkMatter, never the vector.');
  process.exit(1);
}
console.log('\n✓ No vector that DarkMatter attempts is failing.');
console.log('  Skipped vectors are capabilities DarkMatter does not claim, not passes.\n');
