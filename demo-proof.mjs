#!/usr/bin/env node
/**
 * DarkMatter — proof demo
 *
 * Shows the one thing that matters: an AI agent's decisions are sealed when
 * they happen, and any later alteration is mathematically detectable.
 *
 *   node demo-proof.mjs
 *
 * Runs with no account and no network by default, so anyone evaluating
 * DarkMatter can see the mechanism in about ten seconds.
 *
 * Set DARKMATTER_API_KEY to also commit the same chain to the hosted service
 * and print a shareable verification URL:
 *
 *   DARKMATTER_API_KEY=dm_sk_... node demo-proof.mjs
 */

import { createHash } from 'node:crypto';

const API = process.env.DARKMATTER_API_URL || 'https://darkmatterhub.ai';
const KEY = process.env.DARKMATTER_API_KEY;

// ── presentation ────────────────────────────────────────────────────────────
const c = {
  dim: s => `\x1b[2m${s}\x1b[0m`,
  bold: s => `\x1b[1m${s}\x1b[0m`,
  green: s => `\x1b[32m${s}\x1b[0m`,
  red: s => `\x1b[31m${s}\x1b[0m`,
  cyan: s => `\x1b[36m${s}\x1b[0m`,
  yellow: s => `\x1b[33m${s}\x1b[0m`,
};
const rule = (ch = '─') => c.dim(ch.repeat(68));
const short = h => h.slice(0, 14) + '…';

// ── integrity, per Context Passport v2.0 (RFC 8785 canonicalisation) ────────
// Keys sorted, no whitespace, raw UTF-8. Identical bytes in every conformant
// implementation, which is what makes a record verifiable by someone else.
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort()
    .map(k => JSON.stringify(k) + ':' + canonical(value[k]))
    .join(',') + '}';
}
const sha256 = s => 'sha256:' + createHash('sha256').update(s, 'utf8').digest('hex');
const payloadHash = payload => sha256(canonical(payload));
const integrityHash = (payHash, parent) => sha256(payHash + (parent ?? 'root'));

function seal(payloads) {
  const chain = [];
  let parent = null;
  for (const [i, payload] of payloads.entries()) {
    const ph = payloadHash(payload);
    const ih = integrityHash(ph, parent);
    chain.push({ step: i + 1, payload, payload_hash: ph, parent_hash: parent, integrity_hash: ih });
    parent = ih;
  }
  return chain;
}

/** Recompute every hash from the payloads and compare against what is stored. */
function verify(chain) {
  const results = [];
  let parent = null;
  let broken = false;
  for (const rec of chain) {
    const ph = payloadHash(rec.payload);
    const ih = integrityHash(ph, parent);
    // Once the chain breaks, every later record fails too: each integrity hash
    // is computed over its parent's, so a single edit invalidates the tail.
    const ok = !broken && ph === rec.payload_hash && ih === rec.integrity_hash;
    if (!ok) broken = true;
    results.push({ ...rec, ok, expected_payload_hash: ph, expected_integrity_hash: ih });
    parent = rec.integrity_hash;
  }
  return results;
}

// ── the scenario ────────────────────────────────────────────────────────────
// A loan decision: consequential, regulated, and exactly the kind of thing
// someone disputes six months later.
const STEPS = [
  { label: 'intake',   summary: 'Application received',        payload: { event: 'intake',   applicant: 'A-4471', amount_usd: 45000, credit_score: 720 } },
  { label: 'risk',     summary: 'Risk model scored 0.23 (low)', payload: { event: 'risk',     model: 'risk-v3', score: 0.23, band: 'low' } },
  { label: 'decision', summary: 'APPROVED at 6.4% APR',        payload: { event: 'decision', outcome: 'APPROVED', apr: 6.4, reviewed_by: 'agent-underwriter-01' } },
  { label: 'disburse', summary: 'Funds released',              payload: { event: 'disburse', amount_usd: 45000, method: 'ACH' } },
];

async function main() {
  console.log('');
  console.log(c.bold('  DarkMatter — proof of what an AI agent decided'));
  console.log(rule());
  console.log('');
  console.log('  An AI agent processes a loan application in four steps.');
  console.log('  Each step is sealed at the moment it happens.');
  console.log('');

  const chain = seal(STEPS.map(s => s.payload));

  for (const [i, rec] of chain.entries()) {
    console.log(`   ${c.cyan(`[${rec.step}]`)} ${STEPS[i].label.padEnd(9)} ${STEPS[i].summary}`);
    console.log(`       ${c.dim(short(rec.integrity_hash))}`);
  }

  console.log('');
  console.log(`  ${c.green('Chain sealed.')} ${chain.length} records, each linked to the one before it.`);
  console.log('');

  // ── verification ──────────────────────────────────────────────────────────
  console.log(rule());
  console.log(c.bold('  VERIFICATION'));
  console.log(c.dim('  Recompute every hash from the payloads and compare.'));
  console.log('');
  for (const r of verify(chain)) {
    console.log(`   ${c.green('✓')} record ${r.step}  ${c.dim(short(r.integrity_hash))}  intact`);
  }
  console.log('');
  console.log(`  ${c.green('Chain intact.')} ${chain.length}/${chain.length} records verified.`);
  console.log('');

  // ── tampering ─────────────────────────────────────────────────────────────
  console.log(rule());
  console.log(c.bold('  SIX MONTHS LATER, A DISPUTE'));
  console.log('');
  console.log('  Someone with database access edits the decision record,');
  console.log(`  changing the outcome from ${c.green('APPROVED')} to ${c.red('DENIED')}.`);
  console.log('');

  const tampered = JSON.parse(JSON.stringify(chain));
  tampered[2].payload.outcome = 'DENIED';   // the stored hashes are left untouched

  const results = verify(tampered);
  for (const r of results) {
    if (r.ok) {
      console.log(`   ${c.green('✓')} record ${r.step}  ${c.dim(short(r.integrity_hash))}  intact`);
    } else {
      console.log(`   ${c.red('✗')} record ${r.step}  ${c.red('HASH MISMATCH')}`);
      if (r.expected_payload_hash !== r.payload_hash) {
        console.log(`       ${c.dim('stored')}     ${r.payload_hash}`);
        console.log(`       ${c.dim('recomputed')} ${c.red(r.expected_payload_hash)}`);
      } else {
        console.log(`       ${c.dim('broken by the altered record above it')}`);
      }
    }
  }

  const firstBad = results.find(r => !r.ok);
  console.log('');
  console.log(`  ${c.red('Chain BROKEN')} at record ${firstBad.step}.`);
  console.log('');
  console.log('  Nobody had to be trusted for this. The edit is detectable by');
  console.log('  anyone holding the records, using nothing but SHA-256.');
  console.log('');

  // ── hosted mode ───────────────────────────────────────────────────────────
  console.log(rule());
  if (!KEY) {
    console.log(c.dim('  Ran locally, no account needed.'));
    console.log(c.dim('  Set DARKMATTER_API_KEY to commit this chain to the hosted'));
    console.log(c.dim('  service and get a URL you can hand to an auditor:'));
    console.log('');
    console.log(c.dim('    DARKMATTER_API_KEY=dm_sk_... node demo-proof.mjs'));
    console.log('');
    console.log(`  ${c.cyan('darkmatterhub.ai')} ${c.dim('— free tier, 10,000 records/month')}`);
    console.log('');
    return;
  }

  console.log(c.bold('  COMMITTING TO THE HOSTED SERVICE'));
  console.log('');
  const traceId = `trc_demo_${Date.now()}`;
  let parentId = null;
  for (const [i, step] of STEPS.entries()) {
    const res = await fetch(`${API}/api/commit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', authorization: `Bearer ${KEY}` },
      body: JSON.stringify({
        payload: step.payload,
        eventType: i === 2 ? 'audit' : 'commit',
        traceId,
        parentId,
        // Records are private by default. This demo exists to produce a link
        // you can hand to someone, so it publishes each record explicitly.
        share: true,
      }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      console.log(`   ${c.red('✗')} ${step.label}: ${body.error || res.status}`);
      console.log('');
      console.log(c.dim('  The local proof above is unaffected by this failure.'));
      console.log('');
      return;
    }
    parentId = body.id || body.context?.id || parentId;
    console.log(`   ${c.green('✓')} ${step.label.padEnd(9)} committed  ${c.dim(short(body.integrity?.integrity_hash || ''))}`);
  }
  console.log('');
  console.log(`  ${c.bold('Shareable proof:')} ${c.cyan(`${API}/r/${traceId}`)}`);
  console.log('');
  console.log(c.dim('  That link verifies without a DarkMatter account and without'));
  console.log(c.dim('  trusting us. Send it to an auditor, a regulator, or a counterparty.'));
  console.log('');
}

main().catch(err => {
  console.error(c.red(`\n  demo failed: ${err.message}\n`));
  process.exit(1);
});
