#!/usr/bin/env node
/**
 * Lists every tweet that went out more than once, and when.
 *
 *   node scripts/duplicate-report.js          human-readable
 *   node scripts/duplicate-report.js --json   machine-readable
 *
 * Reads scripts/posted-tweets.json, which records posting dates per tweet.
 * Dates before 2026-08-20 are derived rather than read from logs: the old
 * scheduler was `floor(ms / 86400000) % TWEETS.length`, a pure function of the
 * date, and the bank is byte-identical to the 2026-08-13 commit, so the
 * derivation is exact. It was checked against the one surviving run log
 * (2026-08-13 logged "Posting tweet #45 of 57"; day 20678 % 57 = 44, which
 * displays as #45).
 *
 * GitHub only keeps workflow logs for a limited window, so for the older posts
 * this reconstruction is the only record that exists.
 */

const fs = require('fs');
const path = require('path');

const ledger = JSON.parse(fs.readFileSync(path.join(__dirname, 'posted-tweets.json'), 'utf8'));

const src = fs.readFileSync(path.join(__dirname, 'daily-tweet.js'), 'utf8');
const m = src.match(/const TWEETS\s*=\s*\[([\s\S]*?)\n\];/);
let TWEETS;
eval('TWEETS = [' + m[1] + '\n];');

const crypto = require('crypto');
const hash = (t) => crypto.createHash('sha256').update(String(t).trim(), 'utf8').digest('hex');
const textByHash = new Map(TWEETS.map((t) => [hash(t), t]));

const dupes = ledger.posted
  .filter((e) => e.dates.length > 1)
  .map((e) => ({
    index: e.index_when_recorded,
    times: e.dates.length,
    dates: e.dates.slice().sort(),
    text: textByHash.get(e.hash) || '(text no longer in the bank)',
    hash: e.hash,
  }))
  .sort((a, b) => b.times - a.times || a.index - b.index);

if (process.argv.includes('--json')) {
  console.log(JSON.stringify({ duplicates: dupes }, null, 2));
  process.exit(0);
}

const totalPosts = ledger.posted.reduce((n, e) => n + e.dates.length, 0);
const extra = totalPosts - ledger.posted.length;

console.log('');
console.log(`  ${dupes.length} of ${ledger.posted.length} tweets went out more than once.`);
console.log(`  ${totalPosts} posts in total, so ${extra} of them were repeats.`);
console.log('');

dupes.forEach((d) => {
  const first = d.text.split('\n')[0];
  console.log(`  #${String(d.index).padStart(2)}  posted ${d.times}x   ${d.dates.join('  ')}`);
  console.log(`       ${first.slice(0, 92)}${first.length > 92 ? '...' : ''}`);
  console.log('');
});

console.log(`  Dates from 2026-05-05 to 2026-08-19 are derived from the day-modulo`);
console.log(`  scheduler. Later dates are read from workflow logs.`);
console.log('');
