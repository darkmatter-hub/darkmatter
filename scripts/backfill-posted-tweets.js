#!/usr/bin/env node
/**
 * Builds scripts/posted-tweets.json, the ledger of tweets that have already
 * gone out. Run once; after that the posting script maintains it.
 *
 *   node scripts/backfill-posted-tweets.js
 *
 * Why a ledger at all. Every version of the scheduler up to now derived which
 * tweet to post from the date, and kept no record of what had actually been
 * sent. That cannot avoid repeats, for three independent reasons:
 *
 *   1. day % 57 wraps after 57 days, so every post from 2026-07-01 onwards
 *      repeated one from 57 days earlier. Around 50 duplicates went out before
 *      anybody noticed.
 *   2. Manual TWEET_INDEX runs bypassed the schedule entirely and left no
 *      trace, so the rotation could not route around them.
 *   3. The irregular scheduler that replaced day % 57 anchored its counter at
 *      2026-08-20 with a count of zero, which restarted the bank at index 0
 *      and reposted tweets 0, 1 and 2 within five days.
 *
 * Deriving history rather than reading it. GitHub only keeps workflow logs for
 * a limited window, so the older posts cannot be read back directly. They can
 * be derived exactly, because the old scheduler was a pure function of the
 * date, `floor(ms / 86400000) % TWEETS.length`, and the tweet bank is
 * byte-identical to what it was then (verified against the Aug 13 commit).
 * The derivation was checked against the one run whose log survives:
 * 2026-08-13 logged "Posting tweet #45 of 57", and day 20678 % 57 = 44, which
 * displays as #45. It matches.
 *
 * Where the two disagree, the log wins. Entries are marked with their source.
 *
 * Dedupe is on a hash of the tweet text, not on its index. An index only means
 * something relative to a particular ordering of the bank, so reordering or
 * editing the array would silently let a previously posted tweet through
 * again. The text is what a reader recognises, so the text is what is tracked.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SCRIPT = path.join(__dirname, 'daily-tweet.js');
const LEDGER = path.join(__dirname, 'posted-tweets.json');

const src = fs.readFileSync(SCRIPT, 'utf8');
const m = src.match(/const TWEETS\s*=\s*\[([\s\S]*?)\n\];/);
if (!m) throw new Error('Could not find the TWEETS array');
let TWEETS;
eval('TWEETS = [' + m[1] + '\n];');

const hash = (t) => crypto.createHash('sha256').update(t.trim(), 'utf8').digest('hex');
const day = (iso) => Math.floor(Date.parse(iso + 'T00:00:00Z') / 86_400_000);
const iso = (d) => new Date(d * 86_400_000).toISOString().slice(0, 10);

// Records keyed by content hash.
const posted = new Map();
function record(index, date, source) {
  const text = TWEETS[index];
  if (text === undefined) return;
  const h = hash(text);
  if (!posted.has(h)) {
    posted.set(h, { hash: h, index_when_recorded: index, dates: [], sources: [] });
  }
  const e = posted.get(h);
  if (!e.dates.includes(date)) e.dates.push(date);
  if (!e.sources.includes(source)) e.sources.push(source);
}

// 1. The day-modulo era. One post a day, index = day % length.
//    Start: first run of the workflow. End: the day before the irregular
//    scheduler shipped.
for (let d = day('2026-05-05'); d <= day('2026-08-19'); d++) {
  record(d % TWEETS.length, iso(d), 'derived:day-modulo');
}

// 2. Manual override runs, read from the workflow logs.
record(2, '2026-08-13', 'log:manual-override');

// 3. The irregular scheduler, read from the workflow logs.
record(0, '2026-08-22', 'log:irregular');
record(1, '2026-08-22', 'log:irregular');
record(2, '2026-08-25', 'log:irregular');

const entries = [...posted.values()].sort((a, b) => a.index_when_recorded - b.index_when_recorded);
entries.forEach((e) => e.dates.sort());

const ledger = {
  note: 'Tweets already posted, keyed by a sha256 of the tweet text. Maintained by scripts/daily-tweet.js; created by scripts/backfill-posted-tweets.js. Never post a tweet whose hash appears here.',
  bank_size_when_written: TWEETS.length,
  posted: entries,
};

fs.writeFileSync(LEDGER, JSON.stringify(ledger, null, 2) + '\n');

const totalPosts = entries.reduce((n, e) => n + e.dates.length, 0);
console.log(`\n  bank size:              ${TWEETS.length}`);
console.log(`  distinct tweets posted: ${entries.length}`);
console.log(`  total posts recorded:   ${totalPosts}`);
console.log(`  duplicates so far:      ${totalPosts - entries.length}`);
console.log(`  never posted:           ${TWEETS.length - entries.length}`);
console.log(`\n  wrote ${path.relative(process.cwd(), LEDGER)}\n`);
