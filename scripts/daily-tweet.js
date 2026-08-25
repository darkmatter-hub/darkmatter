#!/usr/bin/env node
/**
 * DarkMatter daily X post
 * Picks one tweet from the content bank (deterministic by UTC day so the
 * same post never appears twice in a 60-day window) and posts it via the
 * X API v2 free tier.
 *
 * Required env vars (set as GitHub Secrets):
 *   X_API_KEY           , OAuth 1.0a API Key
 *   X_API_SECRET        , OAuth 1.0a API Key Secret
 *   X_ACCESS_TOKEN      , OAuth 1.0a Access Token  (your account)
 *   X_ACCESS_TOKEN_SECRET, OAuth 1.0a Access Token Secret
 */

'use strict';

const https  = require('https');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

// ── Content bank ──────────────────────────────────────────────────────────────
// 60 posts, 2-month rotation. Covers: positioning, technical facts,
// use cases, product details, accountability philosophy.
const TWEETS = [
  // Positioning
  `AI agents are making decisions right now that nobody can reconstruct later. DarkMatter fixes that, every action sealed at the moment it happens, verifiable by anyone without trusting us.\n\ndarkmatterhub.ai/go/x`,
  `Logs are controlled by whoever runs the system. That's the problem.\n\nDarkMatter stores the record outside your system, cryptographically sealed at commit time. Disputes become facts, not arguments.\n\ndarkmatterhub.ai/go/x`,
  `"The AI said so" isn't an answer when a regulator asks what happened.\n\nDarkMatter is a proof engine for AI agents. An independent record that survives audits, disputes, and failure.\n\ndarkmatterhub.ai/go/x`,
  `When an AI agent makes a decision someone disputes later, your application logs are not evidence. They live inside the same system that made the call.\n\nDarkMatter is the independent record.\n\ndarkmatterhub.ai/go/x`,
  `Your AI agent's logs live inside your system. Anyone who controls the system can alter them.\n\nDarkMatter proves what happened, sealed outside, verified independently.\n\ndarkmatterhub.ai/go/x`,
  `Accountability for AI doesn't come from better logs. It comes from records that neither you nor your vendor can change after the fact.\n\nDarkMatter: independent, sealed, verifiable.\n\ndarkmatterhub.ai/go/x`,

  // Technical, integrity
  `Every DarkMatter commit gets:\n✓ SHA-256 payload hash\n✓ Ed25519 signature (your key, not ours)\n✓ Hash chain linking it to every prior action\n✓ OpenTimestamps anchor for independent proof-of-existence\n\nL3 verification. No trust required.\n\ndarkmatterhub.ai/go/x`,
  `DarkMatter uses a Merkle hash chain. Each commit includes the hash of the one before it.\n\nTamper with any record and every subsequent hash breaks. The manipulation is mathematically detectable.\n\ndarkmatterhub.ai/go/x`,
  `L3 verification in DarkMatter means a third party can check your agent's record with:\n• No DarkMatter account\n• No internet connection\n• No trust in us\n\nJust math.\n\ndarkmatterhub.ai/go/x`,
  `OpenTimestamps anchors DarkMatter checkpoints to a public, independently verifiable timestamp.\n\nThis means the existence of a record at a specific time can be proven independently of DarkMatter, permanently.\n\ndarkmatterhub.ai/go/x`,
  `DarkMatter customers hold their own Ed25519 signing keys. We never see them.\n\nThis means even if DarkMatter were compromised, the cryptographic proof that a record is genuine stays with the customer.\n\ndarkmatterhub.ai/go/x`,
  `Three verification levels:\n\nL1, hash chain integrity\nL2, Ed25519 signature valid\nL3, OpenTimestamps anchor confirmed\n\nL3 means the record is provable with nothing but math and a public timestamp anchor.\n\ndarkmatterhub.ai/go/x`,

  // Use cases
  `AI agents that approve loans, flag fraud, or route medical decisions need an immutable trail.\n\nDarkMatter gives every action a signed, timestamped, tamper-evident record. Built for the regulatory questions coming in 2025.\n\ndarkmatterhub.ai/go/x`,
  `When your AI agent makes a decision that gets disputed:\n\nWithout DarkMatter: reconstruct from logs you control\nWith DarkMatter: produce a cryptographic proof sealed at the moment it happened\n\nOne of those holds up in an audit.\n\ndarkmatterhub.ai/go/x`,
  `Multi-agent systems are especially hard to audit. When Agent A hands off to Agent B, who's accountable?\n\nDarkMatter chains every handoff, signed, sealed, parent-linked. The full trace is always reconstructable.\n\ndarkmatterhub.ai/go/x`,
  `Financial services teams building on LLMs: your regulator will ask what the model decided and why.\n\nDarkMatter makes that answerable, a tamper-evident record of every agent action, verifiable without trusting your own logs.\n\ndarkmatterhub.ai/go/x`,
  `Healthcare AI decisions need audit trails that outlast the system that generated them.\n\nDarkMatter stores records outside your stack, sealed cryptographically. They survive system migrations, vendor changes, and disputes.\n\ndarkmatterhub.ai/go/x`,
  `If you're building AI agents that touch contracts, approvals, or compliance workflows, you need more than logging.\n\nDarkMatter seals every action at commit time. The record can't be altered without detection.\n\ndarkmatterhub.ai/go/x`,

  // Product details
  `DarkMatter integrates in 3 lines:\n\nimport darkmatter as dm\ndm.init(api_key="...")\ndm.commit({"decision": "approved", "confidence": 0.94})\n\nThe rest, hashing, signing, chaining, anchoring, happens automatically.\n\ndarkmatterhub.ai/go/x`,
  `DarkMatter free plan: 10,000 commits/month, 30-day retention, full L1,L3 verification.\n\nNo credit card. No commitment. The cryptographic guarantees are identical across all plans, scale is the only difference.\n\ndarkmatterhub.ai/go/x`,
  `Every DarkMatter commit returns a /r/:id URL, a shareable proof page showing the full verification chain.\n\nSend it to an auditor, a regulator, or a counterparty. They can verify it without any DarkMatter account.\n\ndarkmatterhub.ai/go/x`,
  `Python SDK: darkmatter-sdk 1.4.4 (PyPI)\nTypeScript SDK: darkmatter-js 1.4.0 (npm)\nREST API: works from any language\n\nDarkMatter fits into whatever stack your agents run on.\n\ndarkmatterhub.ai/go/x`,
  `DarkMatter retention by plan:\nFree: 30 days\nPro: 1 year\nTeams: unlimited\nEnterprise: unlimited\n\nThe record you need for a dispute is the one from 6 months ago. Plan accordingly.\n\ndarkmatterhub.ai/go/x`,
  `Context Passport: DarkMatter's format for multi-agent handoffs.\n\nAgent A commits its state. Agent B imports that commit as its starting context. The full chain of custody is cryptographically linked from start to finish.\n\ndarkmatterhub.ai/go/x`,

  // Accountability philosophy
  `Trust in AI systems can't come from the AI companies saying "trust us."\n\nIt has to come from math. Cryptographic proofs that work whether you trust DarkMatter or not.\n\ndarkmatterhub.ai/go/x`,
  `The EU AI Act, SEC guidance on AI, and emerging state regulations all point in the same direction: AI decisions need audit trails.\n\nDarkMatter is the infrastructure for that, built now, before it's required.\n\ndarkmatterhub.ai/go/x`,
  `Independent verification means: a third party can check the record without asking you for anything.\n\nDarkMatter makes that possible by design. The proof is in the math, not in your word.\n\ndarkmatterhub.ai/go/x`,
  `Accountability ≠ explainability.\n\nExplainability is "here's why the model decided this." Accountability is "here's proof the model made this specific decision at this specific time, and it hasn't been altered."\n\nDarkMatter does the second one.\n\ndarkmatterhub.ai/go/x`,
  `The most important property of an audit record isn't what it captures.\n\nIt's that nobody (not the operator, not the vendor, not the model provider) can alter what it captured.\n\nDarkMatter is built on that principle.\n\ndarkmatterhub.ai/go/x`,
  `You can't trust AI agents you can't verify. You can't verify agents whose records live inside systems they control.\n\nDarkMatter moves the record outside the system. That's the whole idea.\n\ndarkmatterhub.ai/go/x`,

  // Short punchy
  `If your AI agent makes a consequential decision and you can't prove what it decided, that's a liability.\n\nDarkMatter: darkmatterhub.ai/go/x`,
  `Signed. Sealed. Unchallengeable.\n\nDarkMatter gives AI agents a record nobody can alter, not even us.\n\ndarkmatterhub.ai/go/x`,
  `dm.commit(), one call to create an immutable, verifiable record of anything your AI agent does.\n\nThe rest is math.\n\ndarkmatterhub.ai/go/x`,
  `The record lives outside your system and is sealed at the moment of action.\n\nThat's what makes it worth anything.\n\nDarkMatter: darkmatterhub.ai/go/x`,
  `DarkMatter proves what happened.\n\ndarkmatterhub.ai/go/x`,
  `AI accountability infrastructure. Built for agents making real decisions.\n\nFree to start, darkmatterhub.ai/go/x`,

  // Engagement / question format
  `What happens when an AI agent makes the wrong call and nobody can reconstruct what it decided?\n\nThat's the accountability gap DarkMatter was built to close.\n\ndarkmatterhub.ai/go/x`,
  `How do you audit an AI agent's decisions if the logs are controlled by the same system that runs the agent?\n\nYou don't. That's why DarkMatter stores the record independently.\n\ndarkmatterhub.ai/go/x`,
  `What would it take for a regulator to accept an AI agent's decision as verified?\n\nA cryptographic proof sealed at commit time, anchored to a public blockchain, verifiable without trusting anyone.\n\nThat's L3 on DarkMatter.\n\ndarkmatterhub.ai/go/x`,
  `If your AI agents were audited tomorrow, could you prove what each one decided and when?\n\nDarkMatter makes that a yes.\n\ndarkmatterhub.ai/go/x`,

  // Differentiation
  `LangSmith traces what happens inside your pipeline.\nDatadog monitors your infrastructure.\n\nDarkMatter proves, to a third party, that a specific AI decision happened, sealed, signed, immutable.\n\nDifferent problem. Different tool.\n\ndarkmatterhub.ai/go/x`,
  `Observability tells you what your system did. DarkMatter proves it, to someone who has no reason to trust you.\n\nThat's the gap between monitoring and accountability.\n\ndarkmatterhub.ai/go/x`,
  `Logs are for debugging. DarkMatter is for accountability.\n\nOne is internal. One survives a dispute.\n\ndarkmatterhub.ai/go/x`,

  // Developer-focused
  `One pip install. Three lines of code. Cryptographic accountability for every AI agent action.\n\npip install darkmatter-sdk\n\ndarkmatterhub.ai/go/x`,
  `DarkMatter works with LangChain, LangGraph, Anthropic SDK, OpenAI SDK, CrewAI, and raw REST.\n\nWherever your agents run, the record follows.\n\ndarkmatterhub.ai/go/x`,
  `Every DarkMatter record is exportable as a portable proof bundle.\n\nYour data, your keys, your proof. We just run the infrastructure.\n\ndarkmatterhub.ai/go/x`,
  `DarkMatter verification works offline.\n\nDownload the proof bundle, run the verifier locally, check the hash chain and signatures with no internet, no DarkMatter server required.\n\ndarkmatterhub.ai/go/x`,

  // Milestones / social proof angles
  `Building AI agents that make decisions with real consequences?\n\nStart recording those decisions in a way that survives a dispute.\n\nDarkMatter free plan, 10k commits/month, no card required.\ndarkmatterhub.ai/go/x`,
  `The teams that will be ready for AI regulation are the ones building accountability infrastructure now.\n\nDarkMatter: the independent record for AI systems.\n\ndarkmatterhub.ai/go/x`,
  `Context is lost at every agent handoff. So is accountability.\n\nDarkMatter Context Passport chains the full custody trail, every agent, every decision, every handoff, in one verifiable record.\n\ndarkmatterhub.ai/go/x`,
  `Most AI incident post-mortems fail because the logs were insufficient, altered, or inside systems the company controls.\n\nDarkMatter makes the record independent of everyone, including DarkMatter.\n\ndarkmatterhub.ai/go/x`,
  `An AI agent that can't be independently verified is a liability waiting to happen.\n\nDarkMatter seals the record at commit time. The proof is in the math.\n\ndarkmatterhub.ai/go/x`,
  `Free tier. No credit card. Full cryptographic integrity.\n\nL1,L3 verification is included on every plan. Scale is the only thing you pay for.\n\nStart at darkmatterhub.ai/go/x`,
  `We built DarkMatter so AI agents can be trusted through independent verification, not through trusting the operator or the vendor. The proof is in the math.\n\ndarkmatterhub.ai/go/x`,
  `The question isn't whether AI will make mistakes. It will.\n\nThe question is whether you'll be able to prove what happened when it does.\n\nDarkMatter: darkmatterhub.ai/go/x`,
  `Regulation is coming for AI. The teams that will handle it are the ones with verifiable records, not better excuses.\n\nDarkMatter: darkmatterhub.ai/go/x`,
  `One API call creates a tamper-evident, cryptographically signed record of any AI agent action.\n\nThat record can be verified by anyone, anywhere, without trusting DarkMatter.\n\ndarkmatterhub.ai/go/x`,
];

// ── Hashtags ──────────────────────────────────────────────────────────────────
// Rotating sets, 3 tags per day, chosen deterministically by UTC day. Tags are
// appended only if the result still fits in X's 280-char limit (URLs count as
// 23 chars regardless of length).
const HASHTAG_SETS = [
  ['#AI', '#AIagents', '#AIsafety'],
  ['#AIgovernance', '#LLM', '#AIagents'],
  ['#responsibleAI', '#AIaudit', '#AI'],
  ['#AIcompliance', '#AIagents', '#MLOps'],
  ['#AIsafety', '#AIgovernance', '#LLMs'],
  ['#AI', '#AIaudit', '#EUAIact'],
  ['#AIagents', '#AItransparency', '#LLMOps'],
];

// X counts an auto-linked URL as 23 characters. Substitute any URL with a
// 23-char placeholder before measuring length.
function tweetLength(text) {
  // \S* so a path (darkmatterhub.ai/go/x) is counted as part of the URL. X
  // charges 23 characters for any link regardless of its actual length.
  return text.replace(/(https?:\/\/\S+|\bdarkmatterhub\.ai\S*)/g, 'x'.repeat(23)).length;
}

function withHashtags(text, dayIndex) {
  const tags = [...HASHTAG_SETS[dayIndex % HASHTAG_SETS.length]];
  // Drop trailing tags until the whole post fits in 280 chars.
  while (tags.length && tweetLength(text + '\n\n' + tags.join(' ')) > 280) {
    tags.pop();
  }
  return tags.length ? text + '\n\n' + tags.join(' ') : text;
}

// -- Posted-tweet ledger ------------------------------------------------------
// The schedule decides WHETHER to post. This decides WHAT, and its only rule
// is that nothing goes out twice.
//
// Every earlier version derived the tweet from the date and kept no record of
// what had been sent, which produced repeats three separate ways: day % 57
// wrapped after 57 days, manual TWEET_INDEX runs left no trace for the
// rotation to route around, and the irregular scheduler anchored its counter
// at zero and replayed the bank from the start.
//
// Dedupe is on a hash of the text, not the index. An index only means anything
// relative to one particular ordering of the bank, so reordering or editing the
// array would quietly let a posted tweet through again. Readers recognise the
// words, so the words are what is tracked.

const LEDGER_PATH = path.join(__dirname, 'posted-tweets.json');

const tweetHash = (t) => crypto.createHash('sha256').update(String(t).trim(), 'utf8').digest('hex');

function loadLedger() {
  try {
    const raw = JSON.parse(fs.readFileSync(LEDGER_PATH, 'utf8'));
    return Array.isArray(raw.posted) ? raw : { posted: [] };
  } catch (e) {
    // A missing ledger must not be treated as "nothing has been posted", or the
    // first run after losing the file would repeat the whole bank.
    console.error(`Cannot read ${LEDGER_PATH}: ${e.message}`);
    console.error('Refusing to post without it. Restore the file, or regenerate it with scripts/backfill-posted-tweets.js.');
    process.exit(1);
  }
}

function postedHashes() {
  return new Set(loadLedger().posted.map((e) => e.hash));
}

// The bank has to be sound before anything is chosen from it.
//
// Found by testing: adding a tweet with a stray trailing comma leaves a hole in
// the array, and the selector happily picked the hole and prepared to post the
// literal string "undefined" to X. Editing this array by hand is exactly how new
// tweets get added, so that mistake is likely rather than theoretical.
//
// Duplicate entries are fatal for the same reason the ledger exists. The ledger
// would catch them on the second attempt, but a bank containing the same words
// twice is a mistake worth surfacing at the point it is made.
function validateBank() {
  const problems = [];

  TWEETS.forEach((t, i) => {
    if (typeof t !== 'string' || t.trim() === '') {
      problems.push(`index ${i}: not a non-empty string (${JSON.stringify(t)}). A stray comma leaves a hole here.`);
      return;
    }
    if (tweetLength(t) > 280) {
      problems.push(`index ${i}: ${tweetLength(t)} characters before hashtags, over the 280 limit.`);
    }
  });

  const byHash = new Map();
  TWEETS.forEach((t, i) => {
    if (typeof t !== 'string') return;
    const h = tweetHash(t);
    if (byHash.has(h)) problems.push(`index ${i} is identical to index ${byHash.get(h)}.`);
    else byHash.set(h, i);
  });

  if (problems.length) {
    console.error(`\nThe tweet bank is not usable (${problems.length} problem(s)):\n`);
    problems.forEach((m) => console.error('  ' + m));
    console.error('');
    process.exit(1);
  }
  return true;
}

// The lowest-numbered tweet nobody has seen yet, or null when the bank is used up.
function nextUnpostedIndex() {
  const seen = postedHashes();
  for (let i = 0; i < TWEETS.length; i++) {
    if (!seen.has(tweetHash(TWEETS[i]))) return i;
  }
  return null;
}

function recordPost(index) {
  const ledger = loadLedger();
  const h = tweetHash(TWEETS[index]);
  const today = new Date().toISOString().slice(0, 10);
  let entry = ledger.posted.find((e) => e.hash === h);
  if (!entry) {
    entry = { hash: h, index_when_recorded: index, dates: [], sources: [] };
    ledger.posted.push(entry);
  }
  if (!entry.dates.includes(today)) entry.dates.push(today);
  if (!entry.sources.includes('live')) entry.sources.push('live');
  ledger.bank_size_when_written = TWEETS.length;
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(ledger, null, 2) + '\n');
  console.log(`Recorded in posted-tweets.json (${ledger.posted.length}/${TWEETS.length} of the bank used).`);
}

// ── Irregular posting schedule ────────────────────────────────────────────────
// A post at exactly 24-hour intervals, day after day without a single gap, is
// the most legible bot signature there is. No person posts that way. So the
// cadence here is uneven on purpose: some days carry two posts, some days none,
// and quiet stretches of two or three days are normal.
//
// It is irregular but not random at runtime. Everything below is a pure
// function of the UTC day number, so the three daily workflow runs each reach
// the same conclusion without sharing any state, and the whole future schedule
// can be printed and inspected before it happens (`--schedule`).
//
// Rates: roughly 0.7 posts a day, about 20 a month, with the 57-tweet bank
// cycling in roughly three months rather than every eight weeks.

const SEED = 'darkmatter-x-v1';

// The three times the workflow fires. Keep in sync with the cron entries in
// .github/workflows/daily-tweet.yml. A run posts only if its slot is one the
// schedule chose for today. Times target US engagement windows.
const SLOTS_UTC = [
  { h: 13, m: 15 },   // ~9:15am ET
  { h: 16, m: 45 },   // ~12:45pm ET
  { h: 21, m: 30 },   // ~5:30pm ET
];

// All orderings of the three slots. Drawing one of these with a single random
// value gives each slot an equal chance of being used, which sorting three
// independently hashed keys did not.
const SLOT_PERMUTATIONS = [
  [0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0],
];

// Ceiling on silence. Irregular is the goal; abandoned is not. Without this,
// an unlucky run of the dice produces week-long gaps that read as a dead
// account rather than a human one.
const MAX_SILENT_DAYS = 4;

// UTC day number when the irregular schedule started. Used only to count how
// many posts have gone out, so each one draws the next tweet in the bank.
// 20685 = 2026-08-20.
const ANCHOR_DAY = 20685;

const utcDay = (ms = Date.now()) => Math.floor(ms / 86_400_000);

// FNV-1a. Not cryptographic, and does not need to be: this only has to spread
// consecutive day numbers into unrelated-looking values.
function hash32(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

const rand = (day, salt) => hash32(`${SEED}:${day}:${salt}`) / 0x1_0000_0000;

// How many posts a day would carry before the anti-silence rule is applied.
function rawPostsOnDay(day) {
  const r = rand(day, 'count');
  if (r < 0.44) return 0;   // silent
  if (r < 0.86) return 1;
  return 2;                 // occasional double
}

// Posts on a given day, with the silence ceiling enforced. Replays a short
// window so the rule can see how long it has been quiet without needing any
// stored state.
function postsOnDay(day) {
  const n = rawPostsOnDay(day);
  if (n > 0) return n;

  // Length of the run of consecutive dice-silent days ending here.
  let run = 0;
  while (run < 60 && rawPostsOnDay(day - run) === 0) run++;

  // Break the silence on every (MAX_SILENT_DAYS + 1)th day of a dry run. That
  // caps a gap at exactly MAX_SILENT_DAYS without turning a long dry run into
  // a post every single day, which is what a naive "was it quiet recently?"
  // check does once the run is longer than the lookback.
  return run % (MAX_SILENT_DAYS + 1) === 0 ? 1 : 0;
}

// Which of the three slots today's posts occupy. Two-post days get two
// different slots, so the posts are hours apart rather than adjacent.
function slotsForDay(day) {
  const n = postsOnDay(day);
  if (n === 0) return [];
  const perm = SLOT_PERMUTATIONS[Math.floor(rand(day, 'perm') * SLOT_PERMUTATIONS.length)];
  return perm.slice(0, n).sort((a, b) => a - b);
}

// Which slot the current run belongs to, tolerating GitHub's cron jitter.
function currentSlot(now = new Date()) {
  const nowMin = now.getUTCHours() * 60 + now.getUTCMinutes();
  let best = Infinity;
  let slot = 0;
  SLOTS_UTC.forEach((s, i) => {
    const d = Math.abs(s.h * 60 + s.m - nowMin);
    if (d < best) { best = d; slot = i; }
  });
  return slot;
}

// Total posts before today, so each post draws the next tweet rather than
// repeating the same one twice on a double day.
function postsBefore(day) {
  let count = 0;
  for (let d = ANCHOR_DAY; d < day; d++) count += postsOnDay(d);
  return count;
}

// What this run should do. The schedule decides whether it is this run's turn;
// the ledger decides which tweet, and refuses to repeat one.
//
// Returns { skip: true } to stay quiet, { exhausted: true } when every tweet
// has been used, or { index } to post.
function planThisRun() {
  const day = utcDay();

  if (process.env.FORCE_POST !== 'true') {
    const todays = slotsForDay(day);
    const slot = currentSlot();
    if (todays.indexOf(slot) === -1) {
      const label = todays.length
        ? `today posts at slot(s) ${todays.join(', ')}`
        : 'today is a quiet day';
      console.log(`This run is slot ${slot}; ${label}. Skipping.`);
      return { skip: true };
    }
  }

  const index = nextUnpostedIndex();
  if (index === null) return { exhausted: true };
  return { index };
}

// Prints the upcoming cadence so it can be eyeballed before it happens:
//   node scripts/daily-tweet.js --schedule 60
function printSchedule(days = 45) {
  const start = utcDay();
  const time = (i) => `${String(SLOTS_UTC[i].h).padStart(2, '0')}:${String(SLOTS_UTC[i].m).padStart(2, '0')}`;
  let total = 0;
  let gap = 0;
  let longestGap = 0;

  console.log(`\n  Next ${days} days (UTC). ${TWEETS.length} tweets in the bank.\n`);
  for (let d = start; d < start + days; d++) {
    const slots = slotsForDay(d);
    const date = new Date(d * 86_400_000).toISOString().slice(0, 10);
    const dow = new Date(d * 86_400_000).toUTCString().slice(0, 3);
    if (slots.length === 0) {
      gap++;
      longestGap = Math.max(longestGap, gap);
      console.log(`  ${date} ${dow}   -`);
    } else {
      gap = 0;
      total += slots.length;
      const at = slots.map(time).join('  ');
      console.log(`  ${date} ${dow}   ${slots.length} post${slots.length > 1 ? 's' : ''}  ${at}`);
    }
  }
  console.log(`\n  ${total} posts over ${days} days (${(total / days).toFixed(2)}/day, ~${Math.round((total / days) * 30)}/month)`);
  console.log(`  longest silent stretch: ${longestGap} day(s)`);

  const remaining = TWEETS.length - loadLedger().posted.length;
  console.log(`  unposted tweets left:   ${remaining} of ${TWEETS.length}`);
  if (remaining === 0) {
    console.log('  the bank is used up; nothing will post until new tweets are added');
  } else if (total > remaining) {
    console.log(`  at this rate the bank runs out inside these ${days} days`);
  }
  console.log('');
}

// ── OAuth 1.0a signing ────────────────────────────────────────────────────────
function oauthSign(method, url, params, secrets) {
  const nonce    = crypto.randomBytes(16).toString('hex');
  const ts       = Math.floor(Date.now() / 1000).toString();
  const oaParams = {
    oauth_consumer_key:     secrets.apiKey,
    oauth_nonce:            nonce,
    oauth_signature_method: 'HMAC-SHA1',
    oauth_timestamp:        ts,
    oauth_token:            secrets.accessToken,
    oauth_version:          '1.0',
  };
  const allParams = { ...params, ...oaParams };
  const paramStr  = Object.keys(allParams).sort()
    .map(k => encodeURIComponent(k) + '=' + encodeURIComponent(allParams[k]))
    .join('&');
  const base   = method.toUpperCase() + '&' + encodeURIComponent(url) + '&' + encodeURIComponent(paramStr);
  const sigKey = encodeURIComponent(secrets.apiSecret) + '&' + encodeURIComponent(secrets.accessTokenSecret);
  const sig    = crypto.createHmac('sha1', sigKey).update(base).digest('base64');
  oaParams.oauth_signature = sig;
  const header = 'OAuth ' + Object.keys(oaParams).sort()
    .map(k => encodeURIComponent(k) + '="' + encodeURIComponent(oaParams[k]) + '"')
    .join(', ');
  return header;
}

// ── Post to X ─────────────────────────────────────────────────────────────────
async function postTweet(text, secrets) {
  const url  = 'https://api.twitter.com/2/tweets';
  const body = JSON.stringify({ text });
  const auth = oauthSign('POST', url, {}, secrets);

  return new Promise((resolve, reject) => {
    const req = https.request(url, {
      method:  'POST',
      headers: {
        'Authorization': auth,
        'Content-Type':  'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(JSON.parse(data));
        } else {
          reject(new Error(`X API ${res.statusCode}: ${data}`));
        }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ── Main ──────────────────────────────────────────────────────────────────────
(async () => {
  const secrets = {
    apiKey:             process.env.X_API_KEY,
    apiSecret:          process.env.X_API_SECRET,
    accessToken:        process.env.X_ACCESS_TOKEN,
    accessTokenSecret:  process.env.X_ACCESS_TOKEN_SECRET,
  };

  // Preview the upcoming cadence. Deliberately before the credential check,
  // since inspecting the schedule should not require X secrets:
  //   node scripts/daily-tweet.js --schedule 60
  // Validate the bank without needing credentials:
  //   node scripts/daily-tweet.js --check
  if (process.argv.includes('--check')) {
    validateBank();
    const remaining = TWEETS.length - loadLedger().posted.length;
    console.log(`Bank OK: ${TWEETS.length} tweets, no holes, no duplicates. ${remaining} unposted.`);
    process.exit(0);
  }

  const scheduleArg = process.argv.indexOf('--schedule');
  if (scheduleArg !== -1) {
    printSchedule(Number(process.argv[scheduleArg + 1]) || 45);
    process.exit(0);
  }

  for (const [k, v] of Object.entries(secrets)) {
    if (!v) { console.error(`Missing env var: ${k}`); process.exit(1); }
  }

  // Before anything is selected, including a manual override.
  validateBank();

  // Manual override: post a specific tweet by index (0-based). Set via the
  // workflow_dispatch `tweet_index` input. When present, it bypasses the
  // schedule entirely so you can post a chosen tweet on demand.
  const override = process.env.TWEET_INDEX;
  let index;
  if (override !== undefined && override !== '') {
    const n = Number(override);
    if (!Number.isInteger(n) || n < 0 || n >= TWEETS.length) {
      console.error(`TWEET_INDEX must be an integer 0..${TWEETS.length - 1}; got "${override}"`);
      process.exit(1);
    }
    index = n;
    if (postedHashes().has(tweetHash(TWEETS[index])) && process.env.ALLOW_REPOST !== 'true') {
      console.error(`Tweet index ${index} has already been posted. Refusing.`);
      console.error('A manual override is exactly how the first duplicate got out: it bypassed');
      console.error('the rotation and left no record, so later runs could not route around it.');
      console.error('Set ALLOW_REPOST=true if you genuinely intend to post it again.');
      process.exit(1);
    }
    console.log(`Manual override: posting tweet index ${index}.`);
  } else {
    // The schedule decides whether this run posts at all. Most runs do not.
    const plan = planThisRun();
    if (plan.skip) process.exit(0);
    if (plan.exhausted) {
      console.error('');
      console.error(`Every one of the ${TWEETS.length} tweets in the bank has already been posted.`);
      console.error('Refusing to repeat one. Add new entries to TWEETS in scripts/daily-tweet.js');
      console.error('and posting resumes on the next scheduled slot.');
      console.error('');
      // Non-zero so GitHub emails the owner. Running out of things to say is a
      // decision for a person, and silently recycling old posts is not it.
      process.exit(1);
    }
    index = plan.index;
  }

  const text = withHashtags(TWEETS[index], index);
  console.log('Posting tweet #' + (index + 1) + ' of ' + TWEETS.length + ` (${tweetLength(text)}/280 chars):`);
  console.log(text);
  console.log('---');

  try {
    const result = await postTweet(text, secrets);
    console.log('Posted successfully. Tweet ID:', result?.data?.id);
    // Only after X confirms. Recording before would mean a failed post burned
    // a tweet that never actually went out.
    recordPost(index);
  } catch (err) {
    console.error('Failed to post:', err.message);
    process.exit(1);
  }
})();
