/**
 * Tests the dated X campaigns: when a post is due, and what a post may say.
 *
 * Two different things can go wrong with a campaign and they need different
 * tests.
 *
 * The cadence can go wrong. "One post every other day" is a promise about
 * spacing, and the obvious implementation (post whatever is scheduled for
 * today or earlier) breaks it the first time a run is missed: it catches up
 * by posting on consecutive days. The rule here is that a missed run delays
 * the rest of the campaign instead.
 *
 * The content can go wrong, and for the accord campaign that is the larger
 * risk. DarkMatter did not sign the White House Accord on Super Intelligence,
 * is not endorsed by anyone who did, and does not monitor or stop a model. A
 * post that implied any of those would be false in public, under the name of
 * a product whose whole proposition is that its claims can be checked. So the
 * things these posts must never say are pinned here, by name.
 *
 * Run: node test/campaign.test.js
 */
'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const c      = require('../scripts/x-campaigns.js');

let passed = 0, failed = 0;
function test(label, fn) {
  try { fn(); console.log('  ok    ' + label); passed++; }
  catch (e) { console.error('  FAIL  ' + label + '\n        ' + e.message); failed++; }
}

const hashOf = (t) => crypto.createHash('sha256').update(String(t).trim(), 'utf8').digest('hex');

// Mirror of tweetLength() in scripts/daily-tweet.js: X charges 23 characters
// for any link whatever its real length.
const counted = (text) =>
  text.replace(/(https?:\/\/\S+|\bdarkmatterhub\.ai\S*)/g, 'x'.repeat(23)).length;

// ── Cadence, on a synthetic campaign ─────────────────────────────────────────
console.log('\nCampaign cadence');

const START = '2026-01-10';
const D0 = c.dayNumber(START);
const fake = [{ name: 't', start: START, everyDays: 2, tags: ['#a', '#b', '#c', '#d'], tweets: ['one', 'two', 'three'] }];
const entry = (text, day) => ({ hash: hashOf(text), campaign: 't', dates: [c.isoDate(day)], sources: ['live'] });
const due = (ledger, day) => c.dueCampaignPost(ledger, day, hashOf, fake);

test('nothing is due before the start day', () => {
  assert.strictEqual(due({ posted: [] }, D0 - 1), null);
});

test('the first post is due on the start day', () => {
  const d = due({ posted: [] }, D0);
  assert(d && d.i === 0 && d.text === 'one', 'expected post 1, got ' + JSON.stringify(d));
});

test('nothing is due the day after a post', () => {
  assert.strictEqual(due({ posted: [entry('one', D0)] }, D0 + 1), null);
});

test('the next post is due two days after the last', () => {
  const d = due({ posted: [entry('one', D0)] }, D0 + 2);
  assert(d && d.i === 1, 'expected post 2, got ' + JSON.stringify(d));
});

test('a missed run delays the campaign instead of doubling up', () => {
  // Post 1 went out on time; nothing ran until day 5. Post 2 (scheduled day 2)
  // goes out on day 5. Post 3 was scheduled for day 4, which has passed, but it
  // must wait for day 7: two posts on consecutive days is not the cadence.
  const afterLate = { posted: [entry('one', D0), entry('two', D0 + 5)] };
  assert.strictEqual(due(afterLate, D0 + 6), null, 'post 3 went out the day after post 2');
  const d = due(afterLate, D0 + 7);
  assert(d && d.i === 2, 'post 3 should be due two days after post 2');
});

test('a post already in the ledger is never offered again', () => {
  // Same words posted by some other route, with no campaign field at all.
  const ledger = { posted: [{ hash: hashOf('one'), dates: [c.isoDate(D0 - 30)], sources: ['live'] }] };
  // Post 1 is spent, and post 2 is not scheduled until day 2, so day 0 is quiet.
  assert.strictEqual(due(ledger, D0), null, 'it offered a post that is spent or not yet scheduled');
  assert.strictEqual(due(ledger, D0 + 2).text, 'two');
});

test('a finished campaign is never due', () => {
  const ledger = { posted: [entry('one', D0), entry('two', D0 + 2), entry('three', D0 + 4)] };
  assert.strictEqual(due(ledger, D0 + 40), null);
  assert.strictEqual(c.campaignPostsRemaining(ledger, hashOf, fake), 0);
});

test('tags keep the first and rotate the rest', () => {
  const a = c.campaignTags(fake[0], 0), b = c.campaignTags(fake[0], 1);
  assert.strictEqual(a[0], '#a'); assert.strictEqual(b[0], '#a');
  assert(a.length === 3 && b.length === 3, 'expected three tags each');
  assert.notDeepStrictEqual(a, b, 'consecutive posts carry identical tags');
});

// ── The accord campaign ──────────────────────────────────────────────────────
console.log('\nAccord campaign content');

const accord = c.CAMPAIGNS.find((x) => x.name === 'accord');
const LINK = 'darkmatterhub.ai/go/accord';

test('it is 15 posts, one every other day, inside 30 days', () => {
  assert(accord, 'no campaign named accord');
  assert.strictEqual(accord.tweets.length, 15);
  assert.strictEqual(accord.everyDays, 2);
  const span = c.scheduledDay(accord, 14) - c.scheduledDay(accord, 0);
  assert(span <= 29, 'last post lands ' + span + ' days after the first');
});

test('every post fits, leaves room for tags, and ends on the campaign link', () => {
  accord.tweets.forEach((t, i) => {
    // 250, not 280: the script drops tags until the post fits, and a post
    // written to the full limit would go out with none.
    assert(counted(t) <= 250, 'post ' + (i + 1) + ' is ' + counted(t) + ' before tags; over 250 leaves no room for any');
    const first = c.campaignTags(accord, i)[0];
    assert(counted(t + '\n\n' + first) <= 280, 'post ' + (i + 1) + ' cannot carry even its first tag');
    assert(t.trim().split('\n').pop() === LINK, 'post ' + (i + 1) + ' does not end with ' + LINK);
  });
});

test('no two posts are the same, and none repeats the evergreen bank', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'scripts', 'daily-tweet.js'), 'utf8');
  const m = src.match(/const TWEETS\s*=\s*\[([\s\S]*?)\n\];/);
  let TWEETS; eval('TWEETS = [' + m[1] + '\n];');
  const seen = new Map(TWEETS.map((t, i) => [hashOf(t), 'bank ' + i]));
  accord.tweets.forEach((t, i) => {
    const h = hashOf(t);
    assert(!seen.has(h), 'post ' + (i + 1) + ' is identical to ' + seen.get(h));
    seen.set(h, 'post ' + (i + 1));
  });
});

test('no post claims endorsement, certification or signatory status', () => {
  // "signatory" and "signed" are allowed only where the post is saying we are
  // not one. Everything else on this list has no honest use here at all.
  const NEVER = [
    /\bcertified\b/i, /\bendorsed?\b/i, /\bapproved by\b/i, /\baccord[- ]ready\b/i,
    /\baccord[- ]compliant\b/i, /\bcompliant with\b/i, /\bofficial(ly)?\b/i,
    /\bpartner(ed|ing)? with the\b/i, /\brequired by the accord\b/i, /\bwe signed\b/i,
  ];
  accord.tweets.forEach((t, i) => {
    NEVER.forEach((re) => assert(!re.test(t), 'post ' + (i + 1) + ' matches ' + re));
    if (/\bsignator(y|ies)\b/i.test(t) && /\b(we|darkmatter)\b[^.]*\bsignator/i.test(t)) {
      assert(/\bnot a signatory\b|\bnot signatories\b|\bisn't a signatory\b/i.test(t),
        'post ' + (i + 1) + ' mentions DarkMatter and signatory without saying it is not one');
    }
  });
});

test('no post names a signatory company or a person', () => {
  const NAMES = ['Google', 'Anthropic', 'Meta', 'OpenAI', 'xAI', 'Nvidia', 'Trump', 'Pichai',
                 'Amodei', 'Zuckerberg', 'Brockman', 'Musk', 'Huang', 'President'];
  accord.tweets.forEach((t, i) => {
    NAMES.forEach((n) => assert(!new RegExp('(^|[^A-Za-z])' + n + '([^A-Za-z]|$)').test(t),
      'post ' + (i + 1) + ' names ' + n));
  });
});

test('no post claims to prevent, block or monitor', () => {
  // DarkMatter records what happened and makes tampering detectable. It does
  // not stop a model doing anything, and layer 1 of the accord is about the
  // controls that do.
  accord.tweets.forEach((t, i) => {
    t.split(/(?<=[.?!])\s+|\n+/).forEach((sentence) => {
      if (!/\b(prevents?|blocks?|stops?)\b/i.test(sentence)) return;
      assert(/\b(not|never|cannot|can't|does not|doesn't|do not|don't|nothing)\b/i.test(sentence),
        'post ' + (i + 1) + ' claims prevention: "' + sentence.trim() + '"');
    });
    assert(!/\bwe monitor\b|\bdarkmatter monitors\b/i.test(t), 'post ' + (i + 1) + ' claims monitoring');
  });
});

test('the campaign says out loud that DarkMatter did not sign', () => {
  const n = accord.tweets.filter((t) => /\bnot a signatory\b|\bdid not sign\b|\bdidn't sign\b/i.test(t)).length;
  assert(n >= 1, 'no post states that DarkMatter is not a signatory');
});

test('house style: no em dashes, no exclamation marks', () => {
  accord.tweets.forEach((t, i) => {
    assert(t.indexOf(String.fromCharCode(0x2014)) === -1, 'post ' + (i + 1) + ' has an em dash');
    assert(t.indexOf('!') === -1, 'post ' + (i + 1) + ' has an exclamation mark');
  });
});

console.log('\n  Passed: ' + passed + '  Failed: ' + failed);
if (failed > 0) process.exitCode = 1;
