/**
 * Dated X campaigns.
 *
 * The bank in daily-tweet.js is evergreen and posts on a deliberately uneven
 * schedule. A campaign is the opposite: a fixed run of posts about one thing,
 * in a fixed order, at a fixed cadence, starting on a fixed day. Putting those
 * in the bank would have scattered them across three months in whatever order
 * the ledger happened to reach them.
 *
 * The rules, all of which are here rather than in daily-tweet.js so they can be
 * required and tested without the script's credentials check running:
 *
 *   - Post i is scheduled for start + i * everyDays (UTC days).
 *   - Posts go out strictly in order. The next one is due when its scheduled
 *     day has arrived AND at least everyDays have passed since the previous
 *     campaign post actually went out. So a missed run delays the rest of the
 *     campaign rather than producing two posts in two days to catch up: the
 *     cadence is the promise, not the calendar.
 *   - Nothing goes out twice. Same ledger, same content hash, as the bank.
 */

'use strict';

const CAMPAIGNS = [
  {
    // The White House Accord on Super Intelligence, signed 2026-09-29: a
    // voluntary joint commitment by six frontier companies to four layers of
    // controls and audits. DarkMatter is not a signatory and nothing here may
    // say or imply otherwise; test/campaign.test.js enforces that, along with the
    // other things these posts must never claim.
    name: 'accord',
    start: '2026-09-30',
    everyDays: 2,
    // First tag always, the rest rotate so consecutive posts differ.
    tags: ['#AIgovernance', '#AIsafety', '#AIaudit', '#AIpolicy', '#SuperIntelligence'],
    tweets: [
      `Six frontier companies signed a voluntary accord on 29 September. Four layers: controls, an internal team, an outside assessor, a board committee. Three of the four exist to check that the first works. We are not a signatory.

darkmatterhub.ai/go/accord`,
      `A policy shows a control exists, not that it ran on a given day. Evidence of that is a record written when it fired: the tool called, the arguments, the result. DarkMatter stores what your code sends. It is not the control.

darkmatterhub.ai/go/accord`,
      `The team that runs a control should not be able to revise its log. DarkMatter has no route to edit a record, and a delete request returns 405. A correction is a new record. Deleting the whole account does remove its records.

darkmatterhub.ai/go/accord`,
      `"Remediated" on a slide is an assertion. Evidence is a remediation record that names the issue record as its parent, with the parent's hash folded in. It shows the response was tied to the issue, not that the fix worked.

darkmatterhub.ai/go/accord`,
      `The accord six frontier companies signed is voluntary. It names no standard, evidence format, auditor or deadline. So a vendor can hold no status under it. If a tool claims one, ask which clause. We did not sign it.

darkmatterhub.ai/go/accord`,
      `Independent assessment means not taking evidence on the audited party's word. A screenshot fails that test. A file the assessor can re-hash on their machine answers one question: does the recorded payload match its hashes.

darkmatterhub.ai/go/accord`,
      `A DarkMatter record stores a SHA-256 hash of its payload. If it names a parent, a second hash binds the two. Edit a record in the middle of a linked chain and the offline check fails. The edit is detected, not stopped.

darkmatterhub.ai/go/accord`,
      `A board member is unlikely to install a tool to read one record. A shared DarkMatter record opens in a browser with no account and shows the recorded input, output and hashes, plus a proof file. We write no board report.

darkmatterhub.ai/go/accord`,
      `A hash chain shows the records you were given match their hashes. It cannot show you were given all of them. Cut the last two records off a chain of five and it still verifies. Ask of any evidence which question it answers.

darkmatterhub.ai/go/accord`,
      `A control firing and a person overriding it are two events. Stored as one kind of entry, a reviewer cannot tell them apart. DarkMatter records carry a type such as escalate or override. The caller sets it. It is not hashed.

darkmatterhub.ai/go/accord`,
      `Evidence is stronger when the assessor runs the check. Our offline verifier is one Python file with no dependencies. It recomputes payload hashes and chain links and exits non-zero on a mismatch. It does not check signatures.

darkmatterhub.ai/go/accord`,
      `No independent party co-signs our checkpoints. If we rewrote a record and recomputed hashes from it on, a fresh download would verify. What exposes that is a copy your assessor exported earlier. Keep the file, not the link.

darkmatterhub.ai/go/accord`,
      `A practical step: if the date of an issue matters to your assessor, write it inside the record's payload. Our hash check covers the payload and the parent link. A timestamp or label stored outside the payload is not covered.

darkmatterhub.ai/go/accord`,
      `DarkMatter prevents nothing an agent does. It does not monitor, score, block or stop one. What a record does is make a later edit detectable: change one value in the payload and it no longer matches the hash stored with it.

darkmatterhub.ai/go/accord`,
      `Evidence you cannot test is a claim. Our public sample record downloads as a JSON file with its own verification steps. Run the check. Under passports, change amount 284 to 285 and run it again. It fails. No account needed.

darkmatterhub.ai/go/accord`,
    ],
  },
];

const MS_PER_DAY = 86_400_000;

const dayNumber = (iso) => Math.floor(Date.parse(iso + 'T00:00:00Z') / MS_PER_DAY);
const isoDate   = (day) => new Date(day * MS_PER_DAY).toISOString().slice(0, 10);

const scheduledDay = (campaign, i) => dayNumber(campaign.start) + i * campaign.everyDays;

// The UTC day the most recent post of this campaign actually went out, from
// the ledger, or null if none has.
function lastPostedDay(campaign, ledger) {
  let last = null;
  (ledger.posted || []).forEach((e) => {
    if (e.campaign !== campaign.name) return;
    (e.dates || []).forEach((d) => {
      const n = dayNumber(d);
      if (last === null || n > last) last = n;
    });
  });
  return last;
}

/**
 * The campaign post that should go out on `day`, or null.
 *
 * @param {object}   ledger  parsed posted-tweets.json
 * @param {number}   day     UTC day number
 * @param {function} hashOf  the ledger's content hash
 * @param {object[]} [campaigns]
 */
function dueCampaignPost(ledger, day, hashOf, campaigns = CAMPAIGNS) {
  const seen = new Set((ledger.posted || []).map((e) => e.hash));

  for (const campaign of campaigns) {
    const i = campaign.tweets.findIndex((t) => !seen.has(hashOf(t)));
    if (i === -1) continue;                                  // finished
    if (scheduledDay(campaign, i) > day) continue;           // not yet

    const last = lastPostedDay(campaign, ledger);
    if (last !== null && day - last < campaign.everyDays) continue;   // too soon

    return { campaign, i, text: campaign.tweets[i] };
  }
  return null;
}

// Posts not yet sent, across every campaign.
function campaignPostsRemaining(ledger, hashOf, campaigns = CAMPAIGNS) {
  const seen = new Set((ledger.posted || []).map((e) => e.hash));
  return campaigns.reduce(
    (n, c) => n + c.tweets.filter((t) => !seen.has(hashOf(t))).length, 0);
}

function campaignTags(campaign, i, max = 3) {
  const [first, ...rest] = campaign.tags || [];
  const out = first ? [first] : [];
  for (let k = 0; k < rest.length && out.length < max; k++) {
    out.push(rest[(i + k) % rest.length]);
  }
  return out;
}

module.exports = {
  CAMPAIGNS, dayNumber, isoDate, scheduledDay, lastPostedDay,
  dueCampaignPost, campaignPostsRemaining, campaignTags,
};
