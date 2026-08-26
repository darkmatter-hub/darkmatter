#!/usr/bin/env node
/**
 * Checks the public pages for claims that rot.
 *
 *   node scripts/content-audit.js
 *
 * Exits non-zero if anything is definitely wrong, so CI can block it.
 *
 * Written after "80 days to August 2. Set up takes 15 minutes." sat on
 * /eu-ai-act for weeks. The countdown beside it was dynamic and correct; the
 * heading was typed by hand and had outlived both its number and its date. It
 * was the second stale date claim on that page.
 *
 * The rules are deliberately narrow. A check that flags things needing
 * judgement gets ignored, and an ignored check is worse than none: it looks
 * like coverage while providing none. So anything reported as an error here
 * is something that cannot be correct, and anything needing a human eye is
 * listed separately without failing the run.
 *
 * Comments, scripts and styles are stripped before matching, so a comment
 * explaining a past mistake does not trip the rule about that mistake.
 */

const fs = require('fs');
const path = require('path');

const DIR = path.join(__dirname, '..', 'public');
const now = new Date();

function visibleText(html) {
  return html
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ');
}

const errors = [];
const notices = [];

// Rule 1. A number of days typed into markup.
//
// This is always a defect. Whatever it said was true for at most one day, and
// nothing updates it. The fix is never to correct the number; it is to compute
// it from a date, as the countdown on the same page already did.
const COUNTDOWN = /(\d+)\s+(day|week|month)s?\s+(to|left|until|away|remaining)\b/gi;

// Rule 2. Dates, so a human can scan what the site currently asserts.
const MONTHS = 'January|February|March|April|May|June|July|August|September|October|November|December';
const DATE_PATTERNS = [
  new RegExp(`\\b(${MONTHS})\\s+(\\d{1,2}),\\s*(\\d{4})\\b`, 'g'),
  new RegExp(`\\b(\\d{1,2})\\s+(${MONTHS})\\s+(\\d{4})\\b`, 'g'),
];

// Phrases that put a date in the future. A past date next to one of these is
// the exact failure that shipped.
const FUTURE_WORDS = /\b(applies from|comes into force|deadline|due|starts|begins|from|by|until|before)\b/i;
// Phrases that correctly describe a date already gone.
const PAST_WORDS = /\b(deferred from|originally|previously|since|was|last updated|in force|adopted|published)\b/i;

const files = fs.readdirSync(DIR).filter((f) => f.endsWith('.html')).sort();

for (const file of files) {
  const raw = fs.readFileSync(path.join(DIR, file), 'utf8');
  const text = visibleText(raw);

  for (const m of text.matchAll(COUNTDOWN)) {
    errors.push(`${file}: hardcoded "${m[0].trim()}" in page text. Compute it from a date instead; a typed count is wrong by the next day.`);
  }

  // Copyright year.
  for (const m of text.matchAll(/(?:&copy;|©)\s*(\d{4})/g)) {
    const year = Number(m[1]);
    if (year < now.getUTCFullYear()) {
      errors.push(`${file}: copyright year ${year}, but it is ${now.getUTCFullYear()}.`);
    }
  }

  // Dates in the past, with the surrounding words, for a human to scan.
  for (const pattern of DATE_PATTERNS) {
    for (const m of text.matchAll(pattern)) {
      const parsed = new Date(m[0].replace(/(\d)(st|nd|rd|th)/, '$1'));
      if (isNaN(parsed) || parsed >= now) continue;

      const from = Math.max(0, m.index - 70);
      const context = text.slice(from, m.index + m[0].length + 40).replace(/\s+/g, ' ').trim();

      const framedFuture = FUTURE_WORDS.test(context);
      const framedPast = PAST_WORDS.test(context);

      if (framedFuture && !framedPast) {
        errors.push(`${file}: "${m[0]}" has passed but reads as future.\n      ...${context}...`);
      } else {
        notices.push(`${file}: "${m[0]}" (past) ... ${context.slice(0, 90)}`);
      }
    }
  }
}

console.log(`\n  Audited ${files.length} public pages.\n`);

if (notices.length) {
  console.log('  Past dates on the site, for a human to confirm are still meant:\n');
  [...new Set(notices)].forEach((n) => console.log('    ' + n));
  console.log('');
}

if (errors.length) {
  console.error(`  ${errors.length} problem(s):\n`);
  errors.forEach((e) => console.error('    ' + e));
  console.error('');
  process.exit(1);
}

console.log('  No rotten claims found.\n');
