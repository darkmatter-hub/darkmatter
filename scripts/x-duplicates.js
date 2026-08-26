#!/usr/bin/env node
/**
 * Finds tweets that were posted more than once on the DarkMatter account, and
 * optionally deletes the later copies.
 *
 *   node scripts/x-duplicates.js            list only, changes nothing
 *   node scripts/x-duplicates.js --delete   delete the later copies
 *
 * Needs X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET. Those
 * live only in GitHub secrets, so this runs from the workflow rather than a
 * laptop.
 *
 * Safety, because deleting a tweet cannot be undone:
 *
 *   - Listing is the default. Deleting takes an explicit --delete.
 *   - Only exact duplicates are ever touched: two tweets on this account whose
 *     text matches after the trailing hashtag block is removed.
 *   - The earliest copy of each is always kept. Only later copies go.
 *   - Anything that does not match another tweet on the account is left alone,
 *     including tweets that were never in the bank.
 *
 * Hashtags are stripped before comparing because withHashtags() rotates them
 * by day, so the same tweet posted twice carries different tags and would
 * otherwise look like two different posts. A reader recognises the sentence,
 * not the tags.
 */

const https = require('https');
const crypto = require('crypto');

const DELETE = process.argv.includes('--delete');

const secrets = {
  apiKey: process.env.X_API_KEY,
  apiSecret: process.env.X_API_SECRET,
  accessToken: process.env.X_ACCESS_TOKEN,
  accessTokenSecret: process.env.X_ACCESS_TOKEN_SECRET,
};
for (const [k, v] of Object.entries(secrets)) {
  if (!v) { console.error(`Missing env var for ${k}`); process.exit(1); }
}

// ---------------------------------------------------------------- OAuth 1.0a

function pct(s) {
  return encodeURIComponent(s).replace(/[!*()']/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function oauthHeader(method, url, queryParams = {}) {
  const oauth = {
    oauth_consumer_key: secrets.apiKey,
    oauth_nonce: crypto.randomBytes(16).toString('hex'),
    oauth_signature_method: 'HMAC-SHA1',
    oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
    oauth_token: secrets.accessToken,
    oauth_version: '1.0',
  };
  // The signature base must include query parameters as well as the oauth ones.
  const all = { ...oauth, ...queryParams };
  const paramString = Object.keys(all).sort().map((k) => `${pct(k)}=${pct(all[k])}`).join('&');
  const base = [method.toUpperCase(), pct(url), pct(paramString)].join('&');
  const key = `${pct(secrets.apiSecret)}&${pct(secrets.accessTokenSecret)}`;
  oauth.oauth_signature = crypto.createHmac('sha1', key).update(base).digest('base64');
  return 'OAuth ' + Object.keys(oauth).sort().map((k) => `${pct(k)}="${pct(oauth[k])}"`).join(', ');
}

function request(method, urlNoQuery, queryParams = {}) {
  return new Promise((resolve, reject) => {
    const qs = Object.keys(queryParams).sort().map((k) => `${pct(k)}=${pct(queryParams[k])}`).join('&');
    const full = qs ? `${urlNoQuery}?${qs}` : urlNoQuery;
    const u = new URL(full);
    const req = https.request(
      { hostname: u.hostname, path: u.pathname + u.search, method,
        headers: { Authorization: oauthHeader(method, urlNoQuery, queryParams), 'Content-Type': 'application/json' } },
      (res) => {
        let body = '';
        res.on('data', (d) => (body += d));
        res.on('end', () => {
          let parsed = null;
          try { parsed = JSON.parse(body); } catch (_) {}
          resolve({ status: res.statusCode, body: parsed, raw: body });
        });
      });
    req.on('error', reject);
    req.end();
  });
}

// Strip the trailing hashtag block that withHashtags() appends.
function normalise(text) {
  return String(text)
    .replace(/\s*(?:^|\n)(?:#[A-Za-z0-9_]+\s*)+$/g, '')
    .replace(/https:\/\/t\.co\/\S+/g, '')
    .trim();
}

(async () => {
  const me = await request('GET', 'https://api.x.com/2/users/me');
  if (me.status !== 200) {
    console.error(`\nCannot read the account (HTTP ${me.status}).`);
    console.error(me.raw.slice(0, 400));
    console.error('\nReading your own timeline needs a paid X API tier. Posting works on the');
    console.error('free tier, reading and deleting generally do not. If this is the blocker,');
    console.error('the duplicates have to be removed by hand from the X web interface.\n');
    process.exit(2);
  }
  const userId = me.body.data.id;
  const handle = me.body.data.username;
  console.log(`\n  Account: @${handle} (${userId})`);

  // Page through the timeline.
  const tweets = [];
  let token;
  for (let page = 0; page < 20; page++) {
    const params = { max_results: '100', 'tweet.fields': 'created_at,text' };
    if (token) params.pagination_token = token;
    const res = await request('GET', `https://api.x.com/2/users/${userId}/tweets`, params);
    if (res.status !== 200) {
      console.error(`\n  Timeline read failed (HTTP ${res.status}): ${res.raw.slice(0, 300)}`);
      if (tweets.length === 0) process.exit(2);
      break;
    }
    (res.body.data || []).forEach((t) => tweets.push(t));
    token = res.body.meta && res.body.meta.next_token;
    if (!token) break;
  }
  console.log(`  Retrieved ${tweets.length} tweets.\n`);

  // Group by normalised text, oldest first.
  const groups = new Map();
  tweets
    .slice()
    .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
    .forEach((t) => {
      const k = normalise(t.text);
      if (!k) return;
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(t);
    });

  const dupeGroups = [...groups.entries()].filter(([, list]) => list.length > 1);
  if (dupeGroups.length === 0) {
    console.log('  No duplicates found on the timeline.\n');
    process.exit(0);
  }

  const toDelete = [];
  console.log(`  ${dupeGroups.length} tweet(s) appear more than once:\n`);
  dupeGroups.forEach(([text, list]) => {
    console.log(`  "${text.split('\n')[0].slice(0, 80)}"`);
    list.forEach((t, i) => {
      const when = t.created_at ? t.created_at.slice(0, 10) : '(no date)';
      if (i === 0) {
        console.log(`     keep    ${when}  ${t.id}`);
      } else {
        console.log(`     DELETE  ${when}  ${t.id}`);
        toDelete.push(t);
      }
    });
    console.log('');
  });

  console.log(`  ${toDelete.length} tweet(s) would be deleted; ${dupeGroups.length} original(s) kept.\n`);

  if (!DELETE) {
    console.log('  Listing only. Re-run with --delete to remove the later copies.\n');
    process.exit(0);
  }

  let ok = 0;
  let failed = 0;
  for (const t of toDelete) {
    const res = await request('DELETE', `https://api.x.com/2/tweets/${t.id}`);
    if (res.status === 200 && res.body && res.body.data && res.body.data.deleted) {
      console.log(`  deleted ${t.id}`);
      ok++;
    } else {
      console.error(`  FAILED  ${t.id}  HTTP ${res.status}  ${res.raw.slice(0, 160)}`);
      failed++;
    }
  }
  console.log(`\n  Deleted ${ok}, failed ${failed}.\n`);
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error('Unexpected error:', e.message);
  process.exit(1);
});
