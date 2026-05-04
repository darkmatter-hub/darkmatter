#!/usr/bin/env node
/**
 * DarkMatter daily X post
 * Picks one tweet from the content bank (deterministic by UTC day so the
 * same post never appears twice in a 60-day window) and posts it via the
 * X API v2 free tier.
 *
 * Required env vars (set as GitHub Secrets):
 *   X_API_KEY            – OAuth 1.0a API Key
 *   X_API_SECRET         – OAuth 1.0a API Key Secret
 *   X_ACCESS_TOKEN       – OAuth 1.0a Access Token  (your account)
 *   X_ACCESS_TOKEN_SECRET – OAuth 1.0a Access Token Secret
 */

'use strict';

const https  = require('https');
const crypto = require('crypto');

// ── Content bank ──────────────────────────────────────────────────────────────
// 60 posts, 2-month rotation. Covers: positioning, technical facts,
// use cases, product details, accountability philosophy.
const TWEETS = [
  // Positioning
  `AI agents are making decisions right now that nobody can reconstruct later. DarkMatter fixes that — every action sealed at the moment it happens, verifiable by anyone without trusting us.\n\ndarkmatterhub.ai`,
  `Logs are controlled by whoever runs the system. That's the problem.\n\nDarkMatter stores the record outside your system, cryptographically sealed at commit time. Disputes become facts, not arguments.\n\ndarkmatterhub.ai`,
  `"The AI said so" isn't an answer when a regulator asks what happened.\n\nDarkMatter gives AI agents a black box — an independent record that survives audits, disputes, and failure.\n\ndarkmatterhub.ai`,
  `Aircraft don't rely on the pilot's notes for accident investigation. They have a black box.\n\nAI agents making consequential decisions need the same thing. That's DarkMatter.\n\ndarkmatterhub.ai`,
  `Your AI agent's logs live inside your system. Anyone who controls the system can alter them.\n\nDarkMatter proves what happened — sealed outside, verified independently.\n\ndarkmatterhub.ai`,
  `Accountability for AI doesn't come from better logs. It comes from records that neither you nor your vendor can change after the fact.\n\nDarkMatter: independent, sealed, verifiable.\n\ndarkmatterhub.ai`,

  // Technical — integrity
  `Every DarkMatter commit gets:\n✓ SHA-256 payload hash\n✓ Ed25519 signature (your key, not ours)\n✓ Hash chain linking it to every prior action\n✓ OpenTimestamps anchor to the Bitcoin blockchain\n\nL3 verification. No trust required.\n\ndarkmatterhub.ai`,
  `DarkMatter uses a Merkle hash chain. Each commit includes the hash of the one before it.\n\nTamper with any record and every subsequent hash breaks. The manipulation is mathematically detectable.\n\ndarkmatterhub.ai`,
  `L3 verification in DarkMatter means a third party can check your agent's record with:\n• No DarkMatter account\n• No internet connection\n• No trust in us\n\nJust math.\n\ndarkmatterhub.ai`,
  `OpenTimestamps anchors DarkMatter checkpoints to the Bitcoin blockchain.\n\nThis means the existence of a record at a specific time can be proven independently of DarkMatter — permanently.\n\ndarkmatterhub.ai`,
  `DarkMatter customers hold their own Ed25519 signing keys. We never see them.\n\nThis means even if DarkMatter were compromised, the cryptographic proof that a record is genuine stays with the customer.\n\ndarkmatterhub.ai`,
  `Three verification levels:\n\nL1 – hash chain integrity\nL2 – Ed25519 signature valid\nL3 – OpenTimestamps anchor confirmed\n\nL3 means the record is provable with nothing but math and a Bitcoin node.\n\ndarkmatterhub.ai`,

  // Use cases
  `AI agents that approve loans, flag fraud, or route medical decisions need an immutable trail.\n\nDarkMatter gives every action a signed, timestamped, tamper-evident record. Built for the regulatory questions coming in 2025.\n\ndarkmatterhub.ai`,
  `When your AI agent makes a decision that gets disputed:\n\nWithout DarkMatter: reconstruct from logs you control\nWith DarkMatter: produce a cryptographic proof sealed at the moment it happened\n\nOne of those holds up in an audit.\n\ndarkmatterhub.ai`,
  `Multi-agent systems are especially hard to audit. When Agent A hands off to Agent B, who's accountable?\n\nDarkMatter chains every handoff — signed, sealed, parent-linked. The full trace is always reconstructable.\n\ndarkmatterhub.ai`,
  `Financial services teams building on LLMs: your regulator will ask what the model decided and why.\n\nDarkMatter makes that answerable — a tamper-evident record of every agent action, verifiable without trusting your own logs.\n\ndarkmatterhub.ai`,
  `Healthcare AI decisions need audit trails that outlast the system that generated them.\n\nDarkMatter stores records outside your stack, sealed cryptographically. They survive system migrations, vendor changes, and disputes.\n\ndarkmatterhub.ai`,
  `If you're building AI agents that touch contracts, approvals, or compliance workflows — you need more than logging.\n\nDarkMatter seals every action at commit time. The record can't be altered without detection.\n\ndarkmatterhub.ai`,

  // Product details
  `DarkMatter integrates in 3 lines:\n\nimport darkmatter as dm\ndm.init(api_key="...")\ndm.commit({"decision": "approved", "confidence": 0.94})\n\nThe rest — hashing, signing, chaining, anchoring — happens automatically.\n\ndarkmatterhub.ai`,
  `DarkMatter free plan: 10,000 commits/month, 30-day retention, full L1–L3 verification.\n\nNo credit card. No commitment. The cryptographic guarantees are identical across all plans — scale is the only difference.\n\ndarkmatterhub.ai`,
  `Every DarkMatter commit returns a /r/:id URL — a shareable proof page showing the full verification chain.\n\nSend it to an auditor, a regulator, or a counterparty. They can verify it without any DarkMatter account.\n\ndarkmatterhub.ai`,
  `Python SDK: darkmatter-sdk 1.4.4 (PyPI)\nTypeScript SDK: darkmatter-js 1.4.0 (npm)\nREST API: works from any language\n\nDarkMatter fits into whatever stack your agents run on.\n\ndarkmatterhub.ai`,
  `DarkMatter retention by plan:\nFree: 30 days\nPro: 1 year\nTeams: unlimited\nEnterprise: unlimited\n\nThe record you need for a dispute is the one from 6 months ago. Plan accordingly.\n\ndarkmatterhub.ai`,
  `Context Passport: DarkMatter's format for multi-agent handoffs.\n\nAgent A commits its state. Agent B imports that commit as its starting context. The full chain of custody is cryptographically linked from start to finish.\n\ndarkmatterhub.ai`,

  // Accountability philosophy
  `Trust in AI systems can't come from the AI companies saying "trust us."\n\nIt has to come from math. Cryptographic proofs that work whether you trust DarkMatter or not.\n\ndarkmatterhub.ai`,
  `The EU AI Act, SEC guidance on AI, and emerging state regulations all point in the same direction: AI decisions need audit trails.\n\nDarkMatter is the infrastructure for that — built now, before it's required.\n\ndarkmatterhub.ai`,
  `Independent verification means: a third party can check the record without asking you for anything.\n\nDarkMatter makes that possible by design. The proof is in the math, not in your word.\n\ndarkmatterhub.ai`,
  `Accountability ≠ explainability.\n\nExplainability is "here's why the model decided this." Accountability is "here's proof the model made this specific decision at this specific time, and it hasn't been altered."\n\nDarkMatter does the second one.\n\ndarkmatterhub.ai`,
  `The most important property of a black box isn't what it records.\n\nIt's that nobody — not the pilot, not the airline, not the manufacturer — can alter what it recorded.\n\nDarkMatter works the same way for AI.\n\ndarkmatterhub.ai`,
  `You can't trust AI agents you can't verify. You can't verify agents whose records live inside systems they control.\n\nDarkMatter moves the record outside the system. That's the whole idea.\n\ndarkmatterhub.ai`,

  // Short punchy
  `If your AI agent makes a consequential decision and you can't prove what it decided — that's a liability.\n\nDarkMatter: darkmatterhub.ai`,
  `Signed. Sealed. Unchallengeable.\n\nDarkMatter gives AI agents a record nobody can alter, not even us.\n\ndarkmatterhub.ai`,
  `dm.commit() — one call to create an immutable, verifiable record of anything your AI agent does.\n\nThe rest is math.\n\ndarkmatterhub.ai`,
  `The record lives outside your system and is sealed at the moment of action.\n\nThat's what makes it worth anything.\n\nDarkMatter: darkmatterhub.ai`,
  `DarkMatter proves what happened.\n\ndarkmatterhub.ai`,
  `AI accountability infrastructure. Built for agents making real decisions.\n\nFree to start — darkmatterhub.ai`,

  // Engagement / question format
  `What happens when an AI agent makes the wrong call and nobody can reconstruct what it decided?\n\nThat's the accountability gap DarkMatter was built to close.\n\ndarkmatterhub.ai`,
  `How do you audit an AI agent's decisions if the logs are controlled by the same system that runs the agent?\n\nYou don't. That's why DarkMatter stores the record independently.\n\ndarkmatterhub.ai`,
  `What would it take for a regulator to accept an AI agent's decision as verified?\n\nA cryptographic proof sealed at commit time, anchored to a public blockchain, verifiable without trusting anyone.\n\nThat's L3 on DarkMatter.\n\ndarkmatterhub.ai`,
  `If your AI agents were audited tomorrow, could you prove what each one decided and when?\n\nDarkMatter makes that a yes.\n\ndarkmatterhub.ai`,

  // Differentiation
  `LangSmith traces what happens inside your pipeline.\nDatadog monitors your infrastructure.\n\nDarkMatter proves, to a third party, that a specific AI decision happened — sealed, signed, immutable.\n\nDifferent problem. Different tool.\n\ndarkmatterhub.ai`,
  `Observability tells you what your system did. DarkMatter proves it — to someone who has no reason to trust you.\n\nThat's the gap between monitoring and accountability.\n\ndarkmatterhub.ai`,
  `Logs are for debugging. DarkMatter is for accountability.\n\nOne is internal. One survives a dispute.\n\ndarkmatterhub.ai`,

  // Developer-focused
  `One pip install. Three lines of code. Cryptographic accountability for every AI agent action.\n\npip install darkmatter-sdk\n\ndarkmatterhub.ai`,
  `DarkMatter works with LangChain, LangGraph, Anthropic SDK, OpenAI SDK, CrewAI, and raw REST.\n\nWherever your agents run, the record follows.\n\ndarkmatterhub.ai`,
  `Every DarkMatter record is exportable as a portable proof bundle.\n\nYour data, your keys, your proof. We just run the infrastructure.\n\ndarkmatterhub.ai`,
  `DarkMatter verification works offline.\n\nDownload the proof bundle, run the verifier locally, check the hash chain and signatures with no internet — no DarkMatter server required.\n\ndarkmatterhub.ai`,

  // Milestones / social proof angles
  `Building AI agents that make decisions with real consequences?\n\nStart recording those decisions in a way that survives a dispute.\n\nDarkMatter free plan — 10k commits/month, no card required.\ndarkmatterhub.ai`,
  `The teams that will be ready for AI regulation are the ones building accountability infrastructure now.\n\nDarkMatter: the independent record for AI systems.\n\ndarkmatterhub.ai`,
  `Context is lost at every agent handoff. So is accountability.\n\nDarkMatter Context Passport chains the full custody trail — every agent, every decision, every handoff — in one verifiable record.\n\ndarkmatterhub.ai`,
  `Most AI incident post-mortems fail because the logs were insufficient, altered, or inside systems the company controls.\n\nDarkMatter makes the record independent of everyone, including DarkMatter.\n\ndarkmatterhub.ai`,
  `An AI agent that can't be independently verified is a liability waiting to happen.\n\nDarkMatter seals the record at commit time. The proof is in the math.\n\ndarkmatterhub.ai`,
  `Free tier. No credit card. Full cryptographic integrity.\n\nL1–L3 verification is included on every plan. Scale is the only thing you pay for.\n\nStart at darkmatterhub.ai`,
  `We built DarkMatter so AI agents can be trusted the same way aircraft are — not because you trust the airline, but because the black box is independent.\n\ndarkmatterhub.ai`,
  `The question isn't whether AI will make mistakes. It will.\n\nThe question is whether you'll be able to prove what happened when it does.\n\nDarkMatter: darkmatterhub.ai`,
  `Regulation is coming for AI. The teams that will handle it are the ones with verifiable records, not better excuses.\n\nDarkMatter: darkmatterhub.ai`,
  `One API call creates a tamper-evident, cryptographically signed record of any AI agent action.\n\nThat record can be verified by anyone, anywhere, without trusting DarkMatter.\n\ndarkmatterhub.ai`,
];

// ── Pick today's tweet ────────────────────────────────────────────────────────
// Deterministic by UTC date — same day always picks the same tweet.
// Cycles through the full bank before repeating.
function todaysTweet() {
  const daysSinceEpoch = Math.floor(Date.now() / 86_400_000);
  return TWEETS[daysSinceEpoch % TWEETS.length];
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

  for (const [k, v] of Object.entries(secrets)) {
    if (!v) { console.error(`Missing env var: ${k}`); process.exit(1); }
  }

  const text = todaysTweet();
  console.log('Posting tweet #' + (Math.floor(Date.now() / 86_400_000) % TWEETS.length + 1) + ' of ' + TWEETS.length + ':');
  console.log(text);
  console.log('---');

  try {
    const result = await postTweet(text, secrets);
    console.log('Posted successfully. Tweet ID:', result?.data?.id);
  } catch (err) {
    console.error('Failed to post:', err.message);
    process.exit(1);
  }
})();
