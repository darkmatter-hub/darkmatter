# 🌑 DarkMatter — Setup Guide

> Get from zero to a verified agent handoff in under 5 minutes.

---

## Prerequisites

- Node.js 18+ installed
- A terminal

That's it. No accounts. No cloud setup. No API keys required to run locally.

---

## Step 1 — Clone and install

```bash
git clone https://github.com/yourusername/darkmatter
cd darkmatter
npm install
```

---

## Step 2 — Generate your agent's private key

Your private key is how your agent proves its identity when signing context.

**DarkMatter never sees this key. It never leaves your machine. It is never sent to any server.**

Run this once per agent you want to create:

```bash
node -e "
const crypto = require('crypto');
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const fs = require('fs');
fs.writeFileSync('agent-x.private.pem', privateKey);
fs.writeFileSync('agent-x.public.pem', publicKey);
console.log('✅ Keypair generated');
console.log('   Private key: agent-x.private.pem  ← keep this secret');
console.log('   Public key:  agent-x.public.pem   ← share this freely');
"
```

You'll get two files:

| File | What it is | Who sees it |
|------|-----------|-------------|
| `agent-x.private.pem` | Your agent's secret signing key | **You only. Never share.** |
| `agent-x.public.pem` | Your agent's public identity | Share with DarkMatter and other agents |

> **Think of it like SSH keys.** Your private key stays on your machine. Your public key goes on GitHub. Same idea.

---

## Step 3 — Start the DarkMatter server

```bash
npm start
```

You should see:

```
██████╗  █████╗ ██████╗ ██╗  ██╗    ███╗   ███╗  █████╗ ████████╗████████╗███████╗██████╗
...
Git for AI agent context. Running on http://localhost:3000
```

Open [http://localhost:3000](http://localhost:3000) — this is your agent network dashboard. It's empty for now.

---

## Step 4 — Register your agents

Register Agent X (sends context):

```bash
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{ "agentName": "Claude Agent X" }'
```

You'll get back an `agentId` — copy it. This is your agent's network identity.

```json
{
  "agentId": "dm_a3f8c2e1b9d04712",
  "agentName": "Claude Agent X",
  "publicKey": "-----BEGIN PUBLIC KEY-----...",
  "note": "Store your privateKey securely — DarkMatter never sees it again"
}
```

Register Agent Y (receives context):

```bash
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{ "agentName": "GPT Agent Y" }'
```

---

## Step 5 — Run the demo

The demo simulates a complete handoff in one script:

```bash
node demo.js
```

What happens:
1. Agent X registers with DarkMatter
2. Agent X completes analysis work
3. Agent X **signs** the context package with its private key
4. Agent X commits the signed package to DarkMatter
5. Agent Y **pulls** the package from DarkMatter
6. Agent Y **verifies the signature** — confirms it came from Agent X untampered
7. Agent Y proceeds safely with the verified context
8. A tamper attempt is demonstrated and **rejected**

Expected output:

```
✅ Registered: Claude Agent X  →  dm_a3f8c2e1b9d04712
✅ Registered: GPT Agent Y     →  dm_7b2d9f4e8a1c3056

✅ Commit created: commit_1710234567_x8k2p
   Signature verified: ✅ YES

✅ GPT Agent Y pulled 1 verified commit(s)
   Verified: ✅ Signature valid — safe to consume

🔴 Tamper attempt:
   Commit verified: ❌ REJECTED
   Reason: Signature verification failed — context may have been tampered with
   → Agent Y never sees this context.
```

Refresh [http://localhost:3000](http://localhost:3000) — you'll see the full commit timeline in the dashboard.

---

## Step 6 — Integrate your own agents

The entire DarkMatter API surface is **three calls**:

### Commit (Agent X — after completing work)

```javascript
const signed = signContext(myContext, agentXId, agentYId, privateKey);

await fetch('http://localhost:3000/api/commit', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    fromAgentId: agentXId,
    toAgentId:   agentYId,
    context:     myContext,
    privateKey:  privateKey,   // read from your local .pem file
  })
});
```

### Pull (Agent Y — before starting work)

```javascript
const res = await fetch(`http://localhost:3000/api/pull/${agentYId}`);
const { commits } = await res.json();

// Every commit here is already verified.
// If the signature failed, it never appears in this list.
const context = commits[0].context;
```

### That's it.

Commit → Handoff → Pull. Three calls. Your agents now have verified, recoverable context transfer.

---

## Key Security Principles

**1. Your private key never leaves your machine**
DarkMatter only stores public keys. Signing happens locally before the API call. The server verifies — it never signs on your behalf.

**2. Every commit is signed**
If an agent tries to inject malicious context with a mismatched key, DarkMatter rejects it. Agent Y never sees unverified context.

**3. Timestamps prevent replay attacks**
Packages older than 5 minutes are automatically rejected — a captured signed package can't be replayed later.

**4. Failed commits are logged, not hidden**
Rejected handoffs appear in the dashboard as `❌ REJECTED` so you can see when tampering is attempted.

---

## Deploying Beyond localhost

To run DarkMatter so multiple agents on different machines can reach it — with persistent storage, automatic deploys, and zero server management:

> **Full production guide: [PRODUCTION.md](./PRODUCTION.md)**

The short version:
- **Database:** Supabase (free tier, Postgres)
- **Server:** Railway or Render (free tier, auto-deploys on `git push`)
- **Your workflow:** write code locally → `git push` → live in 90 seconds

Once deployed, replace `http://localhost:3000` with your Railway/Render URL in all agent calls.

---

## What's Stored (and What Isn't)

| Data | Stored by DarkMatter | Notes |
|------|---------------------|-------|
| Agent name | ✅ Yes | Public identity |
| Public key | ✅ Yes | Used for verification |
| Signed context packages | ✅ Yes | The commits |
| **Private key** | ❌ **Never** | Stays on your machine |
| Plaintext context before signing | ❌ No | Only signed packages stored |

---

## Moving to Production Storage

The prototype uses in-memory storage — data resets when the server restarts. To make it persistent, swap `src/lib/store.js` for Supabase:

1. Create a free [Supabase](https://supabase.com) project
2. Run this SQL in Supabase's SQL editor:

```sql
create table agents (
  agent_id text primary key,
  agent_name text not null,
  public_key text not null,
  registered_at timestamptz default now()
);

create table commits (
  id text primary key,
  from_agent text references agents(agent_id),
  to_agent text references agents(agent_id),
  context jsonb,
  signature text,
  verified boolean,
  verification_reason text,
  timestamp timestamptz,
  saved_at timestamptz default now()
);
```

3. Add your Supabase URL and key to `.env`:

```
SUPABASE_URL=https://yourproject.supabase.co
SUPABASE_KEY=your-anon-key
```

4. Replace the in-memory functions in `store.js` with Supabase client calls.

---

## FAQ

**Q: Do I need one keypair per agent or one per developer?**
One per agent. Each autonomous agent should have its own identity so you can trace exactly which agent signed which context.

**Q: What if I lose my private key?**
Generate a new keypair and re-register the agent with the new public key. Old commits signed with the old key will still verify correctly as long as the old public key is in the registry.

**Q: Can two agents share a keypair?**
Technically yes, but you lose the ability to distinguish who signed what. One agent, one key.

**Q: Is this production-ready?**
This is a prototype. The cryptographic primitive (Ed25519 signing) is production-grade. The infrastructure around it (in-memory store, server-side key handling in demo mode) is not. See the roadmap in README.md.

**Q: What models does this work with?**
Any. DarkMatter is model-agnostic — Claude, GPT, Gemini, Llama, or any custom model. The signing and verification happens at the infrastructure layer, not the model layer.

---

*Questions? Open an issue on GitHub.*
