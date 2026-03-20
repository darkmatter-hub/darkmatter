# 🌑 DarkMatter

> **Git for AI agent context.**
> Agents commit work. Agents verify handoffs. Nothing gets lost. Nothing gets forged.

---

## Live API

DarkMatter is live and ready to use right now — no setup required:

```
https://darkmatter-production.up.railway.app
```

Register your first agent in one command:

```bash
curl -X POST https://darkmatter-production.up.railway.app/api/register \
  -H "Content-Type: application/json" \
  -d '{ "agentName": "My Agent" }'
```

View the live dashboard: **[darkmatter-production.up.railway.app](https://darkmatter-production.up.railway.app)**

---

## The Problem

AI agents are amnesiac and blind by default.

When **Agent X** finishes a task and passes work to **Agent Y**, one of three things happens today:

1. X stuffs context into the next prompt — unverified, unsigned, forgeable
2. X writes to a shared file or database — no proof of who wrote what
3. Context is lost entirely and Y starts from zero

There is no equivalent of `git commit` for agent work. No signed handoff. No tamper detection. No recovery if something breaks mid-pipeline.

**DarkMatter fixes this.**

---

## How It Works

DarkMatter gives AI agents the same primitives developers have had for decades — applied to context instead of code.

| Git | DarkMatter |
|-----|------------|
| `git commit` | Agent checkpoints signed context |
| `git push` | Agent publishes handoff to DarkMatter |
| `git pull` | Receiving agent retrieves verified context |
| `git log` | Full audit trail of every agent action |
| `git blame` | Which agent produced which context |
| `git revert` | Resume from last clean checkpoint after failure |

Every handoff is **cryptographically signed** with the sending agent's private key. The receiving agent **verifies the signature** before consuming any context. Tampered or forged context is rejected automatically.

---

## Quickstart — Use the Hosted API

The fastest way to try DarkMatter — no installation needed.

**Step 1 — Register two agents**

```bash
# Register Agent X
curl -X POST https://darkmatter-production.up.railway.app/api/register \
  -H "Content-Type: application/json" \
  -d '{ "agentName": "Claude Agent X" }'

# Register Agent Y  
curl -X POST https://darkmatter-production.up.railway.app/api/register \
  -H "Content-Type: application/json" \
  -d '{ "agentName": "GPT Agent Y" }'
```

Save the `agentId` and `privateKey` from each response.

**Step 2 — Agent X commits signed context**

```bash
curl -X POST https://darkmatter-production.up.railway.app/api/commit \
  -H "Content-Type: application/json" \
  -d '{
    "fromAgentId": "dm_YOUR_AGENT_X_ID",
    "toAgentId":   "dm_YOUR_AGENT_Y_ID",
    "context":     { "task": "Analysis complete", "findings": "APAC up 34%" },
    "privateKey":  "YOUR_AGENT_X_PRIVATE_KEY"
  }'
```

**Step 3 — Agent Y pulls and verifies**

```bash
curl https://darkmatter-production.up.railway.app/api/pull/dm_YOUR_AGENT_Y_ID
```

Agent Y receives only verified, cryptographically signed context. Tampered packages never appear.

---

## Quickstart — Self Host

> **Full setup guide: [SETUP.md](./SETUP.md)** | **Production deployment: [PRODUCTION.md](./PRODUCTION.md)**

```bash
# 1. Clone and install
git clone https://github.com/bengunvl/darkmatter
cd darkmatter
npm install

# 2. Start the server
npm start

# 3. In a second terminal — run the full demo
node demo.js
```

Open [http://localhost:3000](http://localhost:3000) to see the agent network dashboard.

**DarkMatter never stores your private key.** Signing happens locally. DarkMatter only stores public keys and uses them to verify incoming commits.

---

## Demo Output

```
🌑 DarkMatter — Agent Handoff Demo

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 Step 1: Registering agents...

✅ Registered: Claude Agent X  →  dm_a3f8c2e1b9d04712
✅ Registered: GPT Agent Y     →  dm_7b2d9f4e8a1c3056

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🤖 Step 2: Agent X completes work and commits context...

✅ Commit created: commit_1710234567_x8k2p
   From: Claude Agent X → To: GPT Agent Y
   Signature verified: ✅ YES
   Timestamp: 2026-03-17T14:23:01.000Z

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🤖 Step 3: Agent Y pulls and verifies context...

✅ GPT Agent Y pulled 1 verified commit(s)
   Verified: ✅ Signature valid — safe to consume
   Context: { task: "Analyze Q1 sales data", findings: { topRegion: "APAC"... } }

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 Step 4: Tamper detection...

   Commit verified: ❌ REJECTED (correct)
   Reason: Signature verification failed — context may have been tampered with
   → Agent Y will never see this context.
```

---

## API Reference

**Base URL:** `https://darkmatter-production.up.railway.app`

### Register an agent
```http
POST /api/register
{ "agentName": "Claude Agent X" }
```
Returns `agentId`, `publicKey`, `privateKey`.

---

### Commit context
```http
POST /api/commit
{
  "fromAgentId": "dm_abc123",
  "toAgentId":   "dm_xyz456",
  "context":     { ...any JSON... },
  "privateKey":  "-----BEGIN PRIVATE KEY-----..."
}
```
Signs the context package with the sender's private key and stores a verified commit.

---

### Pull context
```http
GET /api/pull/:agentId
```
Returns all verified commits addressed to this agent. Every commit is re-verified against the sender's public key before being returned. Tampered commits are never returned.

---

### Dashboard data
```http
GET /api/agents    → all registered agents
GET /api/commits   → full commit timeline
```

---

## Architecture

```
Agent X (any model)          DarkMatter              Agent Y (any model)
        │                        │                           │
        │── POST /register ──▶   │                           │
        │◀── agentId + keys ──   │                           │
        │                        │                           │
        │   [does work]          │                           │
        │                        │                           │
        │── POST /commit ──────▶ │  verify signature         │
        │   signed context       │  store commit             │
        │◀── commitId ─────────  │                           │
        │                        │                           │
        │                        │ ◀── GET /pull/:id ────────│
        │                        │     re-verify signature   │
        │                        │──── verified context ────▶│
        │                        │                           │
        │                        │              [resumes work]
```

**Key principle:** DarkMatter never stores private keys. Agents sign locally. DarkMatter verifies against registered public keys. The trust is cryptographic, not operational.

---

## Why Not Just Use Git?

Git is designed for humans committing code asynchronously. Agent networks need:

| Need | Git | DarkMatter |
|------|-----|------------|
| Cryptographic agent identity | ❌ Author is just a string | ✅ Ed25519 keypair per agent |
| Real-time context pull | ❌ Manual pull required | ✅ API call at runtime |
| Tamper/injection detection | ❌ No content verification | ✅ Signature verified before consumption |
| Cross-model handoffs | ❌ Not a concept | ✅ Model-agnostic by design |
| Adversarial context protection | ❌ Trusts all commits | ✅ Rejects unsigned/mismatched context |
| No human in the loop | ❌ Human initiates sessions | ✅ Fully autonomous |

---

## What's Next

- [ ] Agents generate keypairs locally (remove server-side key generation)
- [ ] Failure recovery — resume pipeline from last verified commit
- [ ] Parallel agent branches + merge
- [ ] Agent reputation scoring from commit history
- [ ] Decentralized identity (W3C DIDs) replacing JWT tokens

---

## Philosophy

Most agent memory tools solve the problem from the human's perspective — making AI assistants more useful to the people using them.

DarkMatter solves it from the **agent's perspective** — giving autonomous agents the identity, trust, and context infrastructure they need to work with each other reliably, without a human in the loop.

The agent is the first-class citizen. The infrastructure serves the agent.

---

## License

MIT — build whatever you want with this.

---

*DarkMatter is at the beginning. If you're building multi-agent systems and this resonates, open an issue.*
