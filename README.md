# 🌑 DarkMatter

> **Git for AI Agents.**
> The commit, push, and pull layer for multi-agent systems.
> It's how AI agents talk to one another.

---

## The Problem

Every time one AI agent finishes work and needs to pass it to another, developers are left duct-taping solutions together — stuffing context into prompts, writing to files, or hoping nothing gets lost. There is no standard layer for agents to hand off work reliably.

When **Agent X** finishes a task and passes work to **Agent Y**, one of three things happen today:

1. X stuffs context into the next prompt — no record, no attribution, easily lost
2. X writes to a shared file or database — no proof of who wrote what, no history
3. Context is lost entirely and Y starts from zero

There is no equivalent of `git commit` for agent work. No attributed handoff. No audit trail. No recovery if something breaks mid-pipeline.

**DarkMatter fixes this.**

---

## How It Works

DarkMatter gives AI agents the same primitives developers have used for decades — applied to context instead of code.

| Git | DarkMatter | What it does |
|-----|------------|--------------|
| `git commit` | `POST /api/commit` | Agent checkpoints and attributes context |
| `git push` | `POST /api/commit` | Publishes context to the receiving agent |
| `git pull` | `GET /api/pull` | Receiving agent inherits verified context |
| `git revert` | `eventType: revert` | Roll back to a previous checkpoint |
| `git log` | Dashboard | Full audit trail of every handoff |
| `git blame` | API key auth | Which agent committed what |

---

## Live API

DarkMatter is live — no setup required:

```
https://darkmatterhub.ai
```

**[Open Dashboard →](https://darkmatterhub.ai)**

---

## Quickstart

### 1. Sign up and create your agent

Go to the [dashboard](https://darkmatterhub.ai/signup), create a free account, and create an agent. You'll get an API key immediately — no local setup required.

### 2. Commit context (Agent X)

```bash
curl -X POST https://darkmatterhub.ai/api/commit \
  -H "Authorization: Bearer YOUR_AGENT_X_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "toAgentId": "dm_AGENT_Y_ID",
    "eventType": "commit",
    "context":   { "task": "analysis complete", "result": "..." }
  }'
```

### 3. Pull and inherit context (Agent Y)

```bash
curl https://darkmatterhub.ai/api/pull \
  -H "Authorization: Bearer YOUR_AGENT_Y_KEY"
```

### 4. Check your agent identity

```bash
curl https://darkmatterhub.ai/api/me \
  -H "Authorization: Bearer YOUR_KEY"
```

---

## Real-World Example: Claude → GPT Pipeline

See [`examples/claude-to-gpt/`](./examples/claude-to-gpt/) for a complete working example:

- **Agent XX (Claude)** analyzes a topic on your local machine
- Commits its findings to DarkMatter
- **Agent YY (GPT)** pulls the verified context from anywhere
- Continues the work without re-running Claude

```bash
pip install anthropic openai requests

# Step 1: Claude does analysis and commits
python examples/claude-to-gpt/agent_xx.py

# Step 2: GPT pulls and writes summary
python examples/claude-to-gpt/agent_yy.py
```

The full handoff appears in your [dashboard commit log](https://darkmatterhub.ai/dashboard) — you can see exactly what Claude passed to GPT, when, and that it was received.

---

## API Reference

**Base URL:** `https://darkmatterhub.ai`

All endpoints require: `Authorization: Bearer YOUR_API_KEY`

### POST /api/commit

Commit agent state to DarkMatter. Returns a canonical v2 context object.

```json
{
  "toAgentId": "dm_abc123",
  "payload": {
    "input":  "what the agent received",
    "output": "what the agent produced",
    "memory": { "key": "value" },
    "variables": {}
  },
  "eventType": "commit",
  "parentId":  "ctx_previous",
  "traceId":   "trc_run_123",
  "branchKey": "main",
  "agent": {
    "role":     "researcher",
    "provider": "anthropic",
    "model":    "claude-opus-4-6"
  }
}
```

- `payload` is the structured state. Fields: `input`, `output`, `memory`, `artifacts`, `variables`
- `context` (legacy flat JSON) still accepted — stored as `{ output: context }`
- `parentId` links this commit to a previous context, building the lineage graph
- `eventType` defaults to `commit`. See [Event Types](#event-types)
- `traceId` groups commits into a run/trace

Returns a canonical v2 context object:
```json
{
  "id": "ctx_1774358291224_bad9b97648d2",
  "schema_version": "1.0",
  "parent_id": "ctx_previous",
  "trace_id": "trc_run_123",
  "branch_key": "main",
  "created_by": {
    "agent_id": "dm_abc123",
    "agent_name": "my-agent",
    "role": "researcher",
    "provider": "anthropic",
    "model": "claude-opus-4-6"
  },
  "event": {
    "type": "commit",
    "to_agent_id": "dm_xyz789",
    "to_agent_name": "next-agent"
  },
  "payload": {
    "input": "...",
    "output": "...",
    "memory": {}
  },
  "integrity": {
    "payload_hash": "sha256:...",
    "parent_hash": "sha256:...",
    "verification_status": "valid",
    "verified_at": "2026-03-24T..."
  },
  "created_at": "2026-03-24T13:18:11Z"
}
```

If the recipient agent does not exist, returns `integrity.verification_status: "rejected"` and stores the attempt.

---

### GET /api/pull

Pull all verified context addressed to your agent.

Returns:
```json
{
  "agentId":  "dm_...",
  "agentName": "my-agent",
  "commits": [
    {
      "id": "ctx_...",
      "from":      "dm_abc123",
      "context":   { "any": "json" },
      "timestamp": "...",
      "verified":  true
    }
  ],
  "count": 1
}
```

---

### GET /api/me

Returns the identity of the agent associated with your API key.

```json
{ "agentId": "dm_...", "agentName": "my-agent" }
```

---

### GET /api/replay/:contextId

Walk the parent chain from a context ID back to root, returning the full payload at each step in chronological order. Verifies cryptographic integrity at every link.

```json
{
  "contextId": "ctx_...",
  "totalSteps": 3,
  "chainIntact": true,
  "replay": [
    {
      "step": 1,
      "id": "ctx_...",
      "eventType": "commit",
      "createdBy": { "agent_name": "agent-a", "model": "claude-opus-4-6" },
      "payload": { "input": "...", "output": "..." },
      "integrity": { "payload_hash": "sha256:...", "chainValid": true },
      "timestamp": "..."
    }
  ],
  "summary": {
    "agents": ["agent-a", "agent-b", "agent-c"],
    "models": ["claude-opus-4-6", "gpt-4o"],
    "duration": "12s"
  }
}
```

---

---

### POST /api/fork/:contextId

Branch from any checkpoint. Creates a new context node with explicit lineage fields. The original chain is never modified.

**Request body (all optional):**
```json
{
  "fromCheckpoint": "ctx_...",
  "toAgentId":      "dm_...",
  "branchKey":      "experiment-1",
  "agent":          { "role": "researcher", "model": "claude-opus-4-6" }
}
```

**Response:**
```json
{
  "id":           "ctx_...",
  "fork_of":      "ctx_original",
  "fork_point":   "ctx_checkpoint",
  "lineage_root": "ctx_root",
  "branch_key":   "experiment-1",
  "message":      "Forked from ctx_... Continue by committing with parentId: ctx_..."
}
```

Continue the forked branch by including `parentId: fork_response.id` in your next commit.

---

### GET /api/verify/:contextId

Returns a standalone trust object for the chain ending at this context ID.

```json
{
  "ctx_id":       "ctx_...",
  "chain_intact": true,
  "length":       5,
  "lineage_root": "ctx_root",
  "root_hash":    "sha256:...",
  "tip_hash":     "sha256:...",
  "forked":       true,
  "fork_points":  ["ctx_..."],
  "verified_at":  "2026-03-24T..."
}
```

---

### GET /api/export/:contextId

Downloads a portable JSON proof artifact. Safe to share with auditors.

```json
{
  "metadata": {
    "export_version": "1.0",
    "ctx_id":         "ctx_...",
    "lineage_root":   "ctx_root",
    "chain_length":   5,
    "exported_at":    "2026-03-24T..."
  },
  "integrity": {
    "chain_intact":  true,
    "algorithm":     "sha256",
    "root_hash":     "sha256:...",
    "tip_hash":      "sha256:...",
    "chain_hash":    "sha256:..."
  },
  "chain":       [...],
  "export_hash": "sha256:..."
}
```

`chain_hash` is stable across exports of the same unchanged chain. `export_hash` is unique per export instance (includes timestamp).


### POST /dashboard/agents/:id/webhook

Register a webhook URL for an agent. DarkMatter will POST to this URL whenever a verified commit arrives addressed to this agent.

```json
{ "webhookUrl": "https://your-server.com/webhook" }
```

Webhook payload:
```json
{
  "event":     "commit.received",
  "id": "ctx_...",
  "from":      "dm_abc123",
  "to":        "dm_xyz789",
  "eventType": "commit",
  "verified":  true,
  "timestamp": "2026-03-22T..."
}
```

Each webhook request includes an `X-DarkMatter-Signature` header (HMAC-SHA256) if you set a webhook secret in the dashboard.

---

### POST /dashboard/agents/:id/retention

Set a retention policy for an agent's commits. Commits older than the policy are deleted automatically each day.

```json
{ "retentionDays": 182 }
```

- Minimum: `182` days (6 months — EU AI Act Article 19 minimum)
- `null` = keep forever (default, recommended)

---

### GET /api/stats

Returns live network statistics. No auth required.

```json
{ "agents": 6, "commits": 12, "verified": 11, "rejected": 1 }
```

---

## Event Types

Every commit carries an `eventType` that describes what kind of agent action occurred. This enables rich audit trails for both developer debugging and regulatory compliance.

### Developer Workflow

| Event | When to use |
|-------|-------------|
| `commit` | Agent finished work and handed off context — **default** |
| `revert` | Agent rolled back to a previous checkpoint |
| `branch` | Pipeline split into parallel agents |
| `merge` | Parallel branches rejoined |
| `spawn` | Agent dynamically created a child agent |
| `timeout` | Agent hit deadline before completing task |
| `retry` | Agent reattempting a previously failed task |
| `checkpoint` | Mid-task progress save, not a final handoff |
| `error` | Agent failed mid-task, logging last known state |

### Compliance & Human Oversight

| Event | Regulation hook |
|-------|----------------|
| `override` | Human changed agent output — EU AI Act Art. 14 |
| `consent` | Human explicitly approved agent action before execution — EU AI Act Art. 14 |
| `escalate` | Agent paused and flagged for human review — EU AI Act Art. 14 |
| `redact` | PII or sensitive data removed before handoff — EU AI Act Art. 10 / GDPR |
| `audit` | External system or regulator accessed the audit trail |

**Example — logging a human override:**
```bash
curl -X POST https://darkmatterhub.ai/api/commit \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "toAgentId": "dm_NEXT_AGENT",
    "eventType": "override",
    "context": {
      "reason": "human reviewed and corrected output",
      "original": "AI recommendation",
      "correction": "human decision",
      "reviewer": "analyst@company.com"
    }
  }'
```

---

## Python Example

```python
import requests

DM  = "https://darkmatterhub.ai"
X   = {"Authorization": "Bearer AGENT_X_KEY"}
Y   = {"Authorization": "Bearer AGENT_Y_KEY"}

# Agent X commits context for Agent Y
requests.post(f"{DM}/api/commit", headers=X, json={
    "toAgentId": "dm_AGENT_Y_ID",
    "eventType": "commit",
    "context":   {"task": "done", "result": "..."},
})

# Agent Y pulls and inherits
data    = requests.get(f"{DM}/api/pull", headers=Y).json()
context = data["commits"][0]["context"]
```

---

## Node.js Example

```javascript
const DM  = "https://darkmatterhub.ai";
const hdrs = key => ({ "Authorization": `Bearer ${key}`, "Content-Type": "application/json" });

// Agent X commits
await fetch(`${DM}/api/commit`, {
  method: "POST", headers: hdrs("AGENT_X_KEY"),
  body: JSON.stringify({
    toAgentId: "dm_AGENT_Y_ID",
    eventType: "commit",
    context:   { task: "done" }
  }),
});

// Agent Y pulls
const res     = await fetch(`${DM}/api/pull`, { headers: hdrs("AGENT_Y_KEY") });
const context = (await res.json()).commits[0].context;
```

---

## Independent AI Agent Auditing

Companies running AI agents face a fundamental credibility problem: **they cannot credibly audit their own agent activity.**

EU AI Act Articles 12 and 19 (Regulation EU 2024/1689) require high-risk AI systems to produce automatically generated, tamper-evident logs kept for at least six months. But a company storing its own AI logs faces the same credibility problem as auditing its own books — the same team that operates the agents controls the logs.

**DarkMatter provides the independent layer that makes those logs credible to regulators and auditors.**

Every commit written to DarkMatter:
- Is stored outside the company's own infrastructure
- Is timestamped at the moment of writing and cannot be backdated
- Is attributed to a specific authenticated agent identity
- Cannot be modified after the fact without breaking the record
- Captures human oversight actions (`override`, `consent`, `escalate`) required by EU AI Act Art. 14

When a regulator, auditor, or client asks *"what did your AI agents do, and how do we know that's accurate?"* — the answer is: *"Here is the DarkMatter commit log. It was written in real time by authenticated agents to a third-party system we do not control."*

---

## Why Not Just Pass Context in a Prompt?

| Problem | Without DarkMatter | With DarkMatter |
|---------|-------------------|-----------------|
| Context gets lost | Prompt truncation, no history | Every commit is stored and retrievable |
| No audit trail | No record of what passed between agents | Full log: who sent what, when, to whom |
| No attribution | Any code can write anything | Each commit is tied to an authenticated agent |
| Pipeline breaks | Start from scratch | Pull from last commit and resume |
| Cross-model handoff | Manual, fragile | Any model, any provider, same API |
| Compliance logging | Internal logs, unverifiable | Independent, tamper-evident, exportable |

---

## Architecture

```
Agent X (Claude, local)      DarkMatter              Agent Y (GPT, anywhere)
        │                        │                           │
        │── POST /api/commit ──▶ │  store + verify           │
        │◀── commitId ─────────  │                           │
        │                        │                           │
        │                        │ ◀── GET /api/pull ────────│
        │                        │──── verified context ────▶│
        │                        │                           │
        │                        │              [continues work]
```

Agent X and Agent Y never talk directly. They don't need to know each other's location, infrastructure, or model provider. DarkMatter is the postbox in the middle.

---

## Self-Hosting

DarkMatter is open source (MIT) and fully self-hostable. Deploy it inside your own infrastructure and nothing ever leaves your network.

See [PRODUCTION.md](./PRODUCTION.md) for full setup instructions.

**Stack:** Node.js · Supabase (Postgres) · Railway or any Node host · Cloudflare (optional)

---

## What's Next

- [x] Webhook notifications — POST to your URL when a commit arrives
- [x] Retention policies — auto-expire commits with EU AI Act 6-month minimum
- [x] Replay endpoint — full decision path with integrity verification
- [x] Three-agent demo — Claude → GPT → Claude with lineage
- [ ] SDK packages for Python and Node (`dm.commit()`, `dm.pull()`, `dm.replay()`)
- [ ] Fork endpoint — branch from any context
- [x] Fork endpoint — branch from any checkpoint with full lineage fields
- [x] Verify endpoint — standalone cryptographic trust object
- [x] Export endpoint — portable proof artifact with chain_hash
- [x] Chain viewer in dashboard — visual timeline with fork/replay CTAs
- [x] /demo page — live seeded demo chain, no login required
- [x] /blog page — announcement and technical posts
- [x] Branded confirmation email template
- [ ] SDK packages (Python + JS) — dm.commit(), dm.pull(), dm.replay()
- [ ] Compliance PDF export — EU AI Act audit artifact
- [ ] BYOK — Bring Your Own Key encryption

---

## Philosophy

Most agent tools are built around the human — making AI assistants more useful to the people using them.

DarkMatter is built around the agent — giving autonomous agents a reliable, attributed, auditable way to hand work to each other, without a human in the loop.

---

## License

MIT — build whatever you want with this.

---

*DarkMatter is at the beginning. If you're building multi-agent systems and this resonates, open an issue on GitHub or email us at [darkmatterhub.ai](https://darkmatterhub.ai).*
