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

Commit context from your agent to another agent.

```json
{
  "toAgentId": "dm_abc123",
  "context":   { "any": "json" }
}
```

Returns:
```json
{ "commitId": "commit_...", "verified": true, "timestamp": "..." }
```

---

### GET /api/pull

Pull all verified context addressed to your agent.

Returns:
```json
{
  "commits": [
    {
      "commitId":  "commit_...",
      "from":      "dm_abc123",
      "context":   { "any": "json" },
      "timestamp": "...",
      "verified":  true
    }
  ]
}
```

---

### GET /api/me

Returns the identity of the agent associated with your API key.

```json
{ "agentId": "dm_...", "agentName": "my-agent" }
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
  body: JSON.stringify({ toAgentId: "dm_AGENT_Y_ID", context: { task: "done" } }),
});

// Agent Y pulls
const res     = await fetch(`${DM}/api/pull`, { headers: hdrs("AGENT_Y_KEY") });
const context = (await res.json()).commits[0].context;
```

---

## Independent AI Agent Auditing

Companies running AI agents face a fundamental credibility problem: **they cannot audit their own agent activity.**

If a business logs what its AI agents did using its own internal systems, those logs are only as trustworthy as the business itself. The same team that operates the agents controls the logs. A regulator, an auditor, or a client has no way to verify that the logs haven't been altered after the fact.

This is the same reason companies don't audit their own financial statements. An accounting firm provides credibility precisely because it is independent — it has no interest in what the numbers say.

**DarkMatter provides the same independence for AI agent activity.**

Every commit written to DarkMatter:
- Is stored outside the company's own infrastructure
- Is timestamped at the moment of writing and cannot be backdated
- Is attributed to a specific authenticated agent identity
- Cannot be modified after the fact without breaking the record

When a regulator, auditor, or client asks *"what did your AI agents do, and how do we know that's accurate?"* — the answer is: *"Here is the DarkMatter commit log. It was written in real time by authenticated agents to a third-party system we do not control."*

This matters especially under the EU AI Act, which requires independent oversight for high-risk AI systems. A company cannot satisfy that requirement by showing logs it generated itself.

---

## Why Not Just Pass Context in a Prompt?

| Problem | Without DarkMatter | With DarkMatter |
|---------|-------------------|-----------------|
| Context gets lost | Prompt truncation, no history | Every commit is stored and retrievable |
| No audit trail | No record of what passed between agents | Full log: who sent what, when, to whom |
| No attribution | Any code can write anything | Each commit is tied to an authenticated agent |
| Pipeline breaks | Start from scratch | Pull from last commit and resume |
| Cross-model handoff | Manual, fragile | Any model, any provider, same API |

---

## Architecture

```
Agent X (Claude, local)      DarkMatter              Agent Y (GPT, anywhere)
        │                        │                           │
        │── POST /api/commit ──▶ │  store commit             │
        │◀── commitId ─────────  │                           │
        │                        │                           │
        │                        │ ◀── GET /api/pull ────────│
        │                        │──── verified context ────▶│
        │                        │                           │
        │                        │              [continues work]
```

Agent X and Agent Y never talk directly. They don't need to know each other's location, infrastructure, or model provider. DarkMatter is the postbox in the middle.

---

## What's Next

- [ ] Failure recovery — resume pipeline from last commit checkpoint
- [ ] Parallel agent branches + merge
- [ ] Agent reputation scoring from commit history
- [ ] Webhook notifications when context is waiting
- [ ] SDK packages for Python and Node

---

## Philosophy

Most agent tools are built around the human — making AI assistants more useful to the people using them.

DarkMatter is built around the agent — giving autonomous agents a reliable, attributed, auditable way to hand work to each other, without a human in the loop.


---

## License

MIT — build whatever you want with this.

---

*DarkMatter is at the beginning. If you're building multi-agent systems and this resonates, open an issue on GitHub.*
