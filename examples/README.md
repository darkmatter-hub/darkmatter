# DarkMatter — Three-Agent Killer Demo

The complete DarkMatter value proposition in one runnable script.

## What it does

```
Agent A (Claude)  →  researches a topic          →  ctx_abc  (root)
Agent B (GPT-4o)  →  pulls ctx_abc, writes draft  →  ctx_def  (parent: ctx_abc)
Agent C (Claude)  →  pulls ctx_def, reviews       →  ctx_ghi  (parent: ctx_def)

GET /api/replay/ctx_ghi
→ full 3-step decision chain
→ each payload
→ cryptographic integrity verified root → tip
```

## What this proves

- Context survives model boundaries (Claude → GPT → Claude)
- Every decision is **immutable** and attributed to a specific agent + model
- The full lineage is **replayable** — inputs, outputs, reasoning at every step
- Chain integrity is **cryptographically verified** — tampering breaks the hash chain
- **"Send me the context ID"** = pass `ctx_ghi` to any agent, they inherit the whole story

## Setup

**1. Install dependencies**
```bash
pip install anthropic openai requests
```

**2. Create three agents in your DarkMatter dashboard**

Go to [darkmatterhub.ai/dashboard](https://darkmatterhub.ai/dashboard), create:
- `agent-a` (researcher)
- `agent-b` (writer)
- `agent-c` (reviewer)

**3. Set environment variables**
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export AGENT_A_KEY="dm_sk_..."   # agent-a API key
export AGENT_B_KEY="dm_sk_..."   # agent-b API key
export AGENT_C_KEY="dm_sk_..."   # agent-c API key
export AGENT_B_ID="dm_..."       # agent-b's agent ID
export AGENT_C_ID="dm_..."       # agent-c's agent ID
```

**4. Run**
```bash
python demo.py
```

## Expected output

```
🌑  DarkMatter — Three-Agent Demo
    Topic    : The business case for AI agent infrastructure in 2026
    Trace ID : trc_1774358291_bad9b976

══════════════════════════════════════════════════════════════
  STEP 1 / 3 — Agent A (Claude) — Researcher
══════════════════════════════════════════════════════════════
  Running Claude analysis...
  ✓ Analysis complete  (312 chars)

  Committing to DarkMatter...
  Context ID  : ctx_1774358291224_bad9b97648d2
  Schema      : v1.0
  Hash        : sha256:e7733904f7e156cc···
  Status      : ✓ valid

══════════════════════════════════════════════════════════════
  STEP 2 / 3 — Agent B (GPT-4o) — Writer
══════════════════════════════════════════════════════════════
  Pulling context from DarkMatter...
  ✓ Inherited context : ctx_1774358291224_bad9b97648d2
  ...

══════════════════════════════════════════════════════════════
  REPLAY — Full Decision Path
══════════════════════════════════════════════════════════════
  Total steps   : 3
  Chain intact  : ✓ YES — cryptographically verified
  Agents        : agent-a, agent-b, agent-c
  Models        : claude-opus-4-6, gpt-4o, claude-opus-4-6

  Decision path (root → tip):
    ✓ Step 1 [commit]      agent-a (claude-opus-4-6)
         → 1. Multi-agent systems are exploding...
    ✓ Step 2 [commit]      agent-b (gpt-4o)
         → AI infrastructure is no longer optional...
    ✓ Step 3 [checkpoint]  agent-c (claude-opus-4-6)
         → Score: 8/10. Strength: clear executive framing...

══════════════════════════════════════════════════════════════
  DONE
══════════════════════════════════════════════════════════════
  Context ID (shareable):  ctx_1774358295019_f3a1b2c4d5e6
  Chain intact:            verified

  Pass this context ID to any agent to inherit the full chain:
  dm.pull("ctx_1774358295019_f3a1b2c4d5e6")

  Replay via API:
  curl https://darkmatterhub.ai/api/replay/ctx_1774358295019_f3a1b2c4d5e6 \
       -H 'Authorization: Bearer YOUR_KEY'
```

## The Stripe Moment

When developers naturally say **"send me the context ID"** — they mean a DarkMatter context ID.

The recipient agent calls `dm.pull(ctx_id)` and inherits the entire decision chain: what was researched, what was written, what was reviewed, which models were involved, and cryptographic proof that nothing was tampered with.

That's the product.
