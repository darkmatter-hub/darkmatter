# DarkMatter Context Passport
## A Proposed Open Standard for AI Agent Context Handoffs

**Version:** 1.0  
**Status:** Proposed  
**Maintained by:** DarkMatter (darkmatterhub.ai)  
**Goal:** A structured, model-agnostic context schema any LLM or agent framework can produce and consume — making agent handoffs interoperable, verifiable, and auditable across systems.

---

## Why a Standard

When Agent A hands work to Agent B today, the format is arbitrary. A string, a dict, a JSON blob with no fixed shape. Agent B has to guess what it received, where the output is, who produced it, and whether it was tampered with.

The Context Passport is a minimal, opinionated schema that answers all four questions in a consistent structure — regardless of which model, framework, or provider is on either end of the handoff.

---

## The Schema

```json
{
  "$schema": "https://darkmatterhub.ai/schema/context-passport/v1.json",
  "schema_version": "1.0",

  "id":        "ctx_{timestamp}_{hex}",
  "parent_id": "ctx_... | null",
  "trace_id":  "trc_... | null",
  "branch_key": "main | string",

  "created_by": {
    "agent_id":   "dm_...",
    "agent_name": "string",
    "role":       "researcher | writer | reviewer | critic | planner | executor | validator | custom",
    "provider":   "anthropic | openai | google | mistral | local | custom",
    "model":      "claude-opus-4-6 | gpt-4o | ... | string"
  },

  "event": {
    "type":        "commit | fork | checkpoint | revert | merge | spawn | error | override | audit",
    "to_agent_id": "dm_... | null",
    "timestamp":   "ISO 8601"
  },

  "payload": {
    "input":     "string | object | null",
    "output":    "string | object | null",
    "memory":    "object | null",
    "variables": "object | null"
  },

  "integrity": {
    "payload_hash":        "sha256:hex",
    "parent_hash":         "sha256:hex | null",
    "integrity_hash":      "sha256:hex",
    "verification_status": "valid | broken | unverified",
    "verified_at":         "ISO 8601 | null"
  },

  "lineage": {
    "fork_of":      "ctx_... | null",
    "fork_point":   "ctx_... | null",
    "lineage_root": "ctx_... | null"
  },

  "created_at": "ISO 8601"
}
```

---

## Field Reference

### Identity fields

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Globally unique context ID. Format: `ctx_{unix_ms}_{6 hex bytes}` |
| `parent_id` | string | null | ID of the previous context in the chain. Null for root commits. |
| `trace_id` | string | null | Groups multiple commits into a single pipeline run |
| `branch_key` | string | yes | Branch name. Default `main`. Used to distinguish fork branches. |
| `schema_version` | string | yes | Passport schema version. Currently `1.0`. |

### Agent attribution

| Field | Type | Required | Description |
|---|---|---|---|
| `created_by.agent_id` | string | yes | Unique identifier of the committing agent |
| `created_by.agent_name` | string | yes | Human-readable agent name |
| `created_by.role` | string | no | Semantic role of this agent in the pipeline |
| `created_by.provider` | string | no | LLM provider: `anthropic`, `openai`, `google`, `mistral`, `local`, `custom` |
| `created_by.model` | string | no | Specific model name or version |

### Event

| Field | Type | Required | Description |
|---|---|---|---|
| `event.type` | string | yes | What happened. See event types below. |
| `event.to_agent_id` | string | null | Recipient agent. Null for checkpoint or audit events. |
| `event.timestamp` | ISO 8601 | yes | When the event occurred |

### Payload

The payload carries the actual work. All fields are optional — use what is relevant.

| Field | Type | Description |
|---|---|---|
| `payload.input` | string or object | What this agent received as input |
| `payload.output` | string or object | What this agent produced |
| `payload.memory` | object | Persistent state, parameters, config, or tool results |
| `payload.variables` | object | Named values passed between agents (e.g. `{"user_id": "...", "threshold": 0.9}`) |

The `output` field should be structured where possible. If your agent produces JSON, commit the JSON — not a stringified version of it. This preserves schema across the chain and makes replay and inspection meaningful.

### Integrity

Computed by DarkMatter at commit time. Do not set manually.

| Field | Description |
|---|---|
| `payload_hash` | `sha256(JSON.stringify(payload, sorted keys))` |
| `parent_hash` | The `integrity_hash` of the parent commit. Null for root. |
| `integrity_hash` | `sha256(payload_hash + parent_hash)` |
| `verification_status` | `valid` if chain is intact. `broken` if parent hash mismatch detected. |

Tampering with any node in the chain breaks its hash, which breaks every downstream hash. The chain is independently verifiable without trusting DarkMatter.

### Lineage

Populated automatically on fork operations.

| Field | Description |
|---|---|
| `fork_of` | The context ID that was forked from |
| `fork_point` | The checkpoint where the fork began |
| `lineage_root` | The root of the original chain |

---

## Event Types

### Developer events
`commit` `fork` `checkpoint` `revert` `branch` `merge` `spawn` `retry` `timeout` `error`

### Compliance events
`override` `consent` `escalate` `redact` `audit`

Use compliance event types when an agent action has regulatory significance — a human override, a consent decision, an audit trigger.

---

## Integrity Model

```
payload_hash    = sha256(normalize(payload))
integrity_hash  = sha256(payload_hash + parent_integrity_hash)
```

Where `normalize(payload)` means `JSON.stringify(payload, Object.keys(payload).sort())` — deterministic key ordering so the same payload always produces the same hash.

For the root commit, `parent_integrity_hash = "root"`.

This means:
- Any modification to a committed payload changes its hash
- Which changes every downstream integrity hash
- Tampering is detectable at any point in the chain without access to the original data

---

## Why "Context Passport"

A passport is a standardized document any border authority worldwide can read, verify, and process — regardless of the country that issued it. A Context Passport is the same idea for AI agent handoffs: a standardized document any agent, framework, or model can produce, consume, and verify — regardless of who built it.

The goal is for `schema_version: "1.0"` to mean something to any developer building multi-agent systems, the same way `Content-Type: application/json` means something to any HTTP client.

---

## Implementing the Context Passport

### Producing a passport (any language)

Your agent does not need to construct the full passport manually. Commit your payload to DarkMatter and the passport fields are computed and returned:

```python
import requests

ctx = requests.post("https://darkmatterhub.ai/api/commit",
    headers={"Authorization": f"Bearer {API_KEY}"},
    json={
        "toAgentId": NEXT_AGENT_ID,
        "payload": {
            "input":  received_input,
            "output": {"summary": "...", "confidence": 0.94},  # structured output
            "memory": {"model": "claude-opus-4-6", "temperature": 0.3}
        },
        "agent":    {"role": "researcher", "provider": "anthropic", "model": "claude-opus-4-6"},
        "parentId": previous_ctx_id,
        "traceId":  trace_id,
    }
).json()

passport_id = ctx["id"]  # carry this to the next step
```

### Consuming a passport

The receiving agent pulls and gets a full passport:

```python
contexts = requests.get("https://darkmatterhub.ai/api/pull",
    headers={"Authorization": f"Bearer {AGENT_B_KEY}"}
).json()

passport  = contexts[0]
my_input  = passport["payload"]["output"]   # what the previous agent produced
chain_ok  = passport["integrity"]["verification_status"] == "valid"
who_sent  = passport["created_by"]["agent_name"]
```

### Verifying a passport independently

```bash
curl https://darkmatterhub.ai/api/verify/CTX_ID \
  -H "Authorization: Bearer YOUR_KEY"
# Returns: { chain_intact: true, length: 6, root_hash: "sha256:...", tip_hash: "sha256:..." }
```

---

## Self-hosting

The Context Passport schema is open. The reference implementation (DarkMatter) is MIT licensed. You can run your own passport authority inside your own infrastructure:

```bash
git clone https://github.com/darkmatter-hub/darkmatter
# Node.js + Postgres — full schema enforcement and hash chain verification
```

---

## Roadmap

- **v1.0** — Current. Core schema, hash chain, fork/lineage fields.
- **v1.1** — Schema contracts: define expected output schema per agent role, enforce at pull time.
- **v1.2** — Multimodal payload support: structured references to images, audio, and file outputs.
- **v2.0** — Federated verification: cross-organization passport verification without sharing payload content.

---

## Contributing

The Context Passport is a proposed standard. If you are building multi-agent systems and have opinions on the schema, open an issue or discussion at github.com/darkmatter-hub/darkmatter.
