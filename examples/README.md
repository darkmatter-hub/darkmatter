# DarkMatter — Real-World Example: Claude → GPT Pipeline

This example shows how to pass context from a Claude agent to a GPT agent
using DarkMatter as the handoff layer.

## What it does

```
agent_xx.py (Claude)          DarkMatter          agent_yy.py (GPT)
─────────────────             ──────────          ─────────────────
1. Analyzes topic   ─POST──▶  stores it
                              ◀──GET──            2. Pulls context
                                                  3. Writes summary
```

1. **Agent XX (Claude)** analyzes "top 3 trends in AI agent infrastructure"
2. Commits the full analysis to DarkMatter, addressed to Agent YY
3. **Agent YY (GPT)** pulls the verified context from DarkMatter
4. GPT writes an executive summary based on Claude's analysis

## Setup

```bash
pip install anthropic openai requests
```

Open `agent_xx.py` and add your Anthropic API key:
```python
ANTHROPIC_API_KEY = "sk-ant-..."
```

Open `agent_yy.py` and add your OpenAI API key:
```python
OPENAI_API_KEY = "sk-..."
```

## Run

```bash
# Step 1: Claude analyzes and commits to DarkMatter
python agent_xx.py

# Step 2: GPT pulls and continues
python agent_yy.py
```

## View in dashboard

Every commit appears in your DarkMatter dashboard:
https://darkmatter-production.up.railway.app/dashboard

You'll see:
- Which agent committed
- Which agent received
- The full context that was passed
- Timestamp of the handoff
