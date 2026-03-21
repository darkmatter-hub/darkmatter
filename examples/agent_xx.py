"""
DarkMatter — Agent XX (Claude)
================================
Claude analyzes a topic and commits its findings to DarkMatter
so Agent YY (GPT) can pick up and continue.

Setup:
    pip install anthropic requests

Usage:
    python agent_xx.py
"""

import requests
import json
from datetime import datetime

# ── CONFIG ───────────────────────────────────────────────────────
ANTHROPIC_API_KEY = "your-anthropic-api-key"   # ← paste your key
DARKMATTER_URL    = "https://darkmatter-production.up.railway.app"
AGENT_XX_KEY      = "dm_sk_a01f86d7b193f2fef0d37d1da7fdb1bf39467f0e11d92141"
AGENT_YY_ID       = "dm_084578e0a339ddd5"  # ← Agent YY's ID from dashboard

# ── TASK ─────────────────────────────────────────────────────────
TASK = "Analyze the top 3 trends in AI agent infrastructure in 2026. Be specific and concise."

# ─────────────────────────────────────────────────────────────────

def run_claude(task: str) -> str:
    """Call Claude API directly via requests (no SDK needed)."""
    print(f"\n🤖 Agent XX (Claude) — starting task...")
    print(f"   Task: {task}\n")

    res = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key":         ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type":      "application/json",
        },
        json={
            "model":      "claude-opus-4-6",
            "max_tokens": 1024,
            "messages":   [{"role": "user", "content": task}],
        }
    )

    if res.status_code != 200:
        raise Exception(f"Claude API error {res.status_code}: {res.text}")

    output = res.json()["content"][0]["text"]
    print(f"✅ Claude completed task ({len(output)} chars)\n")
    return output


def commit_to_darkmatter(task: str, output: str) -> dict:
    """Commit Claude's output to DarkMatter for Agent YY."""
    print(f"📤 Committing context to DarkMatter...")
    print(f"   From: agent-xx → To: {AGENT_YY_ID}\n")

    res = requests.post(
        f"{DARKMATTER_URL}/api/commit",
        headers={
            "Authorization": f"Bearer {AGENT_XX_KEY}",
            "Content-Type":  "application/json",
        },
        json={
            "toAgentId": AGENT_YY_ID,
            "context": {
                "task":       task,
                "output":     output,
                "next_task":  "Write a concise 3-paragraph executive summary based on this analysis. Start directly with the summary.",
                "model":      "claude-opus-4-6",
                "status":     "complete",
                "timestamp":  datetime.utcnow().isoformat(),
                "from_agent": "agent-xx (Claude)",
            }
        }
    )

    if res.status_code != 200:
        raise Exception(f"DarkMatter commit error {res.status_code}: {res.text}")

    data = res.json()
    print(f"✅ Context committed to DarkMatter")
    print(f"   Commit ID: {data.get('commitId')}")
    print(f"   Verified:  {data.get('verified')}")
    print(f"\n   Agent YY (GPT) can now pull and continue.")
    print(f"   Run: python agent_yy.py\n")
    return data


def main():
    print("\n🌑 DarkMatter — Claude → GPT Pipeline")
    print("─" * 44)

    # Step 1: Claude does the work
    output = run_claude(TASK)

    # Preview the output
    preview = output[:200] + "..." if len(output) > 200 else output
    print(f"Claude output preview:\n{preview}\n")
    print("─" * 44)

    # Step 2: Commit to DarkMatter for GPT to pick up
    commit_to_darkmatter(TASK, output)

    print("─" * 44)
    print("✓ Agent XX done. Check your DarkMatter dashboard:")
    print(f"  https://darkmatter-production.up.railway.app/dashboard\n")


if __name__ == "__main__":
    main()
