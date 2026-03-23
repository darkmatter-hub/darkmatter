"""
DarkMatter — Agent YY (GPT)
==============================
GPT pulls verified context from DarkMatter that Claude committed,
then continues the pipeline by writing an executive summary.

Setup:
    pip install openai requests

Usage:
    python agent_yy.py
    (run after agent_xx.py has committed context)
"""

import requests
import json

# ── CONFIG ───────────────────────────────────────────────────────
OPENAI_API_KEY = "your-openai-api-key"   # ← paste your key
DARKMATTER_URL = "https://darkmatterhub.ai"
AGENT_YY_KEY   = "dm_sk_your_agent_yy_key_here"

# ─────────────────────────────────────────────────────────────────

def pull_from_darkmatter() -> dict | None:
    """Pull verified context from DarkMatter."""
    print(f"\n📥 Agent YY (GPT) — pulling context from DarkMatter...")

    res = requests.get(
        f"{DARKMATTER_URL}/api/pull",
        headers={"Authorization": f"Bearer {AGENT_YY_KEY}"}
    )

    if res.status_code != 200:
        raise Exception(f"DarkMatter pull error {res.status_code}: {res.text}")

    data    = res.json()
    commits = data.get("commits", [])

    if not commits:
        print("   No context waiting in DarkMatter.")
        print("   Run agent_xx.py first to commit context.\n")
        return None

    latest = commits[0]
    print(f"✅ Pulled {len(commits)} commit(s) from DarkMatter")
    print(f"   From:     {latest['context'].get('from_agent', latest['from'])}")
    print(f"   Verified: {latest['verified']}")
    print(f"   Task:     {latest['context'].get('task', 'N/A')[:60]}...")
    return latest["context"]


def run_gpt(context: dict) -> str:
    """Call GPT with inherited context from Claude."""
    analysis  = context.get("output", "")
    next_task = context.get("next_task", "Summarize the above.")
    original  = context.get("task", "")

    print(f"\n🤖 Agent YY (GPT) — continuing pipeline...")
    print(f"   Inherited task: {next_task[:60]}...\n")

    res = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type":  "application/json",
        },
        json={
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are Agent YY in a multi-agent pipeline. "
                        "You are receiving verified context from Agent XX (Claude) via DarkMatter. "
                        "Continue the work based on what Claude completed."
                    )
                },
                {
                    "role": "user",
                    "content": (
                        f"Original task given to Claude: {original}\n\n"
                        f"Claude's analysis:\n{analysis}\n\n"
                        f"Your task: {next_task}"
                    )
                }
            ],
            "max_tokens": 800,
        }
    )

    if res.status_code != 200:
        raise Exception(f"OpenAI API error {res.status_code}: {res.text}")

    output = res.json()["choices"][0]["message"]["content"]
    print(f"✅ GPT completed task ({len(output)} chars)\n")
    return output


def main():
    print("\n🌑 DarkMatter — Claude → GPT Pipeline")
    print("─" * 44)

    # Step 1: Pull Claude's context from DarkMatter
    context = pull_from_darkmatter()
    if not context:
        return

    print("─" * 44)

    # Step 2: GPT continues with inherited context
    output = run_gpt(context)

    print("─" * 44)
    print("📄 Final output from Agent YY (GPT):\n")
    print(output)
    print("\n" + "─" * 44)
    print("✓ Pipeline complete.")
    print("  Claude analyzed → GPT summarized")
    print("  View the full commit log at:")
    print(f"  https://darkmatterhub.ai/dashboard\n")


if __name__ == "__main__":
    main()
