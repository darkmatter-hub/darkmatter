"""
DarkMatter — Complex Multi-Agent Pipeline
5 agents, agent spawning, all primitives: commit, replay, fork, diff, verify, share, bundle

Agents:
  orchestrator  → spawns researcher + writer
  researcher    → commits findings, spawns fact-checker
  fact-checker  → validates, commits checkpoint
  writer        → drafts summary, commits
  reviewer      → final refine + checkpoint (spawned by orchestrator)

How to create agents:

  Human (CLI):
    darkmatter init
    darkmatter init --email x@example.com --agent my-app

  Agent spawning agent (SDK):
    child = orchestrator.spawn_client("name", role="validator")
    child.commit(to_agent_id=child.agent_id, payload={...})

Run:
  pip install darkmatter-sdk requests
  darkmatter init
  python complex_pipeline.py
"""

import os, sys, time, json
import darkmatter as dm

ORCHESTRATOR_KEY = os.environ["DARKMATTER_API_KEY"]
ORCHESTRATOR_ID  = os.environ["DARKMATTER_AGENT_ID"]
TRACE_ID         = f"trc_complex_{int(time.time())}"

def log(msg="", **kw):
    print(msg, flush=True, **kw)

log("\n" + "="*60)
log("DarkMatter — Complex Multi-Agent Pipeline")
log(f"Trace: {TRACE_ID}")
log("="*60)

# ── Step 1: Orchestrator spawns researcher + writer ───────────────────────────
log("\n[1/7] Orchestrator spawning child agents...")
orchestrator = dm.DarkMatter(api_key=ORCHESTRATOR_KEY)
orchestrator.agent_id = ORCHESTRATOR_ID

researcher = orchestrator.spawn_client("researcher", role="researcher", model="claude-opus-4-6")
log(f"  ✓ Spawned: researcher ({researcher.agent_id[-8:]})")

writer = orchestrator.spawn_client("writer", role="writer", model="gpt-4o")
log(f"  ✓ Spawned: writer ({writer.agent_id[-8:]})")

spawn_ctx = orchestrator.commit(
    to_agent_id=ORCHESTRATOR_ID,
    payload={
        "event": "agents_spawned",
        "spawned": [
            {"name": "researcher", "id": researcher.agent_id},
            {"name": "writer",     "id": writer.agent_id},
        ],
        "task": "Analyze Q1 2026 APAC performance and produce executive summary",
    },
    trace_id=TRACE_ID, event_type="commit",
    agent={"role": "orchestrator", "provider": "anthropic", "model": "claude-opus-4-6"},
)
root_ctx_id = spawn_ctx["id"]
log(f"  ✓ Spawn event committed: {root_ctx_id[-16:]}")

# ── Step 2: Researcher works, spawns fact-checker ─────────────────────────────
log("\n[2/7] Researcher working + spawning fact-checker...")
time.sleep(0.4)

research_ctx = researcher.commit(
    to_agent_id=researcher.agent_id,
    payload={
        "input": "Analyze Q1 2026 APAC performance",
        "output": {
            "findings": [
                "APAC revenue: $4.2B (+34% YoY)",
                "Japan: +41%, enterprise AI adoption",
                "South Korea: +38%, semiconductor tooling",
                "ANZ: +22%, macro headwinds",
                "China: flat, regulatory environment",
            ],
            "confidence": 0.91,
        },
    },
    parent_id=root_ctx_id, trace_id=TRACE_ID, event_type="commit",
    agent={"role": "researcher", "provider": "anthropic", "model": "claude-opus-4-6"},
)
research_ctx_id = research_ctx["id"]
log(f"  ✓ Research committed: {research_ctx_id[-16:]}")

log("  → Researcher spawning fact-checker...")
factchecker = researcher.spawn_client("fact-checker", role="validator", model="claude-opus-4-6")
log(f"  ✓ Spawned: fact-checker ({factchecker.agent_id[-8:]})")

time.sleep(0.3)
factcheck_ctx = factchecker.commit(
    to_agent_id=factchecker.agent_id,
    payload={
        "input":  research_ctx["payload"]["output"]["findings"],
        "output": {"validated": True, "flags": [], "verdict": "All figures cross-referenced. No discrepancies."},
    },
    parent_id=research_ctx_id, trace_id=TRACE_ID, event_type="checkpoint",
    agent={"role": "validator", "provider": "anthropic", "model": "claude-opus-4-6"},
)
factcheck_ctx_id = factcheck_ctx["id"]
log(f"  ✓ Fact-check checkpoint: {factcheck_ctx_id[-16:]}")

# ── Step 3: Writer drafts summary ─────────────────────────────────────────────
log("\n[3/7] Writer drafting (GPT-4o)...")
time.sleep(0.4)

writer_ctx = writer.commit(
    to_agent_id=writer.agent_id,
    payload={
        "input":  {"findings": research_ctx["payload"]["output"]["findings"], "validated": True},
        "output": (
            "Q1 2026 APAC Performance: $4.2B revenue (+34% YoY). "
            "Japan leads at +41% driven by enterprise AI adoption. "
            "South Korea +38% via semiconductor tooling. ANZ +22%. China flat. "
            "Recommend accelerating Japan and Korea investment. Q2 guidance: +28-32% YoY."
        ),
    },
    parent_id=factcheck_ctx_id, trace_id=TRACE_ID, event_type="commit",
    agent={"role": "writer", "provider": "openai", "model": "gpt-4o"},
)
writer_ctx_id = writer_ctx["id"]
log(f"  ✓ Draft committed: {writer_ctx_id[-16:]}")

# ── Step 4: Orchestrator spawns reviewer, final checkpoint ────────────────────
log("\n[4/7] Spawning reviewer + final checkpoint...")
reviewer = orchestrator.spawn_client("reviewer", role="reviewer", model="claude-opus-4-6")
log(f"  ✓ Spawned: reviewer ({reviewer.agent_id[-8:]})")
time.sleep(0.3)

reviewer_ctx = reviewer.commit(
    to_agent_id=reviewer.agent_id,
    payload={
        "input":  writer_ctx["payload"]["output"],
        "output": {
            "approved": True, "edits": 1,
            "edit_summary": "Softened Q2 guidance to reflect uncertainty",
            "final_draft": (
                "Q1 2026 APAC Performance: $4.2B (+34% YoY). "
                "Japan +41%, Korea +38%, ANZ +22%. China flat. "
                "Recommend increasing Japan/Korea investment. Q2: +28-32% YoY."
            ),
            "ready_for_send": True,
        },
    },
    parent_id=writer_ctx_id, trace_id=TRACE_ID, event_type="checkpoint",
    agent={"role": "reviewer", "provider": "anthropic", "model": "claude-opus-4-6"},
)
reviewer_ctx_id = reviewer_ctx["id"]
TIP_CTX_ID = reviewer_ctx_id
log(f"  ✓ Review checkpoint: {reviewer_ctx_id[-16:]}")

# ── Step 5: Fork at writer — try gpt-4o-mini ─────────────────────────────────
log("\n[5/7] Forking at writer step (gpt-4o → gpt-4o-mini)...")
sys.stdout.flush()
time.sleep(0.3)

fork_ctx = writer.fork(writer_ctx_id, to_agent_id=writer.agent_id, branch_key="alt-gpt4o-mini")
fork_ctx_id = fork_ctx["id"]
log(f"  \u2346 Fork created: {fork_ctx_id[-16:]} (branch: alt-gpt4o-mini)")

fork_writer_ctx = writer.commit(
    to_agent_id=writer.agent_id,
    payload={
        "input":  writer_ctx["payload"]["input"],
        "output": (
            "APAC Q1 2026: $4.2B (+34%). Japan +41%, Korea +38%, ANZ +22%, China flat. "
            "AI adoption is the primary driver. Double down on Japan enterprise vertical. "
            "Q2 target: +30% with +35% upside if Korea momentum holds."
        ),
    },
    parent_id=fork_ctx_id, trace_id=TRACE_ID+"_fork", event_type="commit",
    agent={"role": "writer", "provider": "openai", "model": "gpt-4o-mini"},
)
fork_writer_ctx_id = fork_writer_ctx["id"]
log(f"  ✓ Fork draft committed: {fork_writer_ctx_id[-16:]}")

# ── Step 6: Diff ──────────────────────────────────────────────────────────────
log("\n[6/7] Diffing original vs fork...")
sys.stdout.flush()

diff = orchestrator.diff(TIP_CTX_ID, fork_writer_ctx_id)
log(f"  Changed steps:  {diff.get('changedSteps', '?')}")
log(f"  Models A:       {diff.get('summary', {}).get('modelsA', [])}")
log(f"  Models B:       {diff.get('summary', {}).get('modelsB', [])}")
log(f"\n  Original: \"{reviewer_ctx['payload']['output']['final_draft'][:70]}...\"")
log(f"  Fork:     \"{fork_writer_ctx['payload']['output'][:70]}...\"")

# ── Step 7: Verify → share → export ──────────────────────────────────────────
log("\n[7/7] Verify → share → export...")
sys.stdout.flush()

log("  Verifying chain...")
sys.stdout.flush()
verify = orchestrator.verify(TIP_CTX_ID)
log(f"  ✓ Chain intact: {verify.get('chain_intact')}")
log(f"  ✓ Commits: {verify.get('length')}")

sys.stdout.flush()
ret = orchestrator.retention(TIP_CTX_ID)
log(f"  ✓ Expires: {ret.get('expiresAt','')[:10]} ({ret.get('daysRemaining')} days)")

log("  Creating share link...")
sys.stdout.flush()
share = orchestrator.share(TIP_CTX_ID, label="Q1 2026 APAC — 5-agent pipeline with fork")
share_url = share.get("shareUrl", "")
log(f"  ✓ Share URL: {share_url}")

sys.stdout.flush()
md = orchestrator.markdown(TIP_CTX_ID)
log(f"\n  Markdown summary:")
for line in md.get("markdown", "").split("\n"):
    log(f"    {line}")

log("\n  Exporting bundle...")
sys.stdout.flush()
bundle = orchestrator.bundle(TIP_CTX_ID)
bundle_file = f"proof_bundle_{TRACE_ID}.json"
with open(bundle_file, "w") as f:
    json.dump(bundle, f, indent=2)
log(f"  ✓ Bundle: {bundle_file}")
log(f"  Hash:     {bundle['verification']['chainHash'][:48]}...")

# ── Summary ───────────────────────────────────────────────────────────────────
log("\n" + "="*60)
log("Done.")
log("="*60)
log(f"""
  Agents:   orchestrator → researcher → fact-checker
                         → writer
                         → reviewer
  Commits:  6 total (spawn, research, factcheck, write, review, fork-write)
  Fork:     writer step — gpt-4o vs gpt-4o-mini
  Root:     {root_ctx_id}
  Tip:      {TIP_CTX_ID}

  View:     {share_url}

  darkmatter open   {TIP_CTX_ID}
  darkmatter replay {TIP_CTX_ID}
  darkmatter diff   {TIP_CTX_ID} {fork_writer_ctx_id}
""")
