#!/usr/bin/env python3
"""
darkmatter CLI  —  replay · fork · compare
pip install darkmatter-sdk

Commands:
  demo        Run local demo — no signup required
  init        Create account + agent, write .env
  quickstart  Generate a runnable starter example
  replay      Walk a chain step by step
  fork        Branch from any checkpoint
  diff        Compare two chains
  recent      Show your latest chains
  open        Open a chain in the browser
  doctor      Check your setup
"""

import sys, os, json, time, hashlib, secrets, webbrowser
from datetime import datetime, timezone


# ─────────────────────────────────────────────────────────────────────────────
# Terminal / color
# ─────────────────────────────────────────────────────────────────────────────

def _supports_color():
    if '--plain' in sys.argv: return False
    if os.environ.get('NO_COLOR'): return False
    if sys.platform == 'win32':
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
            return True
        except Exception: return False
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

USE_COLOR = _supports_color()

def _c(t, code): return f"\033[{code}m{t}\033[0m" if USE_COLOR else t
def G(t):   return _c(t, '32')     # green   — success / added
def R(t):   return _c(t, '31')     # red     — failure / removed
def V(t):   return _c(t, '35')     # violet  — brand
def C(t):   return _c(t, '36')     # cyan    — IDs / links
def Y(t):   return _c(t, '33')     # amber   — fork / warning
def B(t):   return _c(t, '1')      # bold    — headers
def DIM(t): return _c(t, '2')      # dim     — secondary
def UL(t):  return _c(t, '4')      # underline

# Symbols — safe across terminals
SYM_OK    = G('✓')
SYM_FAIL  = R('✗')
SYM_WARN  = Y('!')
SYM_DOT   = G('●')
SYM_FDOT  = Y('●')
SYM_BAR   = DIM('│')
SYM_FORK  = Y('└─')
SYM_ARR   = C('→')
SYM_MINUS = R('-')
SYM_PLUS  = G('+')

def p(text='', delay=0):
    print(text)
    if delay: time.sleep(delay)

def sep(width=52):
    p(DIM('─' * width))

def blank(): p()

def header(title):
    blank()
    p(B(title))

def ok(msg):   p(f'  {SYM_OK} {msg}')
def fail(msg): p(f'  {SYM_FAIL} {msg}')
def warn(msg): p(f'  {SYM_WARN} {msg}')

def section(title):
    blank()
    p(B(title))

def fix_hint(cmd):
    p(f'  {DIM("Fix")}')
    p(f'    {DIM(cmd)}')


# ─────────────────────────────────────────────────────────────────────────────
# Network / env helpers
# ─────────────────────────────────────────────────────────────────────────────

BASE = 'https://darkmatterhub.ai'

def _api(method, path, body=None, key=None, timeout=12):
    from urllib import request as _r, error as _e
    url  = BASE + path
    data = json.dumps(body).encode() if body else None
    hdrs = {
        'Content-Type':  'application/json',
        'User-Agent':    'darkmatter-cli/1.3',
        'Accept':        'application/json',
    }
    if key: hdrs['Authorization'] = f'Bearer {key}'
    req = _r.Request(url, data=data, headers=hdrs, method=method)
    try:
        with _r.urlopen(req, timeout=timeout) as resp:
            return True, json.loads(resp.read())
    except _e.HTTPError as e:
        try: msg = json.loads(e.read()).get('error', f'HTTP {e.code}')
        except Exception: msg = f'HTTP {e.code}'
        return False, msg
    except Exception as e:
        return False, str(e)

def _load_env():
    env, path = {}, os.path.join(os.getcwd(), '.env')
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                env[k.strip()] = v.strip()
    return env

def _key():
    e = _load_env()
    return e.get('DARKMATTER_API_KEY') or os.environ.get('DARKMATTER_API_KEY', '')

def _agent():
    e = _load_env()
    return e.get('DARKMATTER_AGENT_ID') or os.environ.get('DARKMATTER_AGENT_ID', '')

def _ago(ts):
    try:
        from datetime import timezone as tz
        dt  = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        sec = int((datetime.now(tz.utc) - dt).total_seconds())
        if sec < 60: return f'{sec}s ago'
        if sec < 3600: return f'{sec//60}m ago'
        if sec < 86400: return f'{sec//3600}h ago'
        return f'{sec//86400}d ago'
    except Exception: return ''

def _short_model(m):
    return (m or '').replace('claude-opus-4-6','Claude').replace('claude-sonnet-4-6','Claude Sonnet') \
                    .replace('gpt-4o-mini','GPT-4o-mini').replace('gpt-4o','GPT-4o') \
                    .replace('gpt-4.1','GPT-4.1')

def _model_flow(steps):
    models = []
    for s in steps:
        m = _short_model(s.get('agent_info', {}).get('model') or s.get('model', ''))
        if m and (not models or models[-1] != m): models.append(m)
    return ' → '.join(models) if models else '—'


# ─────────────────────────────────────────────────────────────────────────────
# Local hash chain (demo only — no network)
# ─────────────────────────────────────────────────────────────────────────────

def _sha(t): return hashlib.sha256(t.encode()).hexdigest()

def _mkctx(role, model, payload, parent=None, event_type='commit'):
    cid = 'ctx_' + secrets.token_hex(3)
    now = datetime.now(timezone.utc).isoformat()
    canon = json.dumps(payload, sort_keys=True, separators=(',',':'))
    ph = _sha(canon); par_h = parent['_ih'] if parent else None
    ih = _sha(ph + (par_h or 'root'))
    return {'id': cid, 'parent_id': parent['id'] if parent else None,
            'role': role, 'model': model, 'event_type': event_type,
            'payload': payload, '_ph': ph, '_ih': ih, '_par': par_h, 'ts': now}

def _verify(chain):
    for i, ctx in enumerate(chain):
        ph = _sha(json.dumps(ctx['payload'], sort_keys=True, separators=(',',':')))
        par = chain[i-1]['_ih'] if i > 0 else None
        if ctx['_ih'] != _sha(ph + (par or 'root')): return False
    return True

def _draw_chain(chain, fork_ctx=None, fork_from=None):
    """Draw a git-style chain, with optional fork branch."""
    for i, ctx in enumerate(chain):
        short = _short_model(ctx.get('model', ''))
        is_fork_from = fork_from and ctx['id'] == fork_from
        p(f'  {SYM_DOT} {C(ctx["id"])}  {ctx["event_type"]:<16} {DIM(short)}')
        if i < len(chain) - 1:
            p(f'  {SYM_BAR}')
        if fork_ctx and is_fork_from:
            p(f'  {SYM_FORK}{SYM_FDOT} {Y(fork_ctx["id"])}  '
              f'{DIM("refine with GPT-4o-mini")}   {Y("← NEW")}')


# ─────────────────────────────────────────────────────────────────────────────
# darkmatter demo
# ─────────────────────────────────────────────────────────────────────────────

def cmd_demo():
    blank()
    p(B(V('DarkMatter')) + '  replay · fork · compare')
    blank()
    p('Replay, fork, and compare your AI workflow — step by step.')
    blank()
    p(DIM('No signup needed. Running locally...'))
    p(DIM('Works across Claude, GPT, local models, and your own code.'))
    p(delay=0.4)

    sep()
    p(B('Creating demo chain...'))
    blank()
    p(delay=0.3)

    steps = [
        ('planner',  'claude-opus-4-6', 'plan task',    {
            'input': 'Analyze Q1 performance and draft executive summary',
            'output': {'plan': ['gather data','analyze trends','draft summary'], 'confidence': 0.91}}),
        ('writer',   'gpt-4o',          'draft answer', {
            'input': {'plan': ['gather data','analyze trends','draft summary']},
            'output': 'Q1 Performance: APAC revenue up 34%. Key driver: Japan expansion.'}),
        ('reviewer', 'claude-opus-4-6', 'final refine', {
            'input': 'Q1 Performance: APAC revenue up 34%. Key driver: Japan expansion.',
            'output': {'approved': True, 'edits': 1, 'final': 'Q1 APAC Performance Report: Strong growth trajectory.'}}),
    ]

    chain = []
    for i, (role, model, event, payload) in enumerate(steps):
        ctx = _mkctx(role, model, payload, parent=chain[-1] if chain else None)
        ctx['_label'] = event   # store human step label separately from event_type
        chain.append(ctx)
        short = _short_model(model)
        p(f'  [{i+1}] {event:<18} {short:<12} {C(ctx["id"])}   {SYM_OK}', delay=0.25)

    blank()
    p(B('Chain'))
    for i, ctx in enumerate(chain):
        short = _short_model(ctx['model'])
        label = ctx.get('_label', ctx['event_type'])
        p(f'  {SYM_DOT} {C(ctx["id"])}  {label:<16} {DIM(short)}')
        if i < len(chain) - 1:
            p(f'  {SYM_BAR}')
    p(delay=0.3)

    sep()
    p(B('Verifying chain integrity...'), delay=0.5)
    blank()
    intact = _verify(chain)
    p(f'  {SYM_OK if intact else SYM_FAIL} Chain {"intact" if intact else "broken"} {DIM("(tamper-evident)")}')
    p(f'  Steps: {len(chain)}')
    p(f'  Root:  {C(chain[0]["id"])}')
    p(f'  Tip:   {C(chain[-1]["id"])}')
    p(delay=0.3)

    sep()
    p(B('Replaying from root...'), delay=0.4)
    blank()
    for ctx in chain:
        short = _short_model(ctx['model'])
        label = ctx.get('_label', ctx['event_type'])
        p(f'  {SYM_ARR} {ctx["id"]}  {short:<10}  {label}', delay=0.2)
    blank()
    p(f'{SYM_OK} Replay complete')
    p(delay=0.3)

    sep()
    p(B(f'Forking from step 2 ({C(chain[1]["id"])})'), delay=0.4)
    p(B('Trying GPT-4o-mini for final refine...'))
    p(delay=0.5)

    fork_payload = {'input': chain[1]['payload']['output'],
                    'output': {'approved': True, 'edits': 0,
                               'final': 'Q1 APAC Performance: Strong growth. Recommend expanding Japan strategy.'}}
    fork_ctx = _mkctx('reviewer', 'gpt-4o-mini', fork_payload, parent=chain[1], event_type='fork')

    blank()
    p(f'  Original branch')
    for i, ctx in enumerate(chain):
        p(f'  {SYM_DOT} {C(ctx["id"])}')
        if i < len(chain) - 1: p(f'  {SYM_BAR}')
    blank()
    p(f'  New branch')
    p(f'  {SYM_DOT} {C(chain[0]["id"])}')
    p(f'  {SYM_BAR}')
    p(f'  {SYM_DOT} {C(chain[1]["id"])}')
    p(f'  {SYM_FORK}{SYM_FDOT} {Y(fork_ctx["id"])}  {DIM("refine with GPT-4o-mini")}   {Y("← NEW")}')
    p(delay=0.3)

    sep()
    p(B('Comparing original vs fork (step 3)...'), delay=0.4)
    blank()
    orig = chain[2]['payload']['output']['final']
    forked = fork_ctx['payload']['output']['final']
    p(f'  Model change: {R("Claude")} → {G("GPT-4o-mini")}')
    blank()
    p(f'  {DIM("Step 3")}')
    p(f'  {SYM_MINUS} Claude      "{orig[:50]}"')
    p(f'  {SYM_PLUS} GPT-4o-mini "{forked[:50]}"')
    p(delay=0.3)

    sep()
    blank()
    p('You just:')
    blank()
    p(f'{SYM_OK} Recorded a workflow as a chain')
    p(f'{SYM_OK} Verified it hasn\'t been modified')
    p(f'{SYM_OK} Replayed it step-by-step')
    p(f'{SYM_OK} Forked from a checkpoint')
    p(f'{SYM_OK} Compared two outcomes')
    blank()
    sep()
    p(B('Next'))
    blank()
    p(f'  darkmatter init')
    blank()
    p(DIM('  Or wrap one call directly:'))
    p(DIM('  import darkmatter as dm'))
    p(DIM('  ctx = dm.commit(to_agent_id, payload={"output": result})'))
    blank()
    p(DIM(f'  Docs  {BASE}/docs'))
    blank()


# ─────────────────────────────────────────────────────────────────────────────
# darkmatter init
# ─────────────────────────────────────────────────────────────────────────────

def cmd_init(args):
    email_flag = next((args[i+1] for i,a in enumerate(args) if a=='--email' and i+1<len(args)), None)
    agent_flag = next((args[i+1] for i,a in enumerate(args) if a=='--agent' and i+1<len(args)), None)
    no_test    = '--no-test' in args
    noninter   = bool(email_flag)

    blank()
    p(B(V('DarkMatter')) + '  init')
    blank()
    p('Set up DarkMatter for this project in under a minute.')
    p(DIM('No browser required.'))
    blank()

    env_path = os.path.join(os.getcwd(), '.env')
    env_mode = 'create'

    if os.path.exists(env_path):
        existing = open(env_path).read()
        if 'DARKMATTER_API_KEY' in existing and not noninter:
            p(DIM('Existing .env file detected.'))
            blank()
            p('What would you like to do?')
            p('  1. Append new DarkMatter keys')
            p('  2. Replace existing DarkMatter keys')
            p('  3. Cancel')
            blank()
            try: choice = input('  Choose [1/2/3]: ').strip()
            except (KeyboardInterrupt, EOFError): p(); p('Cancelled.'); return
            if choice == '3': p('Cancelled.'); return
            env_mode = 'replace' if choice == '2' else 'append'
        else:
            env_mode = 'append'

    email = email_flag
    if not email:
        try: email = input('  Email: ').strip()
        except (KeyboardInterrupt, EOFError): p(); p('Cancelled.'); return
    if not email or '@' not in email:
        fail('Invalid email address.'); return

    default_name = os.path.basename(os.getcwd()).replace(' ','-').lower()[:40] or 'my-agent'
    agent_name   = agent_flag
    if not agent_name:
        if noninter:
            agent_name = default_name
        else:
            try: agent_name = input(f'  Agent name [{default_name}]: ').strip() or default_name
            except (KeyboardInterrupt, EOFError): agent_name = default_name

    blank()
    p(DIM('  Creating your agent...'))

    ok2, result = _api('POST', '/api/provision',
                       {'email': email, 'agentName': agent_name, 'source': 'cli_init'})
    if not ok2:
        fail('Provisioning failed')
        blank()
        p(f'  {DIM("Reason")}')
        p(f'    {result}')
        blank()
        p(f'  {DIM("Try")}')
        p(f'    darkmatter doctor')
        blank()
        return

    api_key  = result.get('apiKey', '')
    agent_id = result.get('agentId', '')
    agent_nm = result.get('agentName', agent_name)
    existing = result.get('existingAccount', False)

    if existing:
        blank()
        p(DIM('  Existing account found. Creating a new agent under that account...'))

    ok('Agent created')
    ok('API key generated')

    # Write .env
    new_lines = f'DARKMATTER_API_KEY={api_key}\nDARKMATTER_AGENT_ID={agent_id}\n'
    written = False
    try:
        if env_mode == 'replace':
            lines = [l for l in open(env_path).readlines() if not l.startswith('DARKMATTER_')]
            with open(env_path, 'w') as f: f.writelines(lines); f.write(new_lines)
        else:
            with open(env_path, 'a') as f: f.write(new_lines)
        written = True
    except Exception: pass

    ok('.env written') if written else warn('Could not write to .env')

    blank(); sep(); blank()
    p(B('Project'))
    p(f'  Agent:    {agent_nm}')
    p(f'  Agent ID: {C(agent_id)}')
    masked = api_key[:8] + '·'*8 + api_key[-4:] if len(api_key) > 12 else api_key
    p(f'  API key:  {DIM(masked)}')
    blank()
    p(B('Files'))
    p(f'  {"Created" if env_mode == "create" else "Updated"}:  .env')
    blank()
    p(B('Environment'))
    p(DIM(f'  DARKMATTER_API_KEY={api_key[:8]}...'))
    p(DIM(f'  DARKMATTER_AGENT_ID={agent_id}'))
    blank()

    # Optional test commit
    ctx_id = None
    do_test = False
    if not no_test and not noninter:
        try: ans = input('  Create a test commit now? [y/n] ').strip().lower()
        except (KeyboardInterrupt, EOFError): ans = 'n'
        do_test = ans in ('', 'y', 'yes')

    if do_test:
        blank()
        p(DIM('  Creating test commit...'))
        ok2t, rt = _api('POST', '/api/commit',
                        {'toAgentId': agent_id,
                         'payload': {'input': 'init test', 'output': 'darkmatter init test commit'},
                         'eventType': 'commit', 'agent': {'role': 'tester'}},
                        key=api_key)
        if ok2t:
            ctx_id = rt.get('id', '')
            ok('Test commit created')
            p(f'    Context ID: {C(ctx_id)}')
            blank()
            ok2v, rv = _api('GET', f'/api/verify/{ctx_id}', key=api_key)
            if ok2v and rv.get('chain_intact'):
                ok('Chain intact')
            blank()
            # Mini replay
            ok2r, rr = _api('GET', f'/api/replay/{ctx_id}', key=api_key)
            if ok2r:
                steps = rr.get('replay', [])
                p(DIM('  Replaying...'))
                blank()
                for s in steps:
                    short = _short_model(s.get('model','') or s.get('agent_info',{}).get('model',''))
                    p(f'  {SYM_ARR} {C(s.get("id","")[:14])}  {short}')
                    time.sleep(0.1)
                blank()
                p(f'{SYM_OK} Replay complete')
                blank()
            p(B('Your first chain is live.'))
            blank()
            p(f'  Open it:')
            p(f'    darkmatter open {ctx_id}')
            blank()
            # Auto-open option
            if not noninter:
                try: ans2 = input('  Open in browser? [y/n] ').strip().lower()
                except (KeyboardInterrupt, EOFError): ans2 = 'n'
                if ans2 in ('y', 'yes'):
                    ok2s, rs = _api('POST', f'/api/share/{ctx_id}',
                                    {'label': 'init test chain'}, key=api_key)
                    url = rs.get('shareUrl', BASE + '/dashboard') if ok2s else BASE + '/dashboard'
                    webbrowser.open(url)
                    ok(f'Opening in browser...')
        else:
            warn(f'Test commit failed: {rt}')

    blank(); sep(); blank()
    p(B('Next'))
    blank()
    p(f'  darkmatter quickstart single')
    blank()
    p(DIM(f'  Docs  {BASE}/docs'))
    blank()


# ─────────────────────────────────────────────────────────────────────────────
# darkmatter quickstart
# ─────────────────────────────────────────────────────────────────────────────

QS_FILES = {
'single': ('darkmatter_example.py', '''import os
import darkmatter as dm

# Replace this with your real model call
result = "hello from my first real run"

agent_id = os.environ.get("DARKMATTER_AGENT_ID", "my-agent")

ctx = dm.commit(
    to_agent_id=agent_id,
    payload={"output": result, "event": "single_example"},
)

ctx_id = ctx.get("id") or ctx.get("ctxId", "")
print(f"Context: {ctx_id}")

replay = dm.replay(ctx_id)
print(f"Chain intact: {replay.get(\'chainIntact\')}, Steps: {replay.get(\'totalSteps\')}")
print("View your chain: https://darkmatterhub.ai/dashboard")
'''),
'openai': ('darkmatter_openai_example.py', '''\
import os, openai, darkmatter as dm
from darkmatter.integrations.openai import dm_client

agent_id = os.environ.get("DARKMATTER_AGENT_ID", "my-agent")
client   = dm_client(openai.OpenAI(), agent_id=agent_id, to_agent_id=agent_id)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Summarize the state of AI in 2026."}]
)
print(response.choices[0].message.content)

if client.last_ctx_id:
    replay = dm.replay(client.last_ctx_id)
    print(f"Chain intact: {replay.get('chainIntact')}")
'''),
'anthropic': ('darkmatter_anthropic_example.py', '''\
import os, anthropic, darkmatter as dm
from darkmatter.integrations.anthropic import dm_client

agent_id = os.environ.get("DARKMATTER_AGENT_ID", "my-agent")
client   = dm_client(anthropic.Anthropic(), agent_id=agent_id, to_agent_id=agent_id)

response = client.messages.create(
    model="claude-opus-4-6", max_tokens=256,
    messages=[{"role": "user", "content": "Summarize the state of AI in 2026."}]
)
print(response.content[0].text)

if client.last_ctx_id:
    replay = dm.replay(client.last_ctx_id)
    print(f"Chain intact: {replay.get('chainIntact')}")
'''),
'langgraph': ('darkmatter_langgraph_example.py', '''\
import os
from typing import TypedDict
from langgraph.graph import StateGraph, END
from darkmatter.integrations.langgraph import DarkMatterTracer

agent_id = os.environ.get("DARKMATTER_AGENT_ID", "my-agent")

class State(TypedDict):
    input: str
    output: str

def step_one(state): return {"output": f"Processed: {state[\'input\']}"}
def step_two(state): return {"output": f"Refined: {state[\'output\']}"}

workflow = StateGraph(State)
workflow.add_node("step_one", step_one)
workflow.add_node("step_two", step_two)
workflow.set_entry_point("step_one")
workflow.add_edge("step_one", "step_two")
workflow.add_edge("step_two", END)
app = workflow.compile()
app = DarkMatterTracer(app, agent_id=agent_id, to_agent_id=agent_id)

result = app.invoke({"input": "Analyze Q1 results", "output": ""})
print(result)
'''),
}

def cmd_quickstart(args):
    force   = '--force' in args
    variant = next((a for a in args if a in QS_FILES), None)
    blank()
    p(B(V('DarkMatter')) + '  quickstart')
    blank()

    if not variant:
        p('Choose a starter:')
        p('  1. single       One model call, then replay it')
        p('  2. openai       Wrap an OpenAI call')
        p('  3. anthropic    Wrap an Anthropic call')
        p('  4. langgraph    Trace an existing graph')
        blank()
        try: choice = input('  Choose [1/2/3/4] (default: 1): ').strip()
        except (KeyboardInterrupt, EOFError): p(); p('Cancelled.'); return
        variant = {'1':'single','2':'openai','3':'anthropic','4':'langgraph','':'single'}.get(choice,'single')

    filename, content = QS_FILES[variant]
    content = content.replace('{BASE}', BASE)

    target = os.path.join(os.getcwd(), filename)
    if os.path.exists(target) and not force:
        base, ext = os.path.splitext(filename)
        alt = f'{base}_2{ext}'
        p(f'  {DIM("File exists: " + filename)}')
        p(f'  1. Overwrite (default)')
        p(f'  2. Create {alt}')
        p(f'  3. Cancel')
        blank()
        try: choice = input('  Choose [Enter/2/3]: ').strip()
        except (KeyboardInterrupt, EOFError): p(); p('Cancelled.'); return
        if choice == '3': p('Cancelled.'); return
        if choice == '2': filename = alt; target = os.path.join(os.getcwd(), filename)
        # Enter or '1' = overwrite (default)

    # Inject real agent ID
    aid = _agent()
    if aid:
        content = content.replace('os.environ.get("DARKMATTER_AGENT_ID", "my-agent")',
                                  f'os.environ.get("DARKMATTER_AGENT_ID", "{aid}")')

    blank()
    p(DIM('  Generating starter example...'))
    blank()

    try:
        with open(target, 'w') as f: f.write(content)
        ok(f'Created: {filename}')
    except Exception as e:
        fail(f'Could not write file: {e}'); return

    if aid:
        p(DIM('  This uses your real agent and will show up in your chain history.'))

    blank()
    notes = {
        'single':   [],
        'openai':   ['Set OPENAI_API_KEY in .env', 'pip install openai'],
        'anthropic':['Set ANTHROPIC_API_KEY in .env', 'pip install anthropic'],
        'langgraph':['pip install langgraph', 'Set ANTHROPIC_API_KEY or OPENAI_API_KEY'],
    }
    what = {
        'single':   ['Creates a commit','Replays the run','Prints the context ID'],
        'langgraph':['Wraps a compiled graph with DarkMatterTracer',
                     'Auto-commits each completed node','Replays the resulting chain'],
    }
    if variant in what:
        p(B('What this example does'))
        for w in what[variant]: p(f'  {DIM("·")} {w}')
        blank()
    if notes[variant]:
        p(B('Before you run this'))
        for i, n in enumerate(notes[variant]): p(f'  {i+1}. {n}')
        blank()

    p(B('Run it now:'))
    p(f'  python {filename}')
    blank()
    p(B('Then:'))
    p(f'  darkmatter open')
    blank()
    p(DIM('  Next: run the example, then replay your first real run.'))
    blank()


# ─────────────────────────────────────────────────────────────────────────────
# darkmatter replay
# ─────────────────────────────────────────────────────────────────────────────

def cmd_replay(args):
    ctx_id   = next((a for a in args if a.startswith('ctx_') or a.startswith('share_')), None)
    from_arg = next((args[i+1] for i,a in enumerate(args) if a=='--from' and i+1<len(args)), None)
    full     = '--full' in args
    summary  = not full
    do_open  = '--open' in args

    blank()
    p(B(V('DarkMatter')) + '  replay')
    blank()

    # Resolve numeric index from recent
    if not ctx_id:
        idx = next((a for a in args if a.isdigit()), None)
        if idx:
            api_key = _key()
            if api_key:
                ok2, result = _api('GET', f'/api/search?limit={idx}', key=api_key)
                if ok2:
                    commits = result.get('results', [])
                    n = int(idx) - 1
                    if n < len(commits):
                        ctx_id = commits[n].get('id')
                        p(DIM(f'  Resolved [{idx}] → {ctx_id}'))
                        blank()

    if not ctx_id:
        fail('Context ID required')
        blank()
        fix_hint('darkmatter recent')
        blank(); return

    api_key = _key()
    if not api_key:
        fail('No API key found'); fix_hint('darkmatter init'); blank(); return

    mode_label = 'full' if full else 'summary'
    p(f'  Context: {C(ctx_id)}')
    p(f'  Mode:    {mode_label}')
    blank()
    p(DIM('  Fetching chain...'))

    ok2, result = _api('GET', f'/api/replay/{ctx_id}{"?mode=full" if full else ""}', key=api_key)
    if not ok2:
        fail(f'Context not found: {ctx_id}')
        blank(); fix_hint('darkmatter recent'); blank(); return

    chain = result.get('replay', [])
    if not chain:
        fail('No steps found for this context')
        blank(); fix_hint('darkmatter quickstart single'); blank(); return

    ok(f'{len(chain)} steps')

    # Determine range
    from_step = 1
    if from_arg:
        try:
            from_step = int(from_arg)
            p(f'  Range:   step {from_step} → tip')
        except ValueError:
            pass

    blank()
    p(B('Replaying from root...' if from_step == 1 else f'Replaying from step {from_step}...'))
    blank()

    for step in chain:
        n = step.get('step', 0)
        if n < from_step: continue
        short  = _short_model(step.get('model','') or step.get('agent_info',{}).get('model',''))
        event  = step.get('eventType', step.get('event_type', 'commit'))
        sid    = step.get('id','')
        intact = step.get('integrity', {}).get('chainValid', True)
        dot    = SYM_OK if intact else SYM_FAIL

        p(f'  {SYM_ARR} [{n}] {C(sid)}  {short:<12}  {event}', delay=0.15)

        if full:
            payload = step.get('payload') or step.get('context', {})
            if payload:
                out = payload.get('output','') if isinstance(payload, dict) else str(payload)
                snippet = str(out)[:80]
                p(f'      {DIM(repr(snippet))}')

    blank()
    p(f'{SYM_OK} {"Partial r" if from_step > 1 else "R"}eplay complete')
    blank()
    sep()
    blank()
    p(B('Tip'))
    if from_step == 1:
        p(f'  Replay from a step:')
        p(f'    darkmatter replay {ctx_id} --from 2')
    p(f'  Open in browser:')
    p(f'    darkmatter open {ctx_id}')
    blank()

    if do_open:
        cmd_open([ctx_id])


# ─────────────────────────────────────────────────────────────────────────────
# darkmatter fork
# ─────────────────────────────────────────────────────────────────────────────

def cmd_fork(args):
    ctx_id    = next((a for a in args if a.startswith('ctx_')), None)
    from_arg  = next((args[i+1] for i,a in enumerate(args) if a=='--from' and i+1<len(args)), None)
    model_arg = next((args[i+1] for i,a in enumerate(args) if a=='--model' and i+1<len(args)), None)
    do_open   = '--open' in args

    blank()
    p(B(V('DarkMatter')) + '  fork')
    blank()

    if not ctx_id:
        fail('Context ID required')
        blank(); fix_hint('darkmatter recent'); blank(); return

    api_key = _key()
    if not api_key:
        fail('No API key found'); fix_hint('darkmatter init'); blank(); return

    from_label = f'step {from_arg}' if from_arg else 'tip'
    p(f'  Forking from {from_label} ({C(ctx_id)})')
    if model_arg: p(f'  Suggested model: {G(_short_model(model_arg))}')
    blank()
    p(DIM('  Creating fork...'))

    body = {}
    if from_arg:
        try: body['fromStep'] = int(from_arg)
        except ValueError: body['fromCtxId'] = from_arg
    if model_arg: body['suggestedModel'] = model_arg

    ok2, result = _api('POST', f'/api/fork/{ctx_id}', body if body else None, key=api_key)
    if not ok2:
        fail(f'Fork failed: {result}')
        blank(); return

    fork_id    = result.get('id','')
    fork_point = result.get('fork_of', ctx_id)
    branch     = result.get('branch_key','fork')

    blank()
    ok('Fork created')
    p(f'')
    p(f'  Fork ID:    {Y(fork_id)}')
    p(f'  Fork point: {C(fork_point)}')
    p(f'  Branch:     {DIM(branch)}')

    # Draw the tree
    # Fetch original chain for drawing
    ok2c, chain_data = _api('GET', f'/api/replay/{ctx_id}', key=api_key)
    chain_steps = chain_data.get('replay', []) if ok2c else []

    blank(); sep(); blank()
    p(B('Original'))
    if chain_steps:
        for i, s in enumerate(chain_steps):
            p(f'  {SYM_DOT} {C(s.get("id",""))}')
            if i < len(chain_steps) - 1: p(f'  {SYM_BAR}')
    else:
        p(f'  {SYM_DOT} {C(ctx_id)}')

    blank()
    p(B('Fork'))
    if chain_steps:
        for i, s in enumerate(chain_steps):
            sid = s.get('id','')
            p(f'  {SYM_DOT} {C(sid)}')
            if sid == fork_point:
                p(f'  {SYM_FORK}{SYM_FDOT} {Y(fork_id)}   {Y("← NEW")}')
                break
            p(f'  {SYM_BAR}')
    else:
        p(f'  {SYM_DOT} {C(ctx_id)}')
        p(f'  {SYM_FORK}{SYM_FDOT} {Y(fork_id)}   {Y("← NEW")}')

    blank(); sep(); blank()
    p(B('Next'))
    blank()
    p('Commit to the fork:')
    p(DIM(f'  dm.commit(parent_id="{fork_id}", payload={{...}})'))
    blank()
    if model_arg:
        p(f'Run with {G(_short_model(model_arg))}:')
        p(DIM(f'  dm.commit(parent_id="{fork_id}",'))
        p(DIM(f'    payload={{"model": "{model_arg}", "output": result}})'))
        blank()
    p('Compare results:')
    p(DIM(f'  darkmatter diff {ctx_id} {fork_id}'))
    blank()

    if do_open:
        cmd_open([fork_id])


# ─────────────────────────────────────────────────────────────────────────────
# darkmatter diff
# ─────────────────────────────────────────────────────────────────────────────

def cmd_diff(args):
    ids      = [a for a in args if a.startswith('ctx_')]
    full     = '--full' in args
    mod_only = '--model-only' in args
    step_arg = next((args[i+1] for i,a in enumerate(args) if a=='--step' and i+1<len(args)), None)
    fork_sw  = '--fork' in args

    blank()
    p(B(V('DarkMatter')) + '  diff')
    blank()

    if len(ids) < 2 and not fork_sw:
        fail('Two context IDs required')
        blank()
        p(DIM('  Usage: darkmatter diff <ctxA> <ctxB>'))
        p(DIM('         darkmatter diff <ctx> --fork'))
        blank(); return

    api_key = _key()
    if not api_key:
        fail('No API key found'); fix_hint('darkmatter init'); blank(); return

    ctx_a = ids[0]
    ctx_b = ids[1] if len(ids) > 1 else None

    # --fork: find the fork of ctx_a
    if fork_sw and not ctx_b:
        p(DIM('  Fetching fork...'))
        ok2, result = _api('GET', f'/api/lineage/{ctx_a}', key=api_key)
        # Use the diff endpoint directly
        ctx_b = ctx_a  # will be handled by server diff logic

    p(DIM('  Fetching diff...'))
    ok2, result = _api('GET', f'/api/diff/{ctx_a}/{ctx_b}', key=api_key)
    if not ok2:
        fail(f'Diff failed: {result}')
        blank(); fix_hint('darkmatter recent'); blank(); return

    chain_a   = result.get('chainA', [])
    chain_b   = result.get('chainB', [])
    changed   = result.get('changedSteps', 0)
    unchanged = result.get('unchangedSteps', 0)
    summary   = result.get('summary', {})
    models_a  = ' → '.join(summary.get('modelsA', []))
    models_b  = ' → '.join(summary.get('modelsB', []))

    blank()
    p(B('Comparing'))
    blank()
    p(f'  A  {C(ctx_a)}   {DIM(models_a)}')
    p(f'  B  {C(ctx_b)}   {DIM(models_b)}')
    blank(); sep(); blank()

    if step_arg:
        # Single step diff
        try: target_step = int(step_arg)
        except ValueError: target_step = 1
        _diff_step(chain_a, chain_b, target_step, full)
    elif mod_only:
        p(B('Model changes'))
        blank()
        diffs = result.get('diffs', [])
        if diffs:
            for d in diffs:
                step = d.get('step', '?')
                ma   = _short_model(d.get('modelA',''))
                mb   = _short_model(d.get('modelB',''))
                if ma != mb:
                    p(f'  Step {step}: {R(ma)} → {G(mb)}')
        else:
            p(DIM('  No model changes'))
    elif full:
        p(B('Full diff'))
        blank()
        max_steps = max(len(chain_a), len(chain_b))
        for i in range(max_steps):
            sa = chain_a[i] if i < len(chain_a) else None
            sb = chain_b[i] if i < len(chain_b) else None
            _diff_step_full(sa, sb, i+1)
    else:
        # Summary mode
        p(f'  Changed steps: {Y(str(changed)) if changed else G("0")}')
        p(f'  Unchanged:     {G(str(unchanged))}')
        blank()
        diffs = result.get('diffs', [])
        if diffs:
            p(B('Model changes'))
            for d in diffs:
                step = d.get('step', '?')
                ma   = _short_model(d.get('modelA',''))
                mb   = _short_model(d.get('modelB',''))
                pa   = d.get('payloadChanged', False)
                if ma != mb:
                    p(f'  Step {step}: {R(ma)} → {G(mb)}')
                elif pa:
                    p(f'  Step {step}: payload changed')
            blank()
            p(B('Payload changes'))
            for d in diffs:
                if d.get('payloadChanged'):
                    step = d.get('step', '?')
                    oa   = str(d.get('outputA',''))[:50]
                    ob   = str(d.get('outputB',''))[:50]
                    blank()
                    p(f'  {DIM("Step " + str(step))}')
                    if oa: p(f'  {SYM_MINUS} {_short_model(d.get("modelA",""))}  "{oa}"')
                    if ob: p(f'  {SYM_PLUS} {_short_model(d.get("modelB",""))}  "{ob}"')

    blank(); sep(); blank()

    if changed == 0:
        p(f'{SYM_OK} Chains are identical')
    elif changed > 0:
        first_diff = result.get('diffs', [{}])[0].get('step', '?')
        p(f'{SYM_OK} Same until step {first_diff}, then diverged')

    blank()
    p(B('Replay either:'))
    p(DIM(f'  darkmatter replay {ctx_a}'))
    p(DIM(f'  darkmatter replay {ctx_b}'))
    blank()
    p(B('View details:'))
    p(DIM(f'  darkmatter diff {ctx_a} {ctx_b} --full'))
    blank()


def _diff_step(chain_a, chain_b, step, full):
    sa = next((s for s in chain_a if s.get('step') == step), None)
    sb = next((s for s in chain_b if s.get('step') == step), None)
    if not sa and not sb: p(DIM(f'  Step {step} not found in either chain')); return
    p(B(f'Step {step}'))
    blank()
    _diff_step_full(sa, sb, step)


def _diff_step_full(sa, sb, step):
    if not sa and not sb: return
    ma = _short_model(sa.get('model','') if sa else '')
    mb = _short_model(sb.get('model','') if sb else '')
    identical = (ma == mb)

    p(f'  {DIM("Step " + str(step))} {"" if not identical else DIM("— identical")}')
    if not identical:
        blank()
        p(f'  Model')
        if ma: p(f'    {SYM_MINUS} {R(ma)}')
        if mb: p(f'    {SYM_PLUS} {G(mb)}')

    pa = sa.get('payload') if sa else None
    pb = sb.get('payload') if sb else None
    if pa != pb and (pa is not None or pb is not None):
        oa = str((pa or {}).get('output', pa) if isinstance(pa, dict) else pa or '')[:60]
        ob = str((pb or {}).get('output', pb) if isinstance(pb, dict) else pb or '')[:60]
        blank()
        p(f'  Output')
        if oa: p(f'    {SYM_MINUS} {R(ma or "A")}  "{oa}"')
        if ob: p(f'    {SYM_PLUS} {G(mb or "B")}  "{ob}"')
    blank()


# ─────────────────────────────────────────────────────────────────────────────
# darkmatter recent
# ─────────────────────────────────────────────────────────────────────────────

def cmd_recent(args):
    limit = next((int(args[i+1]) for i,a in enumerate(args) if a=='--limit' and i+1<len(args)), 5)
    json_mode = '--json' in args

    blank()
    p(B(V('DarkMatter')) + '  recent')
    blank()

    api_key = _key()
    if not api_key:
        fail('No API key found'); fix_hint('darkmatter init'); blank(); return

    ok2, result = _api('GET', f'/api/search?limit={limit}', key=api_key)
    if not ok2:
        fail(f'Could not fetch recent chains: {result}')
        blank(); return

    commits = result.get('results', [])
    if not commits:
        p(DIM('  No chains found yet.'))
        blank()
        p(B('Create your first one:'))
        p(f'  darkmatter quickstart single')
        blank(); return

    if json_mode:
        print(json.dumps(commits, indent=2)); return

    p(DIM(f'  Showing last {len(commits)} chains'))
    blank()

    for i, c in enumerate(commits):
        cid    = c.get('id','')
        ts     = _ago(c.get('timestamp', c.get('saved_at','')))
        intact = SYM_OK
        model  = _short_model(c.get('agent_info',{}).get('model') or c.get('model',''))
        # Try to show model flow if lineage available
        flow   = model or '—'
        p(f'  [{i+1}] {C(cid)}  {DIM(ts):<14}  {intact}  {DIM(flow)}')

    blank()
    p(B('Replay:'))
    p(DIM(f'  darkmatter replay {commits[0].get("id","")}'))
    p(DIM(f'  darkmatter replay 1'))
    blank()
    p(B('Open:'))
    p(DIM(f'  darkmatter open {commits[0].get("id","")}'))
    p(DIM(f'  darkmatter open 1'))
    blank()


# ─────────────────────────────────────────────────────────────────────────────
# darkmatter open
# ─────────────────────────────────────────────────────────────────────────────

def cmd_open(args):
    # Reject agent IDs — must be ctx_ or share_ or index
    agent_id_arg = next((a for a in args if a.startswith('dm_')), None)
    if agent_id_arg:
        blank()
        fail(f'Expected a context ID (ctx_...), got an agent ID ({agent_id_arg})')
        p(DIM('  Usage: darkmatter open ctx_abc123'))
        p(DIM('         darkmatter open  (opens most recent chain)'))
        blank()
        return

    target = next((a for a in args if a.startswith('ctx_') or a.startswith('share_')), None)
    api_key = _key()

    blank()

    # Resolve recent index (e.g. "1")
    if not target:
        idx = next((a for a in args if a.isdigit()), None)
        if idx and api_key:
            ok2, result = _api('GET', f'/api/search?limit={idx}', key=api_key)
            if ok2:
                commits = result.get('results', [])
                n = int(idx) - 1
                if n < len(commits):
                    target = commits[n].get('id')
                    p(f'  Resolved [{idx}] {SYM_ARR} {C(target)}')

    if not target and api_key:
        # Most recent
        p(DIM('  Opening most recent chain...'))
        ok2, result = _api('GET', '/api/search?limit=1', key=api_key)
        if ok2:
            commits = result.get('results', [])
            if commits:
                target = commits[0].get('id')
                p(f'  {C(target)}')
            else:
                blank()
                p(DIM('  No chains found yet.'))
                blank()
                p(B('Create your first one:'))
                p(f'  darkmatter quickstart single')
                blank(); return

    if not target:
        # Fallback to dashboard
        url = BASE + '/dashboard'
        p(f'  Opening dashboard: {C(url)}')
        webbrowser.open(url)
        blank(); return

    # Create share link
    url = BASE + '/dashboard'
    if target.startswith('ctx_') and api_key:
        ok2, result = _api('POST', f'/api/share/{target}',
                           {'label': 'opened from CLI'}, key=api_key)
        if ok2:
            url = result.get('shareUrl', BASE + '/dashboard')
    elif target.startswith('share_'):
        url = f'{BASE}/chain/{target}'

    p(f'  Opening: {C(url)}')
    webbrowser.open(url)
    ok('Opened in browser')
    blank()


# ─────────────────────────────────────────────────────────────────────────────
# darkmatter doctor
# ─────────────────────────────────────────────────────────────────────────────

def cmd_doctor(args):
    blank()
    p(B(V('DarkMatter')) + '  doctor')
    blank()
    p(DIM('Checking local setup...'))

    failures = []

    # Environment
    blank(); p(B('Environment'))
    env_path = os.path.join(os.getcwd(), '.env')
    if os.path.exists(env_path): ok('.env file found')
    else: fail('.env file not found'); failures.append('env')

    api_key  = _key()
    agent_id = _agent()

    if api_key: ok('DARKMATTER_API_KEY present')
    else: fail('DARKMATTER_API_KEY missing'); failures.append('api_key')

    if agent_id: ok('DARKMATTER_AGENT_ID present')
    else: fail('DARKMATTER_AGENT_ID missing'); failures.append('agent_id')

    if failures:
        blank(); fix_hint('darkmatter init')
        blank(); _doctor_end(failures); return

    # Connectivity
    blank(); p(B('Connectivity'))
    ok2, _ = _api('GET', '/api/stats')
    if ok2: ok('DarkMatter server reachable')
    else:
        fail('Could not reach DarkMatter server'); failures.append('connectivity')
        blank()
        p(f'  {DIM("Fix")}')
        p(f'    Check your internet connection or try again in a moment.')
        p(f'    Status: {C(BASE)}')
        blank(); _doctor_end(failures); return

    # Auth
    blank(); p(B('Authentication'))
    ok2, result = _api('GET', '/api/me', key=api_key)
    if ok2:
        ok('API key accepted')
        auth_agent = result.get('agentId','')
        auth_name  = result.get('agentName','')
    else:
        fail('API key rejected'); failures.append('auth')
        blank(); fix_hint('darkmatter init')
        blank(); _doctor_end(failures); return

    # Agent
    blank(); p(B('Agent'))
    if auth_name: ok(f'Agent exists  ({auth_name})')
    else: fail('Agent not found'); failures.append('agent')
    if agent_id and auth_agent == agent_id: ok('Agent ID matches API key')
    elif agent_id and auth_agent != agent_id:
        warn(f'Agent ID mismatch (env: {agent_id[:12]}…, key: {auth_agent[:12]}…)')

    if 'agent' in failures:
        blank(); fix_hint('darkmatter init')
        blank(); _doctor_end(failures); return

    # Test commit
    blank(); p(B('Test commit'))
    target = agent_id or auth_agent
    ok2, result = _api('POST', '/api/commit',
                       {'toAgentId': target, 'payload': {'output': 'doctor test'},
                        'eventType': 'commit'}, key=api_key)
    if ok2:
        ctx_id = result.get('id','')
        ok('Test commit succeeded')
        p(f'    Context ID: {C(ctx_id)}')
    else:
        fail(f'Commit failed: {result}'); failures.append('commit')
        blank(); fix_hint('darkmatter init')
        blank(); _doctor_end(failures); return

    # Verify
    blank(); p(B('Verify'))
    ok2, result = _api('GET', f'/api/verify/{ctx_id}', key=api_key)
    if ok2 and result.get('chain_intact'): ok('Chain intact')
    else:
        fail('Chain verify failed'); failures.append('verify')
        blank()
        p(f'  {DIM("Fix")}')
        p(f'    Retry the command. If this keeps happening:')
        p(f'    {C(BASE + "/docs")}')

    blank()
    _doctor_end(failures)


def _doctor_end(failures):
    sep()
    if not failures:
        blank()
        p(f'{SYM_OK}{B(" You\'re ready.")}')
        blank()
        p(B('Next'))
        p(f'  darkmatter quickstart single')
    else:
        blank()
        p(f'  {R(str(len(failures)) + " check(s) failed")}')
        blank()
        p(B('Recommended next step'))
        p(f'  darkmatter init')
    blank()



# ─────────────────────────────────────────────────────────────────────────────
# darkmatter keys — L3 signing key management
# ─────────────────────────────────────────────────────────────────────────────

def _gen_ed25519():
    """Generate Ed25519 keypair using Python stdlib only (no external deps)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        priv = Ed25519PrivateKey.generate()
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pub = priv.public_key()
        pub_pem = pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_raw = pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        import base64
        pub_b64 = base64.urlsafe_b64encode(pub_raw).rstrip(b'=').decode()
        return priv_pem, pub_pem, pub_b64
    except ImportError:
        fail('cryptography package required for key generation.')
        p(f'  {DIM("Fix: pip install cryptography")}')
        sys.exit(1)


def _pub_pem_to_b64(pub_pem_path):
    """Read a public key PEM file and return base64url of raw 32-byte key."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        import base64
        data = open(pub_pem_path, 'rb').read()
        pub  = serialization.load_pem_public_key(data)
        raw  = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()
    except ImportError:
        fail('cryptography package required.')
        p(f'  {DIM("Fix: pip install cryptography")}')
        sys.exit(1)
    except Exception as e:
        fail(f'Could not read public key: {e}')
        sys.exit(1)


def _flag(args, *names, default=None):
    """Extract --flag value from args list."""
    for i, a in enumerate(args):
        if a in names and i + 1 < len(args):
            return args[i + 1]
    return default


def cmd_keys(args):
    import os, stat

    sub = args[0] if args else 'help'

    # ── generate ──────────────────────────────────────────────────────────────
    if sub in ('generate', 'gen', 'g'):
        name    = _flag(args, '--name', '-n') or 'my-signing-key'
        out_dir = _flag(args, '--out',  '-o') or os.getcwd()
        blank()
        p(B(V('DarkMatter')) + '  keys generate')
        blank()
        sep()
        p('  Generating Ed25519 keypair...', delay=0.2)

        safe     = name.replace(' ', '-').lower()
        priv_path = os.path.join(out_dir, f'{safe}.pem')
        pub_path  = os.path.join(out_dir, f'{safe}.pub.pem')

        os.makedirs(out_dir, exist_ok=True)
        priv_pem, pub_pem, pub_b64 = _gen_ed25519()

        open(priv_path, 'wb').write(priv_pem)
        open(pub_path,  'wb').write(pub_pem)
        try:    os.chmod(priv_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        except: pass

        blank()
        ok('Keypair generated')
        blank()
        p(f'  {B("Name:")}        {name}')
        p(f'  {B("Private:")}     {priv_path}')
        p(f'  {DIM("               ← Keep secret. Never share or commit.")}')
        p(f'  {B("Public:")}      {pub_path}')
        blank()
        sep()
        blank()
        p(B('Next'))
        blank()
        p('  Register this key:')
        blank()
        p(DIM(f'  darkmatter keys register \\'))
        p(DIM(f'    --key-id {safe} \\'))
        p(DIM(f'    --public-key {pub_path}'))
        blank()
        p('  Then add to your .env:')
        blank()
        p(DIM('  DARKMATTER_SIGNING_MODE=customer'))
        p(DIM(f'  DARKMATTER_SIGNING_KEY_ID={safe}'))
        p(DIM(f'  DARKMATTER_SIGNING_KEY_PATH={priv_path}'))
        blank()

    # ── register ──────────────────────────────────────────────────────────────
    elif sub in ('register', 'reg', 'r'):
        key_id  = _flag(args, '--key-id',     '-k')
        pub_key = _flag(args, '--public-key', '-p')
        desc    = _flag(args, '--description', '-d') or ''
        api_key = _key()

        blank()
        p(B(V('DarkMatter')) + '  keys register')
        blank()

        if not api_key:
            fail('No API key found. Set DARKMATTER_API_KEY in your .env')
            sys.exit(1)
        if not key_id:
            fail('--key-id required')
            p(f'  {DIM("Example: darkmatter keys register --key-id my-key --public-key my-key.pub.pem")}')
            sys.exit(1)
        if not pub_key:
            fail('--public-key required (path to .pub.pem file)')
            sys.exit(1)
        if not os.path.exists(pub_key):
            fail(f'File not found: {pub_key}')
            sys.exit(1)

        sep()
        p(f'  Registering {B(key_id)} with DarkMatter...', delay=0.3)

        pub_b64 = _pub_pem_to_b64(pub_key)
        body    = {'key_id': key_id, 'public_key': pub_b64, 'algorithm': 'Ed25519'}
        if desc: body['description'] = desc

        ok2, result = _api('POST', '/api/signing-keys', body, key=api_key)

        if ok2:
            blank()
            ok('Key registered')
            blank()
            p(f'  {B("Key ID:")}    {result.get("key_id", key_id)}')
            p(f'  {B("Algorithm:")} {result.get("algorithm", "Ed25519")}')
            p(f'  {B("Status:")}    {G(result.get("status", "active"))}')
            blank()
            sep()
            blank()
            p(B('L3 signing is ready'))
            blank()
            p('  Your commits will now include a customer signature.')
            p('  DarkMatter cannot forge records signed with your key.')
            blank()
            p(DIM('  Make sure your .env includes:'))
            p(DIM('  DARKMATTER_SIGNING_MODE=customer'))
            p(DIM(f'  DARKMATTER_SIGNING_KEY_ID={key_id}'))
            blank()
        else:
            fail(f'Registration failed: {result}')
            sys.exit(1)

    # ── list ──────────────────────────────────────────────────────────────────
    elif sub in ('list', 'ls', 'l'):
        api_key = _key()
        blank()
        p(B(V('DarkMatter')) + '  keys list')
        blank()

        if not api_key:
            fail('No API key found. Set DARKMATTER_API_KEY in your .env')
            sys.exit(1)

        ok2, result = _api('GET', '/api/signing-keys', key=api_key)
        if not ok2:
            fail(f'Failed: {result}'); sys.exit(1)

        keys = result.get('keys', [])
        if not keys:
            p(DIM('  No signing keys registered.'))
            blank()
            p(f'  Generate one: {DIM("darkmatter keys generate --name my-key")}')
            blank()
            return

        sep()
        for k in keys:
            status = G('active') if k.get('status') == 'active' else R('revoked')
            blank()
            p(f'  {B(k["key_id"])}')
            p(f'  {DIM("Algorithm:")} {k.get("algorithm","Ed25519")}')
            p(f'  {DIM("Status:")}    {status}')
            p(f'  {DIM("Created:")}   {(k.get("created_at") or "")[:10]}')
            if k.get('description'): p(f'  {DIM("Note:")}      {k["description"]}')
            if k.get('revoked_at'):  p(f'  {DIM("Revoked:")}   {k["revoked_at"][:10]}')
        blank()
        sep()
        blank()

    # ── revoke ────────────────────────────────────────────────────────────────
    elif sub in ('revoke', 'rm', 'delete'):
        key_id  = _flag(args, '--key-id', '-k')
        api_key = _key()

        blank()
        p(B(V('DarkMatter')) + '  keys revoke')
        blank()

        if not api_key:
            fail('No API key found.'); sys.exit(1)
        if not key_id:
            fail('--key-id required')
            p(DIM('  Example: darkmatter keys revoke --key-id my-key'))
            sys.exit(1)

        sep()
        warn(f'Revoking {B(key_id)}...')
        p(DIM('  Existing L3 records keep their original signature.'), delay=0.3)

        from urllib import request as _r, error as _e
        import json as _json
        url = BASE + f'/api/signing-keys/{key_id}'
        req = _r.Request(url, headers={
            'Authorization': f'Bearer {api_key}',
            'User-Agent': 'darkmatter-cli/1.3',
        }, method='DELETE')
        try:
            with _r.urlopen(req, timeout=12) as resp:
                ok2, result = True, _json.loads(resp.read())
        except _e.HTTPError as e:
            try: msg = _json.loads(e.read()).get('error', f'HTTP {e.code}')
            except: msg = f'HTTP {e.code}'
            ok2, result = False, msg

        if ok2:
            blank()
            ok(f'{B(key_id)} revoked')
            p(DIM('  New commits using this key_id will be rejected.'))
            p(DIM('  To rotate: generate a new key and register it.'))
            blank()
        else:
            fail(f'Failed: {result}'); sys.exit(1)

    # ── help ──────────────────────────────────────────────────────────────────
    else:
        blank()
        p(B(V('DarkMatter')) + '  keys')
        blank()
        p('Manage signing keys for L3 non-repudiation.')
        p('With L3, every commit is signed with a key only you hold.')
        p('DarkMatter cannot forge your records.')
        blank()
        p(B('Commands'))
        blank()
        p('  generate   Generate an Ed25519 keypair')
        p('  register   Register your public key with DarkMatter')
        p('  list       List all registered keys')
        p('  revoke     Revoke a key (existing records unaffected)')
        blank()
        p(B('L3 setup (one time)'))
        blank()
        p(DIM('  darkmatter keys generate --name prod-key'))
        p(DIM('  darkmatter keys register --key-id prod-key --public-key prod-key.pub.pem'))
        p(DIM('  # Add to .env:'))
        p(DIM('  DARKMATTER_SIGNING_MODE=customer'))
        p(DIM('  DARKMATTER_SIGNING_KEY_ID=prod-key'))
        p(DIM('  DARKMATTER_SIGNING_KEY_PATH=./prod-key.pem'))
        blank()
        p(f'  Docs: {C(BASE + "/docs#l3-setup")}')
        blank()


# ─────────────────────────────────────────────────────────────────────────────
# main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    args = [a for a in sys.argv[1:] if a != '--plain']

    dispatch = {
        'demo':       lambda: cmd_demo(),
        'init':       lambda: cmd_init(args[1:]),
        'quickstart': lambda: cmd_quickstart(args[1:]),
        'replay':     lambda: cmd_replay(args[1:]),
        'fork':       lambda: cmd_fork(args[1:]),
        'diff':       lambda: cmd_diff(args[1:]),
        'recent':     lambda: cmd_recent(args[1:]),
        'open':       lambda: cmd_open(args[1:]),
        'doctor':     lambda: cmd_doctor(args[1:]),
        'keys':       lambda: cmd_keys(args[1:]),
    }

    if not args:
        cmd_demo(); return

    cmd = args[0]

    if cmd in dispatch:
        dispatch[cmd](); return

    if cmd in ('--help', '-h', 'help'):
        print()
        print('DarkMatter CLI')
        print()
        print('Commands:')
        print('  demo                   Run local demo — no signup required')
        print('  init                   Create account + agent, write .env')
        print('  quickstart [variant]   Generate a runnable starter example')
        print('  replay <ctx_id>        Walk a chain step by step')
        print('  fork <ctx_id>          Branch from any checkpoint')
        print('  diff <ctxA> <ctxB>     Compare two chains')
        print('  recent                 Show your latest chains')
        print('  open [ctx_id]          Open a chain in the browser')
        print('  doctor                 Check your setup')
        print('  keys generate/register/list/revoke')
        print('                         Manage L3 signing keys')
        print()
        print('Flags:')
        print('  replay  --from <step>  --full  --open')
        print('  fork    --from <step>  --model <model>  --open')
        print('  diff    --full  --step <n>  --model-only')
        print('  recent  --limit <n>  --json')
        print('  init    --email  --agent  --no-test')
        print('  All:    --plain  (no color or Unicode)')
        print()
        print('Quickstart variants:  single  openai  anthropic  langgraph')
        print()
        print('Onboarding flow:')
        print('  1. darkmatter demo')
        print('  2. darkmatter init')
        print('  3. darkmatter quickstart single')
        print('  4. python darkmatter_example.py')
        print('  5. darkmatter open')
        print('  6. darkmatter doctor')
        print()
        print(f'Docs: {BASE}/docs')
        return

    if cmd in ('--version', '-v', 'version'):
        try:
            from darkmatter import __version__
            print(f'darkmatter-sdk {__version__}')
        except Exception:
            print('darkmatter-sdk 1.3.0')
        return

    print(f'Unknown command: {cmd}')
    print("Run 'darkmatter --help' for usage")
    sys.exit(1)


if __name__ == '__main__':
    main()
