# 🌑 DarkMatter — Production Deployment

> From prototype to live production in under 30 minutes. Free tier the whole way.

---

## The Stack

| Layer | Service | Cost | Why |
|-------|---------|------|-----|
| Server | Railway or Render | Free tier | One-click deploy from GitHub |
| Database | Supabase | Free tier (500MB) | Postgres + instant API |
| Code | GitHub | Free | Source of truth, triggers deploys |

Everything connects automatically. You push to GitHub → Railway/Render deploys → Supabase stores data. You never touch a server.

---

## Part 1 — Supabase (Database)

### 1.1 Create your project

1. Go to [supabase.com](https://supabase.com) → **Start your project**
2. Sign in with GitHub
3. Click **New Project**
4. Give it a name: `darkmatter`
5. Set a database password — save it somewhere safe
6. Choose a region closest to your users
7. Click **Create new project** — takes about 2 minutes

### 1.2 Create the tables

Once your project is ready, click **SQL Editor** in the left sidebar and run this:

```sql
-- Agents: one row per registered agent
create table agents (
  agent_id      text primary key,
  agent_name    text not null,
  public_key    text not null,
  registered_at timestamptz default now()
);

-- Commits: every signed context handoff
create table commits (
  id                   text primary key,
  from_agent           text references agents(agent_id),
  to_agent             text references agents(agent_id),
  context              jsonb,
  signature            text,
  verified             boolean default false,
  verification_reason  text,
  timestamp            timestamptz,
  saved_at             timestamptz default now()
);

-- Index for fast agent pulls
create index commits_to_agent_idx on commits(to_agent, verified, timestamp desc);
```

Click **Run**. You should see "Success. No rows returned."

### 1.3 Get your API credentials

1. In the left sidebar → **Settings** → **API**
2. Copy two values:
   - **Project URL** — looks like `https://abcdefgh.supabase.co`
   - **anon / public key** — a long JWT string

You'll need these in the next step.

---

## Part 2 — Railway (Recommended)

Railway is the fastest path to production. Deploys automatically every time you push to GitHub.

### 2.1 Push DarkMatter to GitHub

If you haven't already:

```bash
cd darkmatter
git init
git add .
git commit -m "Initial DarkMatter prototype"
# Create a new repo on github.com, then:
git remote add origin https://github.com/yourusername/darkmatter
git push -u origin main
```

### 2.2 Deploy on Railway

1. Go to [railway.app](https://railway.app) → **Start a New Project**
2. Click **Deploy from GitHub repo**
3. Select your `darkmatter` repo
4. Railway auto-detects Node.js and starts deploying

### 2.3 Add environment variables

In Railway's dashboard → your service → **Variables** tab → **Add Variable**:

```
SUPABASE_URL    =  https://yourproject.supabase.co
SUPABASE_KEY    =  your-anon-key-here
PORT            =  3000
```

### 2.4 Switch to Supabase storage

In your local project:

```bash
# Replace in-memory store with Supabase store
cp src/lib/store.supabase.js src/lib/store.js
npm install @supabase/supabase-js dotenv
git add .
git commit -m "Switch to Supabase production storage"
git push
```

Railway detects the push and redeploys automatically. Done.

### 2.5 Get your live URL

Railway gives you a URL like `https://darkmatter-production.up.railway.app`

That's your DarkMatter endpoint. Any agent anywhere can now call it.

---

## Part 3 — Render (Alternative)

If you prefer Render over Railway — same result, slightly different steps.

### 3.1 Create a Web Service

1. Go to [render.com](https://render.com) → **New** → **Web Service**
2. Connect your GitHub repo
3. Configure:
   - **Name:** `darkmatter`
   - **Runtime:** Node
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
4. Click **Create Web Service**

### 3.2 Add environment variables

In Render → your service → **Environment** tab:

```
SUPABASE_URL    =  https://yourproject.supabase.co
SUPABASE_KEY    =  your-anon-key-here
PORT            =  10000
```

> Render uses port 10000 by default — set PORT to match.

### 3.3 Switch to Supabase storage (same as Railway)

```bash
cp src/lib/store.supabase.js src/lib/store.js
npm install @supabase/supabase-js dotenv
git add .
git commit -m "Switch to Supabase production storage"
git push
```

Render redeploys automatically on push.

---

## Part 4 — Verify Everything Works

Once deployed, run a quick smoke test from your terminal:

```bash
# Replace with your actual Railway/Render URL
export DM=https://darkmatter-production.up.railway.app

# Register an agent
curl -X POST $DM/api/register \
  -H "Content-Type: application/json" \
  -d '{ "agentName": "Test Agent" }'

# Should return agentId + publicKey
# Check Supabase → Table Editor → agents — row should appear
```

If the row appears in Supabase, your full stack is working.

---

## Part 5 — Your Development Workflow

This is how adding a feature or fixing a bug looks from your perspective day to day.

### The Setup (one time)

```
GitHub repo
    │
    ├── Railway/Render (auto-deploys on push to main)
    │
    └── Supabase (production database, always running)
```

### Your local environment

```bash
# .env file (never committed to git)
SUPABASE_URL=https://yourproject.supabase.co
SUPABASE_KEY=your-anon-key
PORT=3000
```

You can point your local server at the real Supabase database during development. Or create a second Supabase project called `darkmatter-dev` for a clean local sandbox.

---

### Day-to-day workflow

**Working on a new feature:**

```bash
# 1. Create a feature branch
git checkout -b feature/agent-reputation

# 2. Vibe code with Claude — iterate locally
npm start
# test at http://localhost:3000

# 3. When it works locally, push
git add .
git commit -m "Add agent reputation endpoint"
git push origin feature/agent-reputation

# 4. Open a Pull Request on GitHub
# Review the diff, make sure it looks right

# 5. Merge to main
git checkout main
git merge feature/agent-reputation
git push origin main

# → Railway/Render automatically deploys within 1-2 minutes
# → Your live URL is updated
```

**Quick bug fix:**

```bash
git checkout -b fix/verify-timeout
# fix the thing
git add . && git commit -m "Fix: extend verify timeout to 10min"
git push origin fix/verify-timeout
# merge to main → auto-deploys
```

**Checking what's live:**

```bash
# Railway: check dashboard → Deployments tab
# Or watch logs in real time:
railway logs

# Render: check dashboard → Logs tab
```

---

### The deploy is always automatic

Once this is set up, your entire deploy process is:

```
1. Write code locally
2. Test locally (npm start)
3. git push
4. Done — live in ~90 seconds
```

You never SSH into a server. You never run a deploy command. You never restart anything. Push to main = live.

---

### If something breaks in production

```bash
# Option 1: Quick fix and push
git checkout -b hotfix/broken-endpoint
# fix it
git push → merge → auto-deploys

# Option 2: Roll back to previous version
# Railway: dashboard → Deployments → click any previous deploy → Redeploy
# Render: dashboard → Events → Rollback
```

One click to roll back. No data loss — Supabase is unaffected by server rollbacks.

---

### When you want a staging environment

Once you have real users, you'll want to test changes before they hit production:

```
Branches:
  main        → production  (Railway/Render auto-deploy)
  staging     → staging URL (second Railway/Render service)
  feature/*   → local only
```

Set up a second Railway service pointing at your `staging` branch. Push features to `staging` first, verify, then merge to `main`.

---

## Summary

| Action | What you do | What happens automatically |
|--------|-------------|---------------------------|
| Add a feature | `git push` | Railway/Render redeploys |
| Fix a bug | `git push` | Railway/Render redeploys |
| Roll back | Click in Railway/Render | Previous version goes live |
| Scale up | Upgrade Railway/Render plan | More resources, zero config |
| Database grows | Nothing | Supabase handles it |

The entire system is designed so you spend time writing code, not managing infrastructure.

---

## Free Tier Limits (for reference)

| Service | Free tier | When you'll hit it |
|---------|-----------|-------------------|
| Railway | $5 credit/month | ~500 hours of server time |
| Render | 750 hours/month | Enough for one always-on service |
| Supabase | 500MB storage, 2GB bandwidth | Thousands of agents and commits |

You won't hit any of these limits during the prototype and early traction phase. Upgrade when you have users that justify it.
