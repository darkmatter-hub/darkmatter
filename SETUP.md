# 🌑 DarkMatter — Local Development Setup

> Run DarkMatter on your own machine for development or testing.

---

## Prerequisites

- Node.js 18+
- A Supabase account (free tier is fine)
- npm

---

## Step 1 — Clone and install

```bash
git clone https://github.com/darkmatter-hub/darkmatter
cd darkmatter
npm install
```

---

## Step 2 — Create a Supabase project

1. Go to [supabase.com](https://supabase.com) → New Project
2. Name it `darkmatter-dev`
3. Go to **SQL Editor** and run the contents of `supabase/schema.sql`
4. Go to **Settings → API** and copy:
   - **Project URL** → `SUPABASE_URL`
   - **anon/public key** → `SUPABASE_KEY`
   - **service_role key** → `SUPABASE_SERVICE_KEY`

---

## Step 3 — Configure environment

```bash
cp .env.example .env
```

Edit `.env`:

```
SUPABASE_URL=https://yourproject.supabase.co
SUPABASE_KEY=your-anon-key
SUPABASE_SERVICE_KEY=your-service-role-key
APP_URL=http://localhost:3000
PORT=3000
```

---

## Step 4 — Start the server

```bash
npm start
```

Open [http://localhost:3000](http://localhost:3000)

---

## Step 5 — Create an account and test

1. Go to `http://localhost:3000/signup`
2. Create an account
3. Create an agent from the dashboard
4. Copy the API key and test:

```bash
# Commit context
curl -X POST http://localhost:3000/api/commit \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"toAgentId":"dm_...","context":{"task":"test"}}'

# Pull context
curl http://localhost:3000/api/pull \
  -H "Authorization: Bearer YOUR_KEY"
```

---

## Development workflow

```bash
# Auto-restart on file changes
npm run dev

# Push changes to production
git add .
git commit -m "your change"
git push  # Railway auto-deploys
```

---

## Running the Claude → GPT example locally

```bash
pip install anthropic openai requests

# Edit the API keys in each file first
python examples/claude-to-gpt/agent_xx.py
python examples/claude-to-gpt/agent_yy.py
```
