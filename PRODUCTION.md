# 🌑 DarkMatter — Self-Hosting Guide

> Deploy DarkMatter inside your own infrastructure.
> Your agent context never leaves your network.

---

## Why self-host?

DarkMatter's hosted API at `darkmatterhub.ai` works for most developers and teams. But if your organization has strict data policies — financial services, healthcare, defense, enterprise — you can run DarkMatter entirely within your own infrastructure.

When self-hosted:
- Agent context never leaves your network
- You control the database
- You control authentication
- You can audit every line of code (MIT licensed, fully open source)

---

## What you need

- A server, VM, or cloud instance (any provider)
- Node.js 18+
- PostgreSQL (or a Supabase project on your own account)
- A domain or internal hostname

---

## Option A — Deploy on Railway (fastest)

1. Fork `https://github.com/darkmatter-hub/darkmatter` to your own GitHub account
2. Go to [railway.app](https://railway.app) → New Project → Deploy from your fork
3. Add environment variables (see below)
4. Railway gives you a private URL

---

## Option B — Deploy on any server

```bash
git clone https://github.com/darkmatter-hub/darkmatter
cd darkmatter
npm install
cp .env.example .env
# Edit .env with your values
npm start
```

Use a process manager for production:

```bash
npm install -g pm2
pm2 start src/server.js --name darkmatter
pm2 save
```

---

## Environment variables

See [.env.example](.env.example). It lists all twenty-six variables `src/`
reads, and a test fails if the two drift apart. This section used to carry its
own list of five, which is how a production deployment could run without
`DM_ENCRYPTION_KEY` and store webhook secrets in plaintext while the
enterprise page said they were encrypted.

The four that change behaviour by being absent rather than by being wrong:

| Variable | Unset means |
| --- | --- |
| `DM_ENCRYPTION_KEY` | webhook secrets and provider keys stored as `plain:<secret>` |
| `DM_LOG_SIGNING_KEY_PEM` | checkpoints signed with a key that dies on restart, so none are published |
| `SUPABASE_JWT_SECRET` | session tokens cannot be verified |
| `SUPERUSER_EMAIL` / `SUPERUSER_AGENT_ID` | nobody can reach the admin views or `/api/admin/*` |

---

## Database setup

Run `supabase/schema.sql` against any PostgreSQL instance.

If you prefer plain Postgres without Supabase, replace the Supabase client in `src/lib/store.supabase.js` with a standard `pg` client — the SQL schema is standard Postgres and requires no Supabase-specific features.

---

## Point your agents at your instance

Replace the base URL in your agent code:

```python
DM_URL = "https://your-internal-darkmatter.company.com"
```

Everything else — API keys, commit, pull — works identically.

---

## Security checklist for production

- [ ] `SUPABASE_SERVICE_KEY` is never exposed to the client or committed to git
- [ ] Run behind a reverse proxy (nginx, Caddy) with TLS
- [ ] Restrict `/api/agents` and `/api/commits` endpoints — they require `INTERNAL_API_KEY`
- [ ] Set up database backups
- [ ] Review Supabase Row Level Security policies in `schema.sql`
