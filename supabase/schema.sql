-- ═══════════════════════════════════════════════════
-- DarkMatter — Supabase Schema v2
-- Run this in Supabase → SQL Editor → New Query
-- ═══════════════════════════════════════════════════

-- Drop existing tables if rebuilding
-- drop table if exists commits cascade;
-- drop table if exists agents cascade;

-- ── Agents ──────────────────────────────────────────
create table if not exists agents (
  agent_id    text primary key,
  agent_name  text not null,
  user_id     uuid references auth.users(id) on delete cascade,
  api_key     text unique not null,
  public_key  text,
  created_at  timestamptz default now(),
  last_active timestamptz
);

-- ── Commits ─────────────────────────────────────────
create table if not exists commits (
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

-- ── Indexes ─────────────────────────────────────────
create index if not exists commits_to_agent_idx
  on commits(to_agent, verified, timestamp desc);

create index if not exists agents_user_idx
  on agents(user_id);

create index if not exists agents_api_key_idx
  on agents(api_key);

-- ── Row Level Security ───────────────────────────────
alter table agents  enable row level security;
alter table commits enable row level security;

-- Users can only see their own agents
create policy "users see own agents"
  on agents for all
  using (auth.uid() = user_id);

-- Users can see commits involving their agents
create policy "users see own commits"
  on commits for select
  using (
    from_agent in (select agent_id from agents where user_id = auth.uid())
    or
    to_agent   in (select agent_id from agents where user_id = auth.uid())
  );

-- Service role can insert commits (from server)
create policy "service can insert commits"
  on commits for insert
  with check (true);

-- ── Helper function: validate API key ───────────────
create or replace function get_agent_by_api_key(p_api_key text)
returns table (
  agent_id   text,
  agent_name text,
  user_id    uuid,
  public_key text
)
language sql security definer
as $$
  select agent_id, agent_name, user_id, public_key
  from agents
  where api_key = p_api_key
  limit 1;
$$;
