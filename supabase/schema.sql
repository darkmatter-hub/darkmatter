-- ═══════════════════════════════════════════════════
-- DarkMatter — Supabase Schema v2
-- STEP 1: Drop existing tables (clears old structure)
-- STEP 2: Recreate with correct schema
-- ═══════════════════════════════════════════════════

-- Drop in correct order (commits references agents)
drop table if exists commits cascade;
drop table if exists agents  cascade;

-- Drop old function if exists
drop function if exists get_agent_by_api_key(text);

-- ── Agents ──────────────────────────────────────────
create table agents (
  agent_id    text primary key,
  agent_name  text not null,
  user_id     uuid references auth.users(id) on delete cascade,
  api_key     text unique not null,
  public_key  text,
  created_at  timestamptz default now(),
  last_active timestamptz
);

-- ── Commits ─────────────────────────────────────────
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

-- ── Indexes ─────────────────────────────────────────
create index commits_to_agent_idx
  on commits(to_agent, verified, timestamp desc);

create index agents_user_idx    on agents(user_id);
create index agents_api_key_idx on agents(api_key);

-- ── Row Level Security ───────────────────────────────
alter table agents  enable row level security;
alter table commits enable row level security;

create policy "users manage own agents"
  on agents for all
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "users see own commits"
  on commits for select
  using (
    from_agent in (select agent_id from agents where user_id = auth.uid())
    or
    to_agent   in (select agent_id from agents where user_id = auth.uid())
  );

create policy "service can insert commits"
  on commits for insert
  with check (true);

-- ── Helper: look up agent by API key ────────────────
create function get_agent_by_api_key(p_api_key text)
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

-- ═══════════════════════════════════════════════════
-- DarkMatter — Schema v3 additions
-- Run these in Supabase SQL Editor (do NOT drop existing tables)
-- ═══════════════════════════════════════════════════

-- ── Add webhook + retention columns to agents ───────
alter table agents
  add column if not exists webhook_url       text,
  add column if not exists webhook_secret    text,
  add column if not exists retention_days    integer default null;
-- retention_days null = keep forever

-- ── Webhooks delivery log ────────────────────────────
create table if not exists webhook_deliveries (
  id           text primary key,
  agent_id     text references agents(agent_id) on delete cascade,
  commit_id    text references commits(id)      on delete cascade,
  webhook_url  text not null,
  status       text not null,  -- 'delivered' | 'failed'
  http_status  integer,
  response     text,
  attempted_at timestamptz default now()
);

create index if not exists webhook_deliveries_agent_idx
  on webhook_deliveries(agent_id, attempted_at desc);

alter table webhook_deliveries enable row level security;

create policy "users see own webhook deliveries"
  on webhook_deliveries for select
  using (
    agent_id in (select agent_id from agents where user_id = auth.uid())
  );

create policy "service can insert webhook deliveries"
  on webhook_deliveries for insert
  with check (true);

-- ═══════════════════════════════════════════════════
-- DarkMatter — Schema v4: Context lineage + integrity
-- Run in Supabase SQL Editor (additive, no drops)
-- ═══════════════════════════════════════════════════

alter table commits
  add column if not exists schema_version  text    default '1.0',
  add column if not exists payload         jsonb,
  add column if not exists event_type      text    default 'commit',
  add column if not exists parent_id       text    references commits(id),
  add column if not exists trace_id        text,
  add column if not exists branch_key      text    default 'main',
  add column if not exists agent_info      jsonb,
  add column if not exists integrity_hash  text,
  add column if not exists parent_hash     text;

-- Indexes for lineage traversal
create index if not exists commits_parent_id_idx  on commits(parent_id);
create index if not exists commits_trace_id_idx   on commits(trace_id);
create index if not exists commits_branch_key_idx on commits(branch_key);
create index if not exists commits_integrity_idx  on commits(integrity_hash);
