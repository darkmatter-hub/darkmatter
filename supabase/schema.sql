-- HISTORICAL SNAPSHOT, May 2026. Not the schema to install.
--
-- SETUP.md pointed here until 2026-08-29. It is missing 11 of the tables the
-- server needs, including log_entries, so the first commit fails. Use
-- schema_full.sql. This file is kept only to show what the schema looked like.
--
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

-- ═══════════════════════════════════════════════════
-- DarkMatter — Schema v5: Fork lineage fields
-- Run in Supabase SQL Editor (additive)
-- ═══════════════════════════════════════════════════

alter table commits
  add column if not exists fork_of      text references commits(id),
  add column if not exists fork_point   text references commits(id),
  add column if not exists lineage_root text references commits(id);
-- fork_of:      original ctx_id this was forked from
-- fork_point:   checkpoint ctx_id where the fork began
-- lineage_root: root ctx_id of the entire graph (original root)

create index if not exists commits_fork_of_idx      on commits(fork_of);
create index if not exists commits_lineage_root_idx on commits(lineage_root);

-- ═══════════════════════════════════════════════════
-- DarkMatter — Schema v6: Enterprise features
-- Run in Supabase SQL Editor (additive)
-- ═══════════════════════════════════════════════════

-- Enterprise accounts table
create table if not exists enterprise_accounts (
  id              text primary key,
  user_id         uuid references auth.users(id) on delete cascade,
  company_name    text not null,
  plan            text default 'enterprise',   -- 'pro' | 'enterprise'
  byok_key_id     text,                        -- identifier for their encryption key
  byok_algorithm  text default 'aes-256-gcm',
  tenant_schema   text,                        -- isolated schema name if dedicated
  did_document    jsonb,                       -- W3C DID document for this account
  created_at      timestamptz default now(),
  active          boolean default true
);

-- Add enterprise fields to agents table
alter table agents
  add column if not exists did_id          text,        -- W3C DID identifier
  add column if not exists did_public_key  text,        -- DID verification key
  add column if not exists encrypted       boolean default false,
  add column if not exists key_id          text;        -- reference to enterprise key

-- Add encryption fields to commits table
alter table commits
  add column if not exists encrypted_payload  text,     -- AES-256-GCM encrypted blob
  add column if not exists key_id             text,     -- key used for encryption
  add column if not exists iv                 text,     -- initialization vector
  add column if not exists auth_tag           text,     -- GCM auth tag
  add column if not exists did_signature      text;     -- DID signature on payload hash

-- Enterprise keys table (stores key metadata, never the actual key)
create table if not exists enterprise_keys (
  key_id          text primary key,
  account_id      text references enterprise_accounts(id) on delete cascade,
  key_hint        text,           -- last 4 chars of key for identification
  algorithm       text default 'aes-256-gcm',
  created_at      timestamptz default now(),
  rotated_at      timestamptz,
  active          boolean default true
);

-- Enterprise inquiries (self-serve form)
create table if not exists enterprise_inquiries (
  id              text primary key,
  company_name    text,
  name            text,
  email           text not null,
  use_case        text,
  team_size       text,
  features        text[],         -- ['byok','did','dedicated','compliance']
  message         text,
  created_at      timestamptz default now(),
  contacted       boolean default false
);

-- Indexes
create index if not exists enterprise_accounts_user_idx on enterprise_accounts(user_id);
create index if not exists enterprise_keys_account_idx  on enterprise_keys(account_id);
create index if not exists commits_key_id_idx           on commits(key_id);

-- RLS
alter table enterprise_accounts  enable row level security;
alter table enterprise_keys       enable row level security;
alter table enterprise_inquiries  enable row level security;

create policy "users see own enterprise account"
  on enterprise_accounts for all
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "service manages enterprise keys"
  on enterprise_keys for all using (true) with check (true);

create policy "service manages inquiries"
  on enterprise_inquiries for insert with check (true);

-- ═══════════════════════════════════════════════════
-- Schema v7: payload_hash column (fixes integrity naming)
-- Run in Supabase SQL Editor
-- ═══════════════════════════════════════════════════

-- Add payload_hash column to store sha256(normalize(payload)) separately from integrity_hash
alter table commits
  add column if not exists payload_hash text;  -- sha256(normalize(payload)), stored without sha256: prefix

-- Index for future integrity auditing queries
create index if not exists commits_payload_hash_idx on commits(payload_hash);

-- Note: existing commits will have payload_hash = null
-- They remain valid — payload_hash is optional in buildContext
-- New commits from this version onward will have it populated

-- ═══════════════════════════════════════════════════
-- Schema v8: Shared chain links + event hooks
-- Run in Supabase SQL Editor
-- ═══════════════════════════════════════════════════

-- Shared read-only chain links
create table if not exists shared_chains (
  id           text primary key,          -- share_xxxxxxxxxxxxx
  ctx_id       text not null,             -- tip context ID
  created_by   text references agents(agent_id),
  label        text,                      -- optional human label
  expires_at   timestamptz,               -- null = never
  view_count   integer default 0,
  created_at   timestamptz default now()
);
create index if not exists shared_chains_ctx_idx on shared_chains(ctx_id);
create index if not exists shared_chains_agent_idx on shared_chains(created_by);

-- Event hooks (post-commit, post-fork, verify-fail)
create table if not exists event_hooks (
  id           text primary key,          -- hook_xxxxxxxxxxxxx
  agent_id     text references agents(agent_id) on delete cascade,
  url          text not null,
  secret       text,
  events       text[] not null,           -- ['commit','fork','verify_fail']
  enabled      boolean default true,
  created_at   timestamptz default now(),
  last_fired   timestamptz,
  failure_count integer default 0
);
create index if not exists event_hooks_agent_idx on event_hooks(agent_id, enabled);

-- Hook delivery log
create table if not exists hook_deliveries (
  id           text primary key,
  hook_id      text references event_hooks(id) on delete cascade,
  event        text not null,
  ctx_id       text,
  status       text,                      -- delivered | failed | skipped
  http_status  integer,
  response     text,
  duration_ms  integer,
  attempted_at timestamptz default now()
);
create index if not exists hook_deliveries_hook_idx on hook_deliveries(hook_id, attempted_at desc);

-- Activation events (track the funnel)
create table if not exists activation_events (
  id           text primary key,
  user_id      uuid references auth.users(id) on delete cascade,
  event        text not null,             -- demo_run|key_created|first_commit|first_replay|first_fork|first_diff|day2_return
  metadata     jsonb,
  occurred_at  timestamptz default now()
);
create index if not exists activation_events_user_idx on activation_events(user_id, event);

-- ═══════════════════════════════════════════════════
-- Schema v9: Slack webhook support + provision
-- Run in Supabase SQL Editor
-- ═══════════════════════════════════════════════════

-- Add slack_channel column to agents (optional label for Slack notifications)
alter table agents
  add column if not exists slack_channel text;

-- Index for provision lookups (email → user already handled by auth.users)
-- No additional tables needed — provision uses auth.admin API + agents table


-- ═══════════════════════════════════════════════════
-- Schema v10: Projects/workspaces + bookmarks
-- Run in Supabase SQL Editor when ready to build team features
-- ═══════════════════════════════════════════════════

-- Projects / workspaces (team adoption layer)
create table if not exists projects (
  id           text primary key,            -- proj_xxxxxxxx
  name         text not null,
  owner_id     uuid references auth.users(id) on delete cascade,
  slug         text unique,                 -- for URLs
  created_at   timestamptz default now()
);

-- Project members
create table if not exists project_members (
  project_id   text references projects(id) on delete cascade,
  user_id      uuid references auth.users(id) on delete cascade,
  role         text default 'member',       -- owner | admin | member
  joined_at    timestamptz default now(),
  primary key (project_id, user_id)
);

-- Saved/bookmarked chains
create table if not exists saved_chains (
  id           text primary key,
  user_id      uuid references auth.users(id) on delete cascade,
  ctx_id       text not null,
  label        text,
  project_id   text references projects(id) on delete set null,
  saved_at     timestamptz default now()
);
create index if not exists saved_chains_user_idx on saved_chains(user_id, saved_at desc);


-- ═══════════════════════════════════════════════════
-- Schema v11: Rich content storage
-- Separates large/binary content from chain metadata
-- Run when ready to support extension capture + rich responses
-- ═══════════════════════════════════════════════════

-- Content blobs — large text, HTML, images stored separately from chain metadata
-- The commits table keeps a small summary; full content lives here
create table if not exists commit_content (
  id            text primary key,            -- matches commits.id
  format        text not null default 'text', -- text | markdown | html | json
  text_content  text,                         -- full text (up to ~1GB in Postgres text col)
  html_content  text,                         -- rendered HTML version
  token_count   integer,                      -- estimated token count
  char_count    integer,                      -- character count
  has_images    boolean default false,
  has_code      boolean default false,
  has_tables    boolean default false,
  created_at    timestamptz default now()
);

-- Attachments — images, files, code blocks stored in object storage
create table if not exists commit_attachments (
  id            text primary key,            -- att_xxx
  commit_id     text references commits(id) on delete cascade,
  type          text not null,               -- image | code | file | audio | video | table | chart
  storage_provider text default 'supabase', -- supabase | s3 | r2 | gcs
  storage_bucket  text,
  storage_key     text,                      -- path in bucket
  public_url      text,                      -- CDN URL if public
  mime_type       text,
  size_bytes      integer,
  filename        text,
  language        text,                      -- for code blocks: python | js | sql | etc
  inline_content  text,                      -- for small content (<10KB): store inline
  position        integer,                   -- order within the response
  metadata        jsonb default '{}',
  created_at      timestamptz default now()
);
create index if not exists commit_attachments_commit_idx on commit_attachments(commit_id);

-- Conversation threads — for extension capture (browser sessions)
-- Groups commits into a conversation with metadata
create table if not exists conversation_threads (
  id              text primary key,            -- conv_xxx (from URL UUID)
  platform        text not null,               -- claude | chatgpt | grok | gemini | perplexity
  platform_url    text,                        -- original conversation URL
  title           text,                        -- extracted or user-set conversation title
  user_id         uuid references auth.users(id) on delete cascade,
  root_ctx_id     text,                        -- first commit in thread
  tip_ctx_id      text,                        -- most recent commit
  turn_count      integer default 0,
  models_used     text[],                      -- e.g. ['claude-opus-4-6', 'gpt-4o']
  total_tokens    integer default 0,
  created_at      timestamptz default now(),
  updated_at      timestamptz default now()
);
create index if not exists conv_threads_user_idx on conversation_threads(user_id, updated_at desc);
create index if not exists conv_threads_platform_idx on conversation_threads(platform);

-- RLS policies
alter table commit_content     enable row level security;
alter table commit_attachments enable row level security;
alter table conversation_threads enable row level security;

create policy "Users see own content" on commit_content
  for all using (
    id in (select c.id from commits c join agents a on c.agent_id=a.agent_id where a.user_id=auth.uid())
  );

create policy "Users see own attachments" on commit_attachments
  for all using (
    commit_id in (select c.id from commits c join agents a on c.agent_id=a.agent_id where a.user_id=auth.uid())
  );

create policy "Users see own threads" on conversation_threads
  for all using (user_id = auth.uid());


-- ═══════════════════════════════════════════════════
-- Schema v12: Agent policies
-- Policies evaluate commits before storage.
-- action = 'reject' | 'flag' | 'allow'
-- condition = JS-style expression string evaluated server-side
-- ═══════════════════════════════════════════════════
create table if not exists agent_policies (
  id          text primary key,
  agent_id    text not null references agents(agent_id) on delete cascade,
  name        text not null,
  description text,
  condition   text not null,       -- e.g. "!payload.model"
  action      text not null default 'flag', -- reject | flag | allow
  message     text,                -- returned to caller when policy fires
  enabled     boolean default true,
  created_at  timestamptz default now()
);
create index if not exists agent_policies_agent_idx on agent_policies(agent_id);
alter table agent_policies enable row level security;
create policy "Users manage own policies" on agent_policies
  for all using (
    agent_id in (select agent_id from agents where user_id = auth.uid())
  );

-- Schema v13: Rich content storage for conversation reconstruction
-- Run in Supabase SQL editor (no special characters)
-- This enables storing full LLM conversation turns with HTML, images, code
-- for complete audit reconstruction of user prompt + agent response

-- Add html_content and storage columns to commit_content if not present
alter table commit_content
  add column if not exists storage_provider text default 'inline',
  add column if not exists prompt_text      text,
  add column if not exists prompt_html      text;

-- Increase no limits on text columns (Postgres text is unbounded)
-- Nothing needed — text columns already unlimited

-- Add platform metadata to commits for faster filtering
alter table commits
  add column if not exists platform    text,
  add column if not exists conv_id     text,
  add column if not exists actor_role  text;

create index if not exists commits_platform_idx on commits(agent_id, platform);
create index if not exists commits_conv_idx     on commits(conv_id);

-- ── User API keys for BYOK recording (Claude Managed Agents, etc.) ────────
create table if not exists user_recording_keys (
  id              text primary key default 'urk_' || extract(epoch from now())::bigint || '_' || substr(md5(random()::text), 0, 8),
  user_id         uuid references auth.users(id) on delete cascade,
  provider        text not null,              -- 'anthropic' | 'openai' | 'google'
  key_hint        text not null,              -- last 4 chars, e.g. "sk-...a1b2"
  encrypted_key   text,                       -- AES-256 encrypted, user-provided BYOK encryption key
  recording_enabled boolean default true,
  label           text,                       -- optional user label
  created_at      timestamptz default now(),
  last_used_at    timestamptz
);

create index if not exists user_recording_keys_user_id on user_recording_keys(user_id);
alter table user_recording_keys enable row level security;
-- Authenticated users can manage their own keys
create policy "user_recording_keys_own" on user_recording_keys
  for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

-- Service role bypasses RLS for server-side operations
create policy "user_recording_keys_service" on user_recording_keys
  for all to service_role
  using (true) with check (true);

-- Add capture_mode column to commits (run once)
alter table commits add column if not exists capture_mode text
  check (capture_mode in ('client_signed','proxy_forwarded','proxy_stored'))
  default 'client_signed';
