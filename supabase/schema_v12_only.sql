-- Schema v12: Agent policies
-- Run this in Supabase SQL editor

create table if not exists agent_policies (
  id          text primary key,
  agent_id    text not null references agents(agent_id) on delete cascade,
  name        text not null,
  description text,
  condition   text not null,
  action      text not null default 'flag',
  message     text,
  enabled     boolean default true,
  created_at  timestamptz default now()
);

create index if not exists agent_policies_agent_idx on agent_policies(agent_id);

alter table agent_policies enable row level security;

create policy "Users manage own policies" on agent_policies
  for all using (
    agent_id in (select agent_id from agents where user_id = auth.uid())
  );
