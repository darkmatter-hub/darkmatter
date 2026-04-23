-- DarkMatter migration 005 — L3 Non-repudiation
-- Run in Supabase SQL editor

-- ── 1. New columns on commits table ─────────────────────────────────────────
alter table commits
  add column if not exists assurance_level           text    default 'L1',
  add column if not exists client_signature          text,
  add column if not exists client_public_key         text,
  add column if not exists client_key_id             text,
  add column if not exists client_signature_algorithm text,
  add column if not exists client_envelope_version   text,
  add column if not exists client_payload_hash       text,
  add column if not exists client_metadata_hash      text,
  add column if not exists client_envelope_hash      text,
  add column if not exists client_attestation_ts     timestamptz,
  add column if not exists timestamp_skew_warning    boolean default false;

-- Index for querying L3 commits
create index if not exists commits_assurance_level_idx on commits(assurance_level);
create index if not exists commits_client_key_id_idx   on commits(client_key_id);

-- ── 2. Signing keys table ─────────────────────────────────────────────────────
create table if not exists signing_keys (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references auth.users(id) on delete cascade,
  key_id       text not null,
  public_key   text not null,       -- base64url raw 32-byte Ed25519 public key
  algorithm    text not null default 'Ed25519',
  status       text not null default 'active',  -- 'active' | 'revoked'
  created_at   timestamptz not null default now(),
  revoked_at   timestamptz,
  description  text
);

-- One key_id per user (key_id is scoped to user, not global)
create unique index if not exists signing_keys_user_key_id_idx
  on signing_keys(user_id, key_id);

-- Fast lookup by key_id for verification
create index if not exists signing_keys_key_id_idx on signing_keys(key_id);

-- RLS
alter table signing_keys enable row level security;

create policy "Users can manage own signing keys"
  on signing_keys for all
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Service role can read all (for verification during commit)
-- This is handled by the service client which bypasses RLS
