-- DarkMatter Integrity Infrastructure — Phase 1→3
-- Run after existing schema migrations
-- ─────────────────────────────────────────────────────────────────────────────

-- ── log_entries: append-only log (Phase 2) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS log_entries (
  position        BIGSERIAL    PRIMARY KEY,
  commit_id       TEXT         NOT NULL REFERENCES commits(id),
  integrity_hash  TEXT         NOT NULL,  -- bare sha256 hex, no prefix
  log_root        TEXT         NOT NULL,  -- running hash of log 0..position
  server_sig      TEXT         NOT NULL,  -- Ed25519 hex over canonical(log_root,position,timestamp)
  timestamp       TIMESTAMPTZ  NOT NULL,
  created_at      TIMESTAMPTZ  DEFAULT now()
);

-- Append-only enforcement: no UPDATE or DELETE allowed
ALTER TABLE log_entries ENABLE ROW LEVEL SECURITY;

CREATE POLICY "log_entries: insert only via service role"
  ON log_entries FOR INSERT
  TO service_role
  WITH CHECK (true);

CREATE POLICY "log_entries: public read"
  ON log_entries FOR SELECT
  USING (true);

-- No UPDATE policy = updates blocked
-- No DELETE policy = deletes blocked

CREATE INDEX IF NOT EXISTS log_entries_commit_idx  ON log_entries(commit_id);
CREATE INDEX IF NOT EXISTS log_entries_ts_idx      ON log_entries(timestamp DESC);

-- ── checkpoints: signed periodic snapshots (Phase 2) ──────────────────────────
CREATE TABLE IF NOT EXISTS checkpoints (
  id             BIGSERIAL    PRIMARY KEY,
  position       BIGINT       NOT NULL,   -- log_entry position at time of checkpoint
  log_root       TEXT         NOT NULL,
  tree_root      TEXT,                    -- Merkle root (Phase 3+)
  server_sig     TEXT         NOT NULL,
  timestamp      TIMESTAMPTZ  NOT NULL,
  published      BOOLEAN      DEFAULT false,
  published_url  TEXT,
  created_at     TIMESTAMPTZ  DEFAULT now()
);

ALTER TABLE checkpoints ENABLE ROW LEVEL SECURITY;

CREATE POLICY "checkpoints: insert via service role"
  ON checkpoints FOR INSERT TO service_role WITH CHECK (true);

CREATE POLICY "checkpoints: update via service role"
  ON checkpoints FOR UPDATE TO service_role USING (true);

CREATE POLICY "checkpoints: public read"
  ON checkpoints FOR SELECT USING (true);

-- ── agent_pubkeys: public key registry (Phase 1 — agent signatures) ───────────
CREATE TABLE IF NOT EXISTS agent_pubkeys (
  agent_id        TEXT         PRIMARY KEY REFERENCES agents(agent_id),
  public_key_pem  TEXT         NOT NULL,
  registered_at   TIMESTAMPTZ  DEFAULT now(),
  revoked_at      TIMESTAMPTZ  -- null = active
);

ALTER TABLE agent_pubkeys ENABLE ROW LEVEL SECURITY;

CREATE POLICY "agent_pubkeys: insert via service role"
  ON agent_pubkeys FOR INSERT TO service_role WITH CHECK (true);

CREATE POLICY "agent_pubkeys: public read (pubkeys are public)"
  ON agent_pubkeys FOR SELECT USING (revoked_at IS NULL);

-- ── Add columns to commits for client-side hashing + signatures ───────────────
ALTER TABLE commits
  ADD COLUMN IF NOT EXISTS client_payload_hash    TEXT,  -- hash computed by client before send
  ADD COLUMN IF NOT EXISTS client_integrity_hash  TEXT,  -- integrity hash computed by client
  ADD COLUMN IF NOT EXISTS agent_signature        TEXT,  -- Ed25519 hex signature by agent
  ADD COLUMN IF NOT EXISTS hash_mismatch          BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS log_position           BIGINT; -- position in log_entries

CREATE INDEX IF NOT EXISTS commits_log_position_idx ON commits(log_position);

-- ── Server signing key storage (for dev; production uses env var) ──────────────
CREATE TABLE IF NOT EXISTS server_config (
  key    TEXT PRIMARY KEY,
  value  TEXT NOT NULL,
  set_at TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE server_config ENABLE ROW LEVEL SECURITY;
-- No read policy = private to service_role only
CREATE POLICY "server_config: service role only"
  ON server_config FOR ALL TO service_role USING (true);

-- ── Helper view: latest checkpoint ────────────────────────────────────────────
CREATE OR REPLACE VIEW latest_checkpoint AS
  SELECT * FROM checkpoints
  ORDER BY position DESC
  LIMIT 1;

COMMENT ON TABLE log_entries  IS 'Append-only log of commit integrity hashes. No UPDATE or DELETE policies — enforced by RLS.';
COMMENT ON TABLE checkpoints  IS 'Periodic signed snapshots of log root. Published externally for independent verification.';
COMMENT ON TABLE agent_pubkeys IS 'Public key registry. Private keys never stored here.';
