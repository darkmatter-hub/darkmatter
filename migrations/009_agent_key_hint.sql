-- 009_agent_key_hint.sql
--
-- Phase 1 of removing plaintext API key storage (security finding F8).
--
-- agents.api_key holds the live plaintext credential alongside api_key_hash,
-- which is the value actually used for authentication. All 58 agents have a
-- populated hash, so the plaintext column is a redundant copy: any database
-- read (a backup, a replica, a leaked service-role key, a future injection)
-- yields every customer's live agent credentials directly.
--
-- The only remaining consumer of the plaintext value is the dashboard, which
-- renders a masked hint. This adds a stored hint so the plaintext column has
-- no readers left.
--
-- Phase 2 (migrations/010) drops agents.api_key, once this has deployed and
-- authentication has been confirmed working from the hash alone.

ALTER TABLE agents ADD COLUMN IF NOT EXISTS key_hint text;

-- Backfill using the same format as maskApiKey() in src/server.js:
--   prefix (dm_sk_ or first 6 chars) + first 4 of body + bullets + last 4
UPDATE agents
SET key_hint =
  CASE
    WHEN api_key IS NULL OR length(api_key) < 14 THEN '••••••••'
    WHEN api_key LIKE 'dm_sk_%' THEN
      'dm_sk_' || substr(api_key, 7, 4) || '••••••••' || right(api_key, 4)
    ELSE
      left(api_key, 6) || substr(api_key, 7, 4) || '••••••••' || right(api_key, 4)
  END
WHERE key_hint IS NULL;

COMMENT ON COLUMN agents.key_hint IS
  'Masked display hint (e.g. dm_sk_ab12••••••••cd34). Exists so the plaintext api_key column can be dropped; never used for authentication.';
