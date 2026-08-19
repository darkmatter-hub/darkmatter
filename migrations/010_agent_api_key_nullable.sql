-- 010_agent_api_key_nullable.sql
--
-- Phase 2 of removing plaintext API key storage (F8).
--
-- agents.api_key is NOT NULL. The code no longer writes it, so deploying that
-- change against the current schema would fail every agent creation with a
-- not-null violation. Dropping the constraint first is both backward and
-- forward compatible:
--
--   old code (writes api_key)      -> still succeeds, column accepts a value
--   new code (omits api_key)       -> succeeds, column accepts NULL
--
-- so the deploy can happen in either order without an outage window.
--
-- Phase 3 (migrations/011) drops the column once this has been running and no
-- new plaintext values are being written.

ALTER TABLE agents ALTER COLUMN api_key DROP NOT NULL;

COMMENT ON COLUMN agents.api_key IS
  'DEPRECATED (F8): plaintext credential, no longer written or read. Retained only so this migration is reversible; dropped in migrations/011.';
