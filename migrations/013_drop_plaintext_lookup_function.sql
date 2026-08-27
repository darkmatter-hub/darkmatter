-- 013_drop_plaintext_lookup_function.sql
--
-- Removes get_agent_by_api_key(text), left behind when the code stopped calling
-- it. Its body was:
--
--   select agent_id, agent_name, user_id, public_key
--   from agents
--   where api_key = p_api_key
--     and api_key is not null;
--
-- A function whose whole purpose is to match a caller-supplied string against a
-- plaintext credential column. Migration 012 dropped that column, so the
-- function is now broken as well as unwanted: calling it raises
-- `column "api_key" does not exist`.
--
-- It was never reachable from a browser. EXECUTE was granted to service_role
-- only, not to anon or authenticated, so it could not be called through
-- PostgREST by an unauthenticated visitor. That is why this is cleanup rather
-- than an incident.
--
-- Worth stating anyway: the application stopped calling it some time ago, and
-- test/smoke.test.js asserts the call site stays gone. Nothing noticed that the
-- function itself survived in the database. Dropping code from an application
-- does not drop it from Postgres, and a schema is a place where dead
-- security-sensitive code can sit unread for months.

DROP FUNCTION IF EXISTS public.get_agent_by_api_key(text);

-- The key_hint comment was written while the plaintext column still existed
-- and read "Exists so the plaintext api_key column can be dropped". It has
-- been. A column comment is documentation, and documentation that describes a
-- pending action long after it happened is the same rot as a stale date on a
-- marketing page.
COMMENT ON COLUMN agents.key_hint IS
  'Masked display hint (e.g. dm_sk_ab12****cd34) for the dashboard. The plaintext api_key column it replaced was dropped in migration 012. Never used for authentication; that is api_key_hash.';
