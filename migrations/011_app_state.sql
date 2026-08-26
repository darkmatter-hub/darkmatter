-- 011_app_state.sql
--
-- A tiny key/value table for small pieces of server state that must survive a
-- restart but do not deserve a table of their own.
--
-- First use: the high-water mark for signup notifications. The admin email
-- currently fires the moment somebody submits the signup form, before any
-- confirmation, so every abandoned or automated signup reaches the inbox. Nine
-- such accounts exist and none of them ever confirmed. An alert that is mostly
-- noise stops being read, which matters because the first real customer is the
-- one message that must not be ignored.
--
-- Notifying on confirmation instead needs a timestamp that outlives deploys.
-- Holding it in memory would mean either re-notifying after every restart, or
-- silently missing anyone who confirmed during one.

CREATE TABLE IF NOT EXISTS app_state (
  key        text PRIMARY KEY,
  value      text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE app_state IS
  'Small server-side key/value state that must survive restarts. Not user data.';

-- Service-role only. Nothing here is ever read by a browser.
ALTER TABLE app_state ENABLE ROW LEVEL SECURITY;
