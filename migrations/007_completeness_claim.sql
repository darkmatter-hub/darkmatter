-- Migration 007: add completeness_claim column to commits table
-- completeness_claim is a signed boolean — the agent asserts nothing was omitted.
-- NULL = no claim made. TRUE = complete. FALSE = partial.
-- This is a signed assertion, not enforced coverage.

ALTER TABLE commits
  ADD COLUMN IF NOT EXISTS completeness_claim BOOLEAN DEFAULT NULL;

COMMENT ON COLUMN commits.completeness_claim IS
  'Signed by customer key as part of L3 envelope. NULL = no claim, TRUE = agent asserts complete, FALSE = partial.';
