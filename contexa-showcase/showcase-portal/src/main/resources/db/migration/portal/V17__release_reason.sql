-- A release that succeeded has no failure reason, as an answered check of run_challenge has none (docs/showcase/
-- 데모-재설계.md W1-0d). Found on the real server on 2026-10-06: an approved release could not be stored and failed the
-- whole run on the NOT NULL constraint. The length follows run_challenge.reason.
ALTER TABLE run_release ALTER COLUMN reason DROP NOT NULL;
ALTER TABLE run_release ALTER COLUMN reason TYPE VARCHAR(200);
