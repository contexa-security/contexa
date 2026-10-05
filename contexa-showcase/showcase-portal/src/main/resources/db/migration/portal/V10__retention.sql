-- Retention (docs/showcase/P5-설계.md section 6). Whether a run was a visitor's live run is kept as a flag, so the
-- visitor hash on the run can be cleared when the visitor's 30 days are over without changing the daily allotment or
-- the statistics. Each retention pass records what it deleted.
ALTER TABLE run ADD COLUMN live_run BOOLEAN NOT NULL DEFAULT false;
UPDATE run SET live_run = true WHERE live_visitor_hash IS NOT NULL;

CREATE TABLE retention_log (
    run_at   TIMESTAMPTZ  PRIMARY KEY,
    deleted  JSONB        NOT NULL
);
