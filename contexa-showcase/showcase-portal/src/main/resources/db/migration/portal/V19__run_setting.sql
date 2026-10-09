-- The measurement setting of a run (docs/showcase/데모-재설계.md W5, V-13): its execution specification without the
-- per-employee template and the system prompt hash, plus the version the templates were learned under. One measurement
-- protocol runs every protagonist's cases, each from that protagonist's own template, so its runs carry several
-- execution specifications but one setting; the benchmark counts within one setting.
ALTER TABLE run ADD COLUMN setting_hash VARCHAR(64);

CREATE INDEX run_setting_idx ON run (setting_hash) WHERE setting_hash IS NOT NULL;
