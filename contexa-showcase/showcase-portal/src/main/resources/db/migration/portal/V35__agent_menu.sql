-- docs/agent Agent중심-화면 AC-4a: the agent menu, a finite table of cases and the paths an agent sends on. A daily job
-- runs each combination with the real engine and keeps the run that answers it; a visitor who picks a combination is
-- shown that stored run, so no model is called for the visit. A combination whose refresh fails keeps its last run.
CREATE TABLE agent_menu (
    case_key        VARCHAR(16)   NOT NULL,
    path            VARCHAR(24)   NOT NULL,
    run_id          VARCHAR(40)   NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    definition_sha  CHAR(64)      NOT NULL,
    ran_at          TIMESTAMPTZ   NOT NULL,
    PRIMARY KEY (case_key, path)
);

-- One row per day of the refresh job: what it ran, what it spent, and why it stopped early (the daily spending limit).
CREATE TABLE agent_menu_job (
    day          DATE           PRIMARY KEY,
    started_at   TIMESTAMPTZ    NOT NULL,
    finished_at  TIMESTAMPTZ,
    ran          INTEGER        NOT NULL DEFAULT 0,
    failed       INTEGER        NOT NULL DEFAULT 0,
    skipped      INTEGER        NOT NULL DEFAULT 0,
    spent_usd    NUMERIC(12, 6) NOT NULL DEFAULT 0,
    stopped      VARCHAR(40)
);
