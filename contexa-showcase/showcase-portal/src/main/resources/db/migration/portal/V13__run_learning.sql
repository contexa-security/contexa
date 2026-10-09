-- What the engine learned during a run (docs/showcase/데모-재설계.md R-32): the template state the run started from and the
-- run principal's state at the run's end, read through the engine's public stores, with the behaviour documents the
-- template did not have. Kept with the run (396 days, deleted with it).
CREATE TABLE run_learning (
    run_id       VARCHAR(40)  PRIMARY KEY REFERENCES run (run_id) ON DELETE CASCADE,
    template_id  VARCHAR(48),
    learning     JSONB        NOT NULL,
    captured_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);
