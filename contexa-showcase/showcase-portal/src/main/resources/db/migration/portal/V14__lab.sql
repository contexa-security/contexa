-- The lab (docs/showcase/데모-재설계.md 5A.1, W2-2). A row is written when the run has its run ID, with the time the
-- visitor sent the call, which is before the run started. A visitor's hash is cleared when the visitor's 30 days are
-- over; the rows stay so the published aggregates do not shrink silently (review R-27).

-- The case a lab run started from, the conditions the visitor changed and whether it ran as designed.
CREATE TABLE lab_composition (
    run_id        VARCHAR(40)   PRIMARY KEY REFERENCES run (run_id) ON DELETE CASCADE,
    case_key      VARCHAR(48)   NOT NULL,
    designed      BOOLEAN       NOT NULL,
    changed       JSONB         NOT NULL,
    conditions    JSONB         NOT NULL,
    composed_at   TIMESTAMPTZ   NOT NULL
);

-- The visitor's call before sending (activity 2): the request as a whole and, optionally, each approach.
CREATE TABLE visitor_prediction (
    run_id         VARCHAR(40)   PRIMARY KEY REFERENCES run (run_id) ON DELETE CASCADE,
    visitor_hash   CHAR(64),
    call           VARCHAR(16)   NOT NULL,
    approaches     JSONB         NOT NULL DEFAULT '{}'::jsonb,
    predicted_at   TIMESTAMPTZ   NOT NULL,
    CONSTRAINT visitor_prediction_call_chk CHECK (call IN ('NORMAL', 'ATTACK', 'UNSURE'))
);

-- The visitor's assessment of control D's decision of a step (activity 5): once per step, by the run's own visitor.
CREATE TABLE visitor_assessment (
    run_id         VARCHAR(40)   NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    step_no        INTEGER       NOT NULL,
    visitor_hash   CHAR(64),
    verdict        VARCHAR(16)   NOT NULL,
    reasons        JSONB         NOT NULL DEFAULT '[]'::jsonb,
    assessed_at    TIMESTAMPTZ   NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, step_no),
    CONSTRAINT visitor_assessment_verdict_chk CHECK (verdict IN ('SOUND', 'UNSOUND', 'UNSURE'))
);

CREATE INDEX visitor_prediction_visitor_idx ON visitor_prediction (visitor_hash);
CREATE INDEX visitor_assessment_visitor_idx ON visitor_assessment (visitor_hash);
