-- W6-1 (P6-CHANGE-2): the harness runs of the reactivity metrics (docs/showcase/프롬프트-최종-구현계획.md 8.4 to 8.7):
-- the batch a run belongs to, its kind (a case as designed, one lab condition changed, a case-definition variant, an
-- injection) and its variant label, so a metric reads the runs of one batch. The rows go with their run.
CREATE TABLE reactivity_run (
    run_id       VARCHAR(40)   PRIMARY KEY REFERENCES run (run_id) ON DELETE CASCADE,
    batch_id     VARCHAR(64)   NOT NULL,
    kind         VARCHAR(16)   NOT NULL,
    label        VARCHAR(160)  NOT NULL,
    case_key     VARCHAR(48)   NOT NULL,
    recorded_at  TIMESTAMPTZ   NOT NULL,
    CONSTRAINT reactivity_run_kind_chk CHECK (kind IN ('BASE', 'LAB', 'VARIANT', 'INJECTION'))
);

CREATE INDEX reactivity_run_batch_idx ON reactivity_run (batch_id, recorded_at);
