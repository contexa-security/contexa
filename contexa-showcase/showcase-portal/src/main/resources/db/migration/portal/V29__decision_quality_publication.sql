-- BM-S8 of docs/showcase/벤치마크-구현계획.md: the decision quality of a measurement protocol an operator published for
-- a measurement setting (G5 of docs/showcase/프롬프트-v21-구현계획.md: each decision's reason codes against the facts
-- they cite, from control D's latest inspection), counted when published so a visitor reads stored values and no
-- visitor request reads control D. Republishing a setting replaces its row.
CREATE TABLE decision_quality_publication (
    setting_hash  VARCHAR(64)   PRIMARY KEY,
    protocol_id   VARCHAR(40)   NOT NULL REFERENCES measurement_protocol (protocol_id),
    quality       JSONB         NOT NULL,
    published_at  TIMESTAMPTZ   NOT NULL
);
