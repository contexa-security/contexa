-- W7-13 (P7): what the benchmark's prompt quality tab shows (docs/showcase/화면설계-프롬프트신뢰-보강안.md 3.5, 5): the
-- harness batch and the measurement protocol an operator published for a measurement setting, with the view counted
-- from them when published, so a visitor reads stored values and no visitor request reads control D. Republishing a
-- setting replaces its row.
CREATE TABLE prompt_quality_publication (
    setting_hash  VARCHAR(64)   PRIMARY KEY,
    batch_id      VARCHAR(64)   NOT NULL,
    protocol_id   VARCHAR(40)   NOT NULL REFERENCES measurement_protocol (protocol_id),
    quality       JSONB         NOT NULL,
    published_at  TIMESTAMPTZ   NOT NULL
);

CREATE INDEX prompt_quality_publication_at_idx ON prompt_quality_publication (published_at);
