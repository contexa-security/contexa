-- Combination records of the exploration grid (deck p.13, P4): the first live run of a combination under a version
-- key is kept and every later visitor of the same combination sees that run and its time instead of a new run.
CREATE TABLE combination_record (
    combo_key          VARCHAR(48)   NOT NULL,
    catalog_version    INTEGER       NOT NULL,
    version_key        CHAR(64)      NOT NULL,
    run_id             VARCHAR(40)   NOT NULL REFERENCES run (run_id),
    visitor_hash       CHAR(64),
    recorded_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
    PRIMARY KEY (combo_key, catalog_version, version_key)
);

CREATE INDEX combination_record_version_idx ON combination_record (catalog_version, version_key);
