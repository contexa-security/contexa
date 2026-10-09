-- The measurement protocol (docs/showcase/데모-재설계.md W5-0, review R-13, R-14): an operator runs every designed case N
-- times under one engine setting. Only runs of a protocol make the benchmark's scores; every other run is an
-- observation (a visitor's live run, an operator's single run) and is shown apart.
CREATE TABLE measurement_protocol (
    protocol_id   VARCHAR(40)   PRIMARY KEY,
    repeat        INTEGER       NOT NULL CHECK (repeat > 0),
    cases         JSONB         NOT NULL,
    started_at    TIMESTAMPTZ   NOT NULL,
    finished_at   TIMESTAMPTZ
);

ALTER TABLE run ADD COLUMN protocol_id VARCHAR(40) REFERENCES measurement_protocol (protocol_id);

CREATE INDEX run_protocol_idx ON run (protocol_id) WHERE protocol_id IS NOT NULL;
