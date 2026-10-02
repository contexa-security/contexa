CREATE TABLE lab.engine_observation (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id uuid NOT NULL UNIQUE,
    request_id uuid NOT NULL,
    kind varchar(60) NOT NULL,
    observed_at timestamptz NOT NULL,
    collected_at timestamptz NOT NULL DEFAULT now(),
    payload jsonb NOT NULL,
    content_sha256 char(64) NOT NULL
);
CREATE INDEX engine_observation_request ON lab.engine_observation (request_id, sequence);
CREATE TRIGGER immutable_engine_observation BEFORE UPDATE ON lab.engine_observation
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
