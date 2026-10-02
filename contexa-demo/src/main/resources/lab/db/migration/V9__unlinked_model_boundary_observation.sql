CREATE TABLE lab.model_boundary_observation (
    id uuid PRIMARY KEY,
    observed_at timestamptz NOT NULL,
    input_sha256 char(64) NOT NULL,
    payload jsonb NOT NULL,
    content_sha256 char(64) NOT NULL,
    collected_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER immutable_model_boundary BEFORE UPDATE ON lab.model_boundary_observation
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
COMMENT ON TABLE lab.model_boundary_observation IS
    'ChatClient advisor boundary only. No HTTP request/generation association; no public API. Not wire evidence.';
