CREATE TABLE lab.comparison_preparation (
    id uuid PRIMARY KEY,
    visitor_id uuid NOT NULL REFERENCES lab.visitor(id),
    workspace_id uuid NOT NULL REFERENCES lab.workspace(id),
    command_id uuid NOT NULL,
    prepared_at timestamptz NOT NULL,
    input_sha256 char(64) NOT NULL,
    snapshot_sha256 char(64) NOT NULL,
    preparation jsonb NOT NULL,
    UNIQUE (visitor_id, command_id)
);
CREATE INDEX comparison_preparation_owner ON lab.comparison_preparation (visitor_id, prepared_at, id);
CREATE TRIGGER immutable_comparison_preparation BEFORE UPDATE ON lab.comparison_preparation
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();

CREATE TABLE lab.comparison_preparation_attempt (
    id uuid PRIMARY KEY,
    preparation_id uuid NOT NULL REFERENCES lab.comparison_preparation(id),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    submitted_input_sha256 char(64) NOT NULL,
    outcome varchar(30) NOT NULL CHECK (outcome IN ('CREATED', 'REUSED', 'INPUT_CONFLICT'))
);
CREATE INDEX comparison_preparation_attempt_parent ON lab.comparison_preparation_attempt (preparation_id, received_at);
CREATE TRIGGER immutable_comparison_preparation_attempt BEFORE UPDATE ON lab.comparison_preparation_attempt
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
