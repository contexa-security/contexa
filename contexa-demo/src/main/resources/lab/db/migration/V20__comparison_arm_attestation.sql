CREATE TABLE lab.comparison_arm_attestation (
    id uuid PRIMARY KEY,
    visitor_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    preparation_id uuid NOT NULL,
    command_id uuid NOT NULL,
    arm varchar(12) NOT NULL CHECK (arm IN ('baseline', 'contexa')),
    captured_at timestamptz NOT NULL,
    snapshot_sha256 char(64) NOT NULL,
    attestation jsonb NOT NULL,
    UNIQUE (visitor_id, command_id)
);
CREATE INDEX comparison_arm_attestation_owner
    ON lab.comparison_arm_attestation (visitor_id, preparation_id, captured_at);
CREATE TRIGGER immutable_comparison_arm_attestation BEFORE UPDATE ON lab.comparison_arm_attestation
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
