CREATE TABLE lab.business_approval (
    id uuid PRIMARY KEY,
    visitor_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    command_id uuid NOT NULL,
    requester varchar(80) NOT NULL,
    requested_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    input_sha256 char(64) NOT NULL,
    request_record jsonb NOT NULL,
    UNIQUE (visitor_id,command_id),
    CHECK (expires_at>requested_at)
);
CREATE INDEX approval_workspace ON lab.business_approval(visitor_id,workspace_id,requested_at DESC);
CREATE TRIGGER immutable_business_approval BEFORE UPDATE ON lab.business_approval
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
CREATE TABLE lab.business_approval_decision (
    id uuid PRIMARY KEY,
    approval_id uuid NOT NULL UNIQUE REFERENCES lab.business_approval(id),
    visitor_id uuid NOT NULL,
    command_id uuid NOT NULL,
    reviewer varchar(80) NOT NULL,
    verdict varchar(20) NOT NULL CHECK (verdict IN ('APPROVED','REJECTED')),
    decided_at timestamptz NOT NULL,
    input_sha256 char(64) NOT NULL,
    decision_record jsonb NOT NULL,
    UNIQUE (visitor_id,command_id)
);
CREATE TRIGGER immutable_approval_decision BEFORE UPDATE ON lab.business_approval_decision
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
CREATE TABLE lab.business_approval_attempt (
    request_id uuid PRIMARY KEY,
    approval_id uuid NOT NULL REFERENCES lab.business_approval(id),
    command_id uuid NOT NULL,
    operation varchar(20) NOT NULL CHECK (operation IN ('REQUEST','DECISION')),
    reused boolean NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER immutable_approval_attempt BEFORE UPDATE ON lab.business_approval_attempt
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
