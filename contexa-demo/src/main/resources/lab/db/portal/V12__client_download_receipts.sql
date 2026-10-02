CREATE TABLE lab.client_receipt (
    id uuid PRIMARY KEY,
    visitor_id uuid NOT NULL,
    arm varchar(10) NOT NULL CHECK (arm IN ('baseline', 'contexa')),
    request_id uuid NOT NULL,
    input_sha256 char(64) NOT NULL,
    reported_at timestamptz NOT NULL,
    receipt jsonb NOT NULL,
    UNIQUE (visitor_id, arm, request_id)
);
CREATE INDEX client_receipt_owner ON lab.client_receipt (visitor_id, arm, request_id, reported_at);
CREATE TRIGGER immutable_client_receipt BEFORE UPDATE ON lab.client_receipt
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
