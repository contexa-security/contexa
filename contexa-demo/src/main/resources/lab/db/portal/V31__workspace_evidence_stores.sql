CREATE TABLE lab.workspace_evidence_store (
    lease_id uuid PRIMARY KEY REFERENCES lab.workspace_lease(id),
    baseline_url text NOT NULL,
    contexa_url text NOT NULL,
    security_url text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER immutable_workspace_evidence_store BEFORE UPDATE ON lab.workspace_evidence_store
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
