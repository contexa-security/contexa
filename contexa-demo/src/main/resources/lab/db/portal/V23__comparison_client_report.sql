CREATE TABLE lab.comparison_client_report (
    attempt_id uuid NOT NULL,
    stage varchar(12) NOT NULL CHECK (stage IN ('STARTED','FINISHED')),
    run_id uuid NOT NULL REFERENCES lab.comparison_run(id),
    step_id uuid NOT NULL REFERENCES lab.comparison_run_step(id),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    content_sha256 char(64) NOT NULL,
    payload jsonb NOT NULL,
    PRIMARY KEY (attempt_id, stage),
    CHECK (octet_length(payload::text)<=4096)
);
CREATE INDEX comparison_client_report_run ON lab.comparison_client_report(run_id,received_at);
CREATE TRIGGER immutable_comparison_client_report BEFORE UPDATE ON lab.comparison_client_report
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
