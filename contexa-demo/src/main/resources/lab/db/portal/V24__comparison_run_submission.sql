CREATE TABLE lab.comparison_run_submission (
    id uuid PRIMARY KEY,
    preparation_id uuid NOT NULL REFERENCES lab.comparison_preparation(id),
    visitor_id uuid NOT NULL REFERENCES lab.visitor(id),
    command_id uuid NOT NULL,
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    input_sha256 char(64) NOT NULL
);
CREATE INDEX comparison_run_submission_parent ON lab.comparison_run_submission(preparation_id, started_at, id);
CREATE TRIGGER immutable_comparison_run_submission BEFORE UPDATE ON lab.comparison_run_submission
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();

CREATE TABLE lab.comparison_run_submission_result (
    submission_id uuid PRIMARY KEY REFERENCES lab.comparison_run_submission(id),
    finished_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    state varchar(24) NOT NULL CHECK (state IN ('RUN_AVAILABLE','REJECTED','FAILED')),
    run_id uuid REFERENCES lab.comparison_run(id),
    http_status integer CHECK (http_status BETWEEN 100 AND 599),
    reason varchar(64),
    CHECK ((state='RUN_AVAILABLE' AND run_id IS NOT NULL AND http_status IS NOT NULL AND http_status=200)
        OR (state='REJECTED' AND run_id IS NULL AND http_status IS NOT NULL AND http_status BETWEEN 400 AND 599)
        OR (state='FAILED' AND run_id IS NULL AND http_status IS NULL))
);
CREATE TRIGGER immutable_comparison_run_submission_result BEFORE UPDATE ON lab.comparison_run_submission_result
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
