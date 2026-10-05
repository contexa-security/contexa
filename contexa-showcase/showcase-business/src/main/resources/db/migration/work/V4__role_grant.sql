-- Roles an administrator gives on a project through the business API (deck A5). Rows of a run are removed with the
-- run; the company's own assignments stay in project_assignment.
CREATE TABLE role_grant (
    grant_id        UUID          PRIMARY KEY,
    run_id          VARCHAR(40),
    request_id      VARCHAR(64),
    granted_by      VARCHAR(80)   NOT NULL,
    grantee         VARCHAR(64)   NOT NULL REFERENCES employee (employee_key),
    project_key     VARCHAR(32)   NOT NULL REFERENCES project (project_key),
    responsibility  VARCHAR(24)   NOT NULL,
    granted_at      TIMESTAMPTZ   NOT NULL
);

CREATE INDEX role_grant_run_idx ON role_grant (run_id);
