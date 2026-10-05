-- Virtual company of the showcase (docs/showcase/ADR.md ADR-19). CompanyGenerator fills every table except the
-- run tables from (seed, anchor date, generator version); run tables hold per-run principals, overlays and results.

-- One generated company per database.
CREATE TABLE company_generation (
    generation_id      SMALLINT     PRIMARY KEY CHECK (generation_id = 1),
    seed               BIGINT       NOT NULL,
    anchor_date        DATE         NOT NULL,
    generator_version  VARCHAR(32)  NOT NULL,
    data_sha256        CHAR(64)     NOT NULL,
    generated_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);

ALTER TABLE employee ADD COLUMN email VARCHAR(128);
ALTER TABLE employee ADD COLUMN office_network VARCHAR(18);
ALTER TABLE employee ADD CONSTRAINT employee_email_uk UNIQUE (email);

CREATE TABLE project (
    project_key         VARCHAR(32)   PRIMARY KEY,
    display_name        VARCHAR(128)  NOT NULL,
    program             VARCHAR(32)   NOT NULL,
    sensitivity         VARCHAR(16)   NOT NULL,
    owner_employee_key  VARCHAR(64)   NOT NULL REFERENCES employee (employee_key),
    CONSTRAINT project_sensitivity_chk CHECK (sensitivity IN ('INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'))
);

CREATE TABLE project_assignment (
    project_key     VARCHAR(32)  NOT NULL REFERENCES project (project_key),
    employee_key    VARCHAR(64)  NOT NULL REFERENCES employee (employee_key),
    responsibility  VARCHAR(32)  NOT NULL,
    assigned_from   DATE         NOT NULL,
    assigned_until  DATE,
    PRIMARY KEY (project_key, employee_key),
    CONSTRAINT project_assignment_period_chk CHECK (assigned_until IS NULL OR assigned_until >= assigned_from)
);

CREATE INDEX project_assignment_employee_idx ON project_assignment (employee_key);

CREATE TABLE document (
    document_key   VARCHAR(48)   PRIMARY KEY,
    project_key    VARCHAR(32)   NOT NULL REFERENCES project (project_key),
    document_type  VARCHAR(24)   NOT NULL,
    title          VARCHAR(200)  NOT NULL,
    revision       VARCHAR(8)    NOT NULL,
    sensitivity    VARCHAR(16)   NOT NULL,
    size_bytes     INTEGER       NOT NULL CHECK (size_bytes > 0),
    body           TEXT          NOT NULL,
    updated_on     DATE          NOT NULL,
    CONSTRAINT document_type_chk CHECK (document_type IN ('DRAWING', 'SPECIFICATION', 'TEST_REPORT', 'BOM', 'NOTE')),
    CONSTRAINT document_sensitivity_chk CHECK (sensitivity IN ('INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'))
);

CREATE INDEX document_project_idx ON document (project_key, document_key);

CREATE TABLE customer (
    customer_key     VARCHAR(32)   PRIMARY KEY,
    display_name     VARCHAR(128)  NOT NULL,
    region           VARCHAR(8)    NOT NULL,
    account_manager  VARCHAR(64)   NOT NULL REFERENCES employee (employee_key),
    project_key      VARCHAR(32)   NOT NULL REFERENCES project (project_key)
);

CREATE INDEX customer_manager_idx ON customer (account_manager);

CREATE TABLE device (
    device_key     VARCHAR(48)   PRIMARY KEY,
    employee_key   VARCHAR(64)   NOT NULL REFERENCES employee (employee_key),
    platform       VARCHAR(32)   NOT NULL,
    user_agent     VARCHAR(300)  NOT NULL,
    first_seen_on  DATE          NOT NULL
);

CREATE INDEX device_employee_idx ON device (employee_key);

-- Daily access counts per employee and project (company history, read only).
CREATE TABLE access_history (
    employee_key  VARCHAR(64)  NOT NULL REFERENCES employee (employee_key),
    project_key   VARCHAR(32)  NOT NULL REFERENCES project (project_key),
    access_date   DATE         NOT NULL,
    access_count  INTEGER      NOT NULL CHECK (access_count > 0),
    PRIMARY KEY (employee_key, project_key, access_date)
);

-- Run principals: the fresh user of one run in every control maps back to the employee it plays.
CREATE TABLE run_principal (
    username         VARCHAR(80)   PRIMARY KEY,
    run_id           VARCHAR(40)   NOT NULL,
    employee_key     VARCHAR(64)   NOT NULL REFERENCES employee (employee_key),
    organization_id  VARCHAR(64)   NOT NULL,
    tenant_id        VARCHAR(64)   NOT NULL,
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX run_principal_run_idx ON run_principal (run_id);

-- Facts that a run may add on top of the company (conditions chosen for the run). run_id NULL = company fact.
CREATE TABLE itsm_ticket (
    ticket_key    VARCHAR(40)   PRIMARY KEY,
    run_id        VARCHAR(40),
    kind          VARCHAR(16)   NOT NULL,
    requester     VARCHAR(64)   NOT NULL REFERENCES employee (employee_key),
    approver      VARCHAR(64)   REFERENCES employee (employee_key),
    project_key   VARCHAR(32)   NOT NULL REFERENCES project (project_key),
    purpose       VARCHAR(32)   NOT NULL,
    summary       VARCHAR(300)  NOT NULL,
    valid_from    TIMESTAMPTZ   NOT NULL,
    valid_until   TIMESTAMPTZ   NOT NULL,
    status        VARCHAR(16)   NOT NULL,
    CONSTRAINT itsm_ticket_kind_chk CHECK (kind IN ('INCIDENT', 'CHANGE')),
    CONSTRAINT itsm_ticket_status_chk CHECK (status IN ('OPEN', 'APPROVED', 'CLOSED', 'REJECTED')),
    CONSTRAINT itsm_ticket_period_chk CHECK (valid_until > valid_from)
);

CREATE INDEX itsm_ticket_requester_idx ON itsm_ticket (requester, project_key);
CREATE INDEX itsm_ticket_run_idx ON itsm_ticket (run_id);

CREATE TABLE oncall_roster (
    roster_key    VARCHAR(48)   PRIMARY KEY,
    run_id        VARCHAR(40),
    employee_key  VARCHAR(64)   NOT NULL REFERENCES employee (employee_key),
    team          VARCHAR(32)   NOT NULL,
    starts_at     TIMESTAMPTZ   NOT NULL,
    ends_at       TIMESTAMPTZ   NOT NULL,
    CONSTRAINT oncall_roster_period_chk CHECK (ends_at > starts_at)
);

CREATE INDEX oncall_roster_employee_idx ON oncall_roster (employee_key, starts_at);
CREATE INDEX oncall_roster_run_idx ON oncall_roster (run_id);

CREATE TABLE approval (
    approval_key  VARCHAR(40)   PRIMARY KEY,
    run_id        VARCHAR(40),
    requester     VARCHAR(64)   NOT NULL REFERENCES employee (employee_key),
    approver      VARCHAR(64)   NOT NULL REFERENCES employee (employee_key),
    project_key   VARCHAR(32)   NOT NULL REFERENCES project (project_key),
    purpose       VARCHAR(32)   NOT NULL,
    max_items     INTEGER       NOT NULL CHECK (max_items > 0),
    valid_from    TIMESTAMPTZ   NOT NULL,
    valid_until   TIMESTAMPTZ   NOT NULL,
    status        VARCHAR(16)   NOT NULL,
    CONSTRAINT approval_status_chk CHECK (status IN ('APPROVED', 'REJECTED', 'EXPIRED')),
    CONSTRAINT approval_period_chk CHECK (valid_until > valid_from)
);

CREATE INDEX approval_requester_idx ON approval (requester, project_key);
CREATE INDEX approval_run_idx ON approval (run_id);

-- Normal activity of the protagonists that the template learning replays as real requests (ADR-23).
CREATE TABLE scripted_activity (
    employee_key  VARCHAR(64)  NOT NULL REFERENCES employee (employee_key),
    activity_no   INTEGER      NOT NULL,
    observed_at   TIMESTAMPTZ  NOT NULL,
    operation     VARCHAR(24)  NOT NULL,
    target_key    VARCHAR(48)  NOT NULL,
    items         INTEGER      NOT NULL CHECK (items > 0),
    PRIMARY KEY (employee_key, activity_no)
);

-- Sign-in accounts of the plain controls (B, C1, C2 share them).
CREATE TABLE plain_user (
    username       VARCHAR(80)   PRIMARY KEY REFERENCES run_principal (username) ON DELETE CASCADE,
    password_hash  VARCHAR(100)  NOT NULL,
    created_at     TIMESTAMPTZ   NOT NULL DEFAULT now()
);

-- Business outcome of exports in every control: whether the data was delivered (deck p.24).
CREATE TABLE export_job (
    job_id           UUID          PRIMARY KEY,
    run_id           VARCHAR(40),
    request_id       VARCHAR(64),
    control          VARCHAR(8)    NOT NULL,
    username         VARCHAR(80)   NOT NULL,
    project_key      VARCHAR(32)   NOT NULL,
    mode             VARCHAR(8)    NOT NULL,
    requested_items  INTEGER       NOT NULL CHECK (requested_items > 0),
    delivered_items  INTEGER       NOT NULL DEFAULT 0,
    status           VARCHAR(16)   NOT NULL,
    manifest_sha256  CHAR(64),
    started_at       TIMESTAMPTZ   NOT NULL,
    finished_at      TIMESTAMPTZ,
    CONSTRAINT export_job_mode_chk CHECK (mode IN ('SYNC', 'STREAM')),
    CONSTRAINT export_job_status_chk CHECK (status IN ('RUNNING', 'COMPLETED', 'INTERRUPTED'))
);

CREATE INDEX export_job_run_idx ON export_job (run_id);
CREATE INDEX export_job_request_idx ON export_job (request_id);

-- Every decision of the rule controls with the facts it looked up.
CREATE TABLE rule_decision_log (
    decision_id  UUID          PRIMARY KEY,
    run_id       VARCHAR(40),
    request_id   VARCHAR(64),
    control      VARCHAR(8)    NOT NULL,
    username     VARCHAR(80)   NOT NULL,
    operation    VARCHAR(24)   NOT NULL,
    rule_id      VARCHAR(32)   NOT NULL,
    outcome      VARCHAR(8)    NOT NULL,
    reason       VARCHAR(300)  NOT NULL,
    facts        JSONB         NOT NULL,
    decided_at   TIMESTAMPTZ   NOT NULL,
    CONSTRAINT rule_decision_outcome_chk CHECK (outcome IN ('ALLOW', 'DENY'))
);

CREATE INDEX rule_decision_run_idx ON rule_decision_log (run_id);
CREATE INDEX rule_decision_request_idx ON rule_decision_log (request_id);
