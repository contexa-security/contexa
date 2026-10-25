-- docs/agent A6-R8 and A6-R9.
--
-- document_deletion: a document marked for deletion through the business API. The document itself stays until the
-- company's retention purge, so nothing in the company's data is lost; rows of a run are removed with the run.
CREATE TABLE document_deletion (
    deletion_id   UUID          PRIMARY KEY,
    run_id        VARCHAR(40),
    request_id    VARCHAR(64),
    requested_by  VARCHAR(80)   NOT NULL,
    document_key  VARCHAR(48)   NOT NULL REFERENCES document (document_key),
    project_key   VARCHAR(32)   NOT NULL REFERENCES project (project_key),
    requested_at  TIMESTAMPTZ   NOT NULL
);

CREATE INDEX document_deletion_run_idx ON document_deletion (run_id);

-- The destinations the company registers for exports; an export that names any other destination hands the documents
-- to a place the company does not know. The destination of a job is kept as the request wrote it.
CREATE TABLE export_destination (
    destination_key  VARCHAR(120)  PRIMARY KEY,
    kind             VARCHAR(16)   NOT NULL,
    description      VARCHAR(200)  NOT NULL,
    CONSTRAINT export_destination_kind_chk CHECK (kind IN ('INTERNAL', 'PARTNER'))
);

INSERT INTO export_destination (destination_key, kind, description) VALUES
    ('design-share', 'INTERNAL', 'The design engineering team share'),
    ('program-share', 'INTERNAL', 'The program management share'),
    ('partner-exchange', 'PARTNER', 'The registered supplier document exchange');

ALTER TABLE export_job ADD COLUMN destination VARCHAR(120);

-- The company's rule of a document deletion, as data both control C2 and control D read (like V7 for reads): an
-- employee assigned to the project, or a ticket of a design change that covers the project.
INSERT INTO company_policy (policy_key, description, account_manager_exempt, assigned_exempt, recent_work_days,
                            effective_from)
VALUES ('DOCUMENT_DELETE_APPROVAL',
        'A project document is marked for deletion by an employee assigned to the project, or under a ticket of a '
            || 'design change that covers the project.',
        false, true, NULL, DATE '2026-01-01');
