ALTER TABLE lab.business_request_snapshot DROP CONSTRAINT business_request_target;
ALTER TABLE lab.business_request_snapshot ADD CONSTRAINT business_request_target CHECK (
    (resource_type='DOCUMENT' AND document_id IS NOT NULL AND document_version IS NOT NULL
        AND customer_id IS NULL AND customer_version IS NULL)
    OR (resource_type='CUSTOMER' AND customer_id IS NOT NULL AND customer_version IS NOT NULL
        AND document_id IS NULL AND document_version IS NULL)
    OR (resource_type='EXPORT' AND document_id IS NULL AND document_version IS NULL
        AND customer_id IS NULL AND customer_version IS NULL));
CREATE TABLE lab.export_file (
    id uuid PRIMARY KEY,
    visitor_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    username varchar(80) NOT NULL,
    command_id uuid NOT NULL,
    resource_type varchar(20) NOT NULL CHECK (resource_type IN ('DOCUMENT','CUSTOMER')),
    language varchar(2) NOT NULL CHECK (language IN ('KO','EN')),
    purpose varchar(40) NOT NULL,
    input_sha256 char(64) NOT NULL,
    filename varchar(120) NOT NULL,
    content_type varchar(80) NOT NULL,
    content bytea NOT NULL,
    content_sha256 char(64) NOT NULL,
    prepared_items integer NOT NULL CHECK (prepared_items BETWEEN 1 AND 50),
    prepared_at timestamptz NOT NULL,
    UNIQUE (visitor_id,command_id),
    CHECK (octet_length(content)<=5242880)
);
CREATE TRIGGER immutable_export_file BEFORE UPDATE ON lab.export_file
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
CREATE TABLE lab.export_item (
    file_id uuid NOT NULL REFERENCES lab.export_file(id),
    resource_id varchar(60) NOT NULL,
    resource_version integer NOT NULL,
    content_sha256 char(64) NOT NULL,
    content_bytes integer NOT NULL CHECK (content_bytes>=0),
    PRIMARY KEY (file_id,resource_id)
);
CREATE TRIGGER immutable_export_item BEFORE UPDATE ON lab.export_item
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
CREATE TABLE lab.export_attempt (
    request_id uuid PRIMARY KEY REFERENCES lab.business_request_snapshot(request_id),
    file_id uuid NOT NULL REFERENCES lab.export_file(id),
    command_id uuid NOT NULL,
    reused boolean NOT NULL,
    prepared_at timestamptz NOT NULL
);
CREATE INDEX export_attempt_file ON lab.export_attempt(file_id);
CREATE TRIGGER immutable_export_attempt BEFORE UPDATE ON lab.export_attempt
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
