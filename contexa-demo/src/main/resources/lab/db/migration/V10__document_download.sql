CREATE TABLE lab.document_file (
    id uuid PRIMARY KEY,
    visitor_id uuid NOT NULL,
    command_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    username varchar(80) NOT NULL,
    document_id varchar(60) NOT NULL,
    document_version integer NOT NULL,
    language varchar(2) NOT NULL CHECK (language IN ('KO', 'EN')),
    purpose varchar(40) NOT NULL,
    input_sha256 char(64) NOT NULL,
    filename varchar(120) NOT NULL,
    content bytea NOT NULL,
    content_sha256 char(64) NOT NULL,
    prepared_at timestamptz NOT NULL,
    UNIQUE (visitor_id, command_id),
    FOREIGN KEY (document_id, document_version) REFERENCES lab.business_document(id, version)
);
CREATE TRIGGER immutable_document_file BEFORE UPDATE ON lab.document_file
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
CREATE TABLE lab.document_download_attempt (
    request_id uuid PRIMARY KEY REFERENCES lab.business_request_snapshot(request_id),
    file_id uuid NOT NULL REFERENCES lab.document_file(id),
    reused boolean NOT NULL,
    prepared_at timestamptz NOT NULL
);
CREATE INDEX document_download_file ON lab.document_download_attempt (file_id);
CREATE TRIGGER immutable_document_download_attempt BEFORE UPDATE ON lab.document_download_attempt
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
