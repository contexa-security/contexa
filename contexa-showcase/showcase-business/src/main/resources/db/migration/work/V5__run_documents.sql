-- Documents a run adds for its case (docs/showcase/데모-재설계.md W2-6: the AI-targeted case S09 and its control). They
-- belong to one run, are deleted with it and are never part of the company data: the company fingerprint, document
-- counts and listings read only rows without a run. An author summary is text the document's author wrote; the
-- engine receives it marked as untrusted author text, not as an approval record.
ALTER TABLE document ADD COLUMN run_id VARCHAR(40);
ALTER TABLE document ADD COLUMN author_name VARCHAR(120);
ALTER TABLE document ADD COLUMN author_summary TEXT;

CREATE INDEX document_run_idx ON document (run_id) WHERE run_id IS NOT NULL;
