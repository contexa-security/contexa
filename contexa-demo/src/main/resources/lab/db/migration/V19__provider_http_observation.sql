CREATE TABLE lab.provider_http_observation (
    id uuid PRIMARY KEY,
    model_observation_id uuid NOT NULL,
    request_id uuid NOT NULL,
    observed_at timestamptz NOT NULL,
    payload jsonb NOT NULL,
    content_sha256 char(64) NOT NULL,
    collected_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX provider_http_request_idx ON lab.provider_http_observation (request_id, observed_at, id);
CREATE TRIGGER immutable_provider_http BEFORE UPDATE ON lab.provider_http_observation
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
INSERT INTO lab.observation_storage_limit VALUES ('provider_http_observation', 0, 0, 100000, 134217728);
CREATE TRIGGER limit_provider_http AFTER INSERT ON lab.provider_http_observation
    FOR EACH ROW EXECUTE FUNCTION lab.reserve_observation_storage();
ALTER TABLE lab.observation_collector_status DROP CONSTRAINT observation_collector_status_source_check;
ALTER TABLE lab.observation_collector_status ADD CONSTRAINT observation_collector_status_source_check
    CHECK (source IN ('HTTP', 'ENGINE', 'MODEL', 'PROVIDER'));
COMMENT ON TABLE lab.provider_http_observation IS
    'Synchronous RestClient HTTP boundary. Bounded sanitized bodies, explicit advisor scope, no headers. No server-receipt guarantee on transport failure.';
