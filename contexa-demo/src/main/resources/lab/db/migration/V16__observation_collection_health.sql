ALTER TABLE lab.business_http_observation ADD COLUMN collector_instance_id uuid;

CREATE TABLE lab.observation_collector_status (
    instance_id uuid NOT NULL,
    source varchar(16) NOT NULL CHECK (source IN ('HTTP', 'ENGINE', 'MODEL')),
    started_at timestamptz NOT NULL,
    sampled_at timestamptz NOT NULL,
    lifecycle varchar(16) NOT NULL CHECK (lifecycle IN ('RUNNING', 'STOPPING', 'STOPPED')),
    offered bigint NOT NULL CHECK (offered >= 0),
    stored bigint NOT NULL CHECK (stored >= 0),
    rejected bigint NOT NULL CHECK (rejected >= 0),
    write_unconfirmed bigint NOT NULL CHECK (write_unconfirmed >= 0),
    abandoned bigint NOT NULL CHECK (abandoned >= 0),
    pending bigint NOT NULL CHECK (pending >= 0),
    in_flight bigint NOT NULL CHECK (in_flight BETWEEN 0 AND 1),
    PRIMARY KEY (instance_id, source),
    CHECK (offered = stored + rejected + write_unconfirmed + abandoned + pending + in_flight)
);

-- These are append quotas for demo observations, not the physical PostgreSQL file size.
-- Existing evidence remains intact; no automatic deletion or counter reset is performed.
CREATE TABLE lab.observation_storage_limit (
    table_name varchar(64) PRIMARY KEY,
    retained_rows bigint NOT NULL CHECK (retained_rows >= 0),
    retained_json_bytes bigint NOT NULL CHECK (retained_json_bytes >= 0),
    max_rows bigint NOT NULL CHECK (max_rows > 0),
    max_json_bytes bigint CHECK (max_json_bytes > 0)
);
INSERT INTO lab.observation_storage_limit
SELECT 'business_http_observation', count(*),
       coalesce(sum(octet_length(to_jsonb(value)::text)), 0), 100000, 134217728
FROM lab.business_http_observation value;
INSERT INTO lab.observation_storage_limit
SELECT 'engine_observation', count(*),
       coalesce(sum(octet_length(to_jsonb(value)::text)), 0), 100000, 134217728
FROM lab.engine_observation value;
INSERT INTO lab.observation_storage_limit
SELECT 'model_boundary_observation', count(*),
       coalesce(sum(octet_length(to_jsonb(value)::text)), 0), 100000, 134217728
FROM lab.model_boundary_observation value;
INSERT INTO lab.observation_storage_limit VALUES ('observation_collector_status', 0, 0, 1024, null);

CREATE FUNCTION lab.reserve_observation_storage() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    row_bytes bigint;
BEGIN
    row_bytes := CASE WHEN TG_TABLE_NAME = 'observation_collector_status' THEN 0
                      ELSE octet_length(to_jsonb(NEW)::text) END;
    UPDATE lab.observation_storage_limit
       SET retained_rows = retained_rows + 1,
           retained_json_bytes = retained_json_bytes + row_bytes
     WHERE table_name = TG_TABLE_NAME
       AND retained_rows < max_rows
       AND (max_json_bytes IS NULL OR retained_json_bytes + row_bytes <= max_json_bytes);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Demo observation storage limit reached for %', TG_TABLE_NAME USING ERRCODE = '54000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER limit_http_observation AFTER INSERT ON lab.business_http_observation
    FOR EACH ROW EXECUTE FUNCTION lab.reserve_observation_storage();
CREATE TRIGGER limit_engine_observation AFTER INSERT ON lab.engine_observation
    FOR EACH ROW EXECUTE FUNCTION lab.reserve_observation_storage();
CREATE TRIGGER limit_model_observation AFTER INSERT ON lab.model_boundary_observation
    FOR EACH ROW EXECUTE FUNCTION lab.reserve_observation_storage();
CREATE TRIGGER limit_collector_status AFTER INSERT ON lab.observation_collector_status
    FOR EACH ROW EXECUTE FUNCTION lab.reserve_observation_storage();
