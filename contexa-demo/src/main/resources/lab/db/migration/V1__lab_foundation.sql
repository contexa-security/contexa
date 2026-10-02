CREATE TABLE lab.account (
    username varchar(80) PRIMARY KEY,
    display_name varchar(120) NOT NULL,
    password_hash varchar(255) NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE lab.account_role (
    username varchar(80) NOT NULL REFERENCES lab.account(username),
    authority varchar(80) NOT NULL,
    PRIMARY KEY (username, authority)
);
CREATE TABLE lab.scenario_version (
    id uuid PRIMARY KEY,
    scenario_key varchar(40) NOT NULL,
    version integer NOT NULL CHECK (version > 0),
    definition jsonb NOT NULL,
    oracle jsonb NOT NULL,
    content_sha256 char(64) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scenario_key, version)
);
CREATE TABLE lab.experiment (
    id uuid PRIMARY KEY,
    owner_username varchar(80) NOT NULL REFERENCES lab.account(username),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE lab.run_manifest (
    id uuid PRIMARY KEY,
    experiment_id uuid NOT NULL REFERENCES lab.experiment(id),
    scenario_version_id uuid NOT NULL REFERENCES lab.scenario_version(id),
    previous_run_id uuid REFERENCES lab.run_manifest(id),
    manifest jsonb NOT NULL,
    content_sha256 char(64) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE lab.run_event (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id uuid NOT NULL REFERENCES lab.run_manifest(id),
    event_type varchar(80) NOT NULL,
    source_timestamp timestamptz NOT NULL,
    collected_at timestamptz NOT NULL DEFAULT now(),
    payload jsonb NOT NULL
);
CREATE INDEX run_event_run_sequence ON lab.run_event (run_id, sequence);
CREATE TABLE lab.request_observation (
    id uuid PRIMARY KEY,
    run_id uuid NOT NULL REFERENCES lab.run_manifest(id),
    arm varchar(12) NOT NULL CHECK (arm IN ('BASELINE', 'CONTEXA')),
    step_id varchar(100) NOT NULL,
    request_id varchar(150) NOT NULL,
    method varchar(12) NOT NULL,
    path text NOT NULL,
    issued_at timestamptz NOT NULL,
    completed_at timestamptz,
    http_status integer CHECK (http_status BETWEEN 100 AND 599),
    received_bytes bigint CHECK (received_bytes >= 0),
    failure_type varchar(80),
    UNIQUE (run_id, arm, request_id)
);
CREATE TABLE lab.source_evidence (
    id uuid PRIMARY KEY,
    request_observation_id uuid REFERENCES lab.request_observation(id),
    source_owner varchar(60) NOT NULL,
    source_kind varchar(80) NOT NULL,
    source_id text NOT NULL,
    observed_at timestamptz NOT NULL,
    collected_at timestamptz NOT NULL DEFAULT now(),
    provenance varchar(30) NOT NULL CHECK (provenance IN
        ('LIVE_OBSERVATION', 'BUSINESS_CONFIGURATION', 'CAPTURED_HISTORY', 'CONTROLLED_INPUT', 'MODEL_CLAIM', 'EVALUATION')),
    snapshot jsonb NOT NULL,
    content_sha256 char(64) NOT NULL
);
CREATE INDEX evidence_request ON lab.source_evidence (request_observation_id);
CREATE TABLE lab.model_attempt (
    id uuid PRIMARY KEY,
    request_observation_id uuid NOT NULL REFERENCES lab.request_observation(id),
    source_event_id text NOT NULL,
    analysis_generation text NOT NULL,
    layer varchar(40) NOT NULL,
    source_attempt_id text NOT NULL,
    started_at timestamptz NOT NULL,
    completed_at timestamptz,
    input_evidence_id uuid REFERENCES lab.source_evidence(id),
    output_evidence_id uuid REFERENCES lab.source_evidence(id),
    failure_type varchar(80),
    UNIQUE (request_observation_id, analysis_generation, source_attempt_id)
);
CREATE TABLE lab.enforcement_observation (
    id uuid PRIMARY KEY,
    request_observation_id uuid NOT NULL REFERENCES lab.request_observation(id),
    decision_source_id text,
    decision_request_id text,
    applied_action varchar(40),
    observed_at timestamptz NOT NULL,
    evidence_id uuid NOT NULL REFERENCES lab.source_evidence(id)
);
CREATE TABLE lab.readiness_snapshot (
    id uuid PRIMARY KEY,
    role varchar(12) NOT NULL CHECK (role IN ('portal', 'baseline', 'contexa')),
    observed_at timestamptz NOT NULL,
    snapshot jsonb NOT NULL,
    content_sha256 char(64) NOT NULL
);
CREATE TABLE lab.authentication_observation (
    id uuid PRIMARY KEY,
    username varchar(80),
    event_type varchar(40) NOT NULL,
    occurred_at timestamptz NOT NULL,
    request_id uuid NOT NULL,
    http_status integer NOT NULL,
    role varchar(12) NOT NULL
);
CREATE FUNCTION lab.reject_evidence_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Lab evidence is append-only; retain prior versions';
END;
$$;
CREATE TRIGGER immutable_manifest BEFORE UPDATE ON lab.run_manifest
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
CREATE TRIGGER immutable_scenario BEFORE UPDATE ON lab.scenario_version
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
CREATE TRIGGER immutable_source_evidence BEFORE UPDATE ON lab.source_evidence
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
CREATE TRIGGER immutable_run_event BEFORE UPDATE ON lab.run_event
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
