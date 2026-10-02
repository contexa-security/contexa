CREATE TABLE lab.comparison_run (
    id uuid PRIMARY KEY,
    visitor_id uuid NOT NULL REFERENCES lab.visitor(id),
    workspace_id uuid NOT NULL REFERENCES lab.workspace(id),
    command_id uuid NOT NULL,
    coordinator_instance_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    dispatch_deadline timestamptz NOT NULL,
    input_sha256 char(64) NOT NULL,
    manifest_sha256 char(64) NOT NULL,
    manifest jsonb NOT NULL,
    state varchar(20) NOT NULL CHECK (state IN ('READY','RUNNING','RESPONDED','CANCELLED','EXPIRED','INTERRUPTED')),
    UNIQUE (visitor_id, command_id)
);
CREATE INDEX comparison_run_owner ON lab.comparison_run(visitor_id,created_at);
CREATE FUNCTION lab.protect_comparison_manifest() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (to_jsonb(NEW)-'state') IS DISTINCT FROM (to_jsonb(OLD)-'state') THEN
        RAISE EXCEPTION 'Comparison manifest is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER immutable_comparison_manifest BEFORE UPDATE ON lab.comparison_run
    FOR EACH ROW EXECUTE FUNCTION lab.protect_comparison_manifest();
CREATE TABLE lab.comparison_run_step (
    id uuid PRIMARY KEY,
    run_id uuid NOT NULL REFERENCES lab.comparison_run(id),
    arm varchar(12) NOT NULL CHECK (arm IN ('baseline','contexa')),
    ordinal integer NOT NULL CHECK (ordinal>0),
    state varchar(20) NOT NULL CHECK (state IN ('PLANNED','DISPATCHED','RESPONDED','NOT_DISPATCHED')),
    request_id uuid,
    started_at timestamptz,
    responded_at timestamptz,
    http_status integer,
    failure_type varchar(100),
    UNIQUE (run_id,arm,ordinal),
    UNIQUE (arm,request_id)
);
CREATE TABLE lab.comparison_run_event (
    sequence bigserial PRIMARY KEY,
    run_id uuid NOT NULL REFERENCES lab.comparison_run(id),
    step_id uuid REFERENCES lab.comparison_run_step(id),
    kind varchar(32) NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    detail varchar(200)
);
CREATE INDEX comparison_run_event_parent ON lab.comparison_run_event(run_id,sequence);
CREATE TRIGGER immutable_comparison_run_event BEFORE UPDATE ON lab.comparison_run_event
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
CREATE TABLE lab.comparison_run_creation_attempt (
    sequence bigserial PRIMARY KEY,
    run_id uuid NOT NULL REFERENCES lab.comparison_run(id),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    submitted_input_sha256 char(64) NOT NULL,
    outcome varchar(20) NOT NULL CHECK (outcome IN ('CREATED','REUSED','INPUT_CONFLICT'))
);
CREATE TRIGGER immutable_comparison_run_creation_attempt BEFORE UPDATE ON lab.comparison_run_creation_attempt
    FOR EACH ROW EXECUTE FUNCTION lab.reject_evidence_update();
