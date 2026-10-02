CREATE TABLE lab.workspace_slot (
    id varchar(40) PRIMARY KEY,
    generation uuid NOT NULL,
    baseline_url text NOT NULL,
    contexa_url text NOT NULL,
    state varchar(30) NOT NULL DEFAULT 'PREPARING'
        CHECK (state IN ('PREPARING', 'AVAILABLE', 'LEASED', 'RESET_REQUIRED')),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE lab.workspace_slot_worker (
    slot_id varchar(40) NOT NULL REFERENCES lab.workspace_slot(id),
    generation uuid NOT NULL,
    arm varchar(12) NOT NULL CHECK (arm IN ('baseline', 'contexa')),
    instance_id uuid NOT NULL,
    registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (slot_id, generation, arm)
);

CREATE TABLE lab.workspace_lease (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL UNIQUE REFERENCES lab.workspace(id),
    visitor_id uuid NOT NULL REFERENCES lab.visitor(id),
    slot_id varchar(40) NOT NULL REFERENCES lab.workspace_slot(id),
    generation uuid NOT NULL,
    state varchar(20) NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'EXPIRED', 'CANCELLED')),
    baseline_url text NOT NULL,
    contexa_url text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    comparison_limit integer NOT NULL CHECK (comparison_limit BETWEEN 1 AND 3),
    comparison_used integer NOT NULL DEFAULT 0 CHECK (comparison_used >= 0),
    chat_limit integer NOT NULL CHECK (chat_limit BETWEEN 1 AND 24),
    chat_used integer NOT NULL DEFAULT 0 CHECK (chat_used >= 0),
    embedding_limit integer NOT NULL CHECK (embedding_limit BETWEEN 1 AND 48),
    embedding_used integer NOT NULL DEFAULT 0 CHECK (embedding_used >= 0),
    work_limit integer NOT NULL CHECK (work_limit BETWEEN 1 AND 60),
    work_used integer NOT NULL DEFAULT 0 CHECK (work_used >= 0),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 minutes'),
    CHECK (comparison_used <= comparison_limit AND chat_used <= chat_limit
        AND embedding_used <= embedding_limit AND work_used <= work_limit)
);
CREATE UNIQUE INDEX workspace_lease_slot_exclusive ON lab.workspace_lease(slot_id) WHERE state = 'ACTIVE';
CREATE UNIQUE INDEX workspace_lease_owner_exclusive ON lab.workspace_lease(visitor_id) WHERE state = 'ACTIVE';
CREATE INDEX workspace_lease_expiry ON lab.workspace_lease(expires_at) WHERE state = 'ACTIVE';

CREATE TABLE lab.workspace_budget_attempt (
    id uuid PRIMARY KEY,
    lease_id uuid NOT NULL REFERENCES lab.workspace_lease(id),
    kind varchar(30) NOT NULL CHECK (kind IN ('COMPARISON', 'CHAT', 'EMBEDDING', 'WORK')),
    source_id uuid,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX workspace_budget_attempt_owner ON lab.workspace_budget_attempt(lease_id, created_at);

CREATE FUNCTION lab.prevent_workspace_budget_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'workspace budget attempt is immutable';
END;
$$;
CREATE TRIGGER immutable_workspace_budget_attempt BEFORE UPDATE ON lab.workspace_budget_attempt
FOR EACH ROW EXECUTE FUNCTION lab.prevent_workspace_budget_mutation();
