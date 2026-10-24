-- The work a person delegated to an agent, as the company records it (docs/agent A7-0, A7-1). A token or a session
-- only states that an agent acts for a person; the delegation of record says what the person delegated: the
-- objective, the operations and resources, whether a person must approve, and until when. Contexa reads it through
-- its delegation record lookup (A1-4) and only narrows what the request stated.
CREATE TABLE agent_delegation (
    delegation_key     VARCHAR(80)   PRIMARY KEY,
    run_id             VARCHAR(40)   NOT NULL,
    delegator          VARCHAR(64)   NOT NULL REFERENCES employee (employee_key),
    agent_id           VARCHAR(120)  NOT NULL,
    objective_id       VARCHAR(80),
    objective_family   VARCHAR(80),
    summary            TEXT,
    operations         TEXT,
    resources          TEXT,
    approval_required  BOOLEAN       NOT NULL DEFAULT FALSE,
    valid_from         TIMESTAMPTZ   NOT NULL,
    expires_at         TIMESTAMPTZ   NOT NULL,
    revoked            BOOLEAN       NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT agent_delegation_period_chk CHECK (expires_at > valid_from)
);

CREATE INDEX agent_delegation_lookup_idx ON agent_delegation (delegator, agent_id);
CREATE INDEX agent_delegation_run_idx ON agent_delegation (run_id);
