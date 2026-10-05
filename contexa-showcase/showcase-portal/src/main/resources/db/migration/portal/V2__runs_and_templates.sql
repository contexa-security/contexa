-- Learned engine templates and orchestrated runs (docs/showcase/ADR.md ADR-23, plan 3.3).

-- One learning attempt of a protagonist's template; READY rows hold the snapshot runs are cloned from.
CREATE TABLE engine_template (
    template_id            VARCHAR(48)   PRIMARY KEY,
    employee_key           VARCHAR(64)   NOT NULL,
    company_seed           BIGINT        NOT NULL,
    company_anchor         DATE          NOT NULL,
    company_sha256         CHAR(64)      NOT NULL,
    status                 VARCHAR(16)   NOT NULL,
    attempt                INTEGER       NOT NULL,
    requests               INTEGER       NOT NULL DEFAULT 0,
    allowed                INTEGER       NOT NULL DEFAULT 0,
    baseline_update_count  BIGINT,
    work_profile_observations INTEGER,
    memory_documents       INTEGER,
    snapshot               JSONB,
    failure                VARCHAR(500),
    chat_model             VARCHAR(128),
    embedding_model        VARCHAR(128),
    created_at             TIMESTAMPTZ   NOT NULL DEFAULT now(),
    ready_at               TIMESTAMPTZ,
    CONSTRAINT engine_template_status_chk CHECK (status IN ('LEARNING', 'READY', 'FAILED', 'RETIRED'))
);

CREATE INDEX engine_template_ready_idx ON engine_template (employee_key, status, ready_at DESC);

-- Every replayed request of a template learning attempt and the engine decision it received.
CREATE TABLE template_step (
    template_id         VARCHAR(48)   NOT NULL REFERENCES engine_template (template_id) ON DELETE CASCADE,
    step_no             INTEGER       NOT NULL,
    request_id          UUID          NOT NULL,
    operation           VARCHAR(24)   NOT NULL,
    target_key          VARCHAR(48)   NOT NULL,
    company_time        TIMESTAMPTZ   NOT NULL,
    http_status         INTEGER,
    final_action        VARCHAR(24),
    technical_fallback  BOOLEAN,
    waited_ms           BIGINT,
    PRIMARY KEY (template_id, step_no)
);

CREATE TABLE run (
    run_id            VARCHAR(40)   PRIMARY KEY,
    scenario_key      VARCHAR(48)   NOT NULL,
    scenario_version  INTEGER       NOT NULL,
    employee_key      VARCHAR(64)   NOT NULL,
    principal         VARCHAR(80)   NOT NULL,
    template_id       VARCHAR(48)   REFERENCES engine_template (template_id),
    organization_id   VARCHAR(64)   NOT NULL,
    tenant_id         VARCHAR(64)   NOT NULL,
    client_ip         VARCHAR(45)   NOT NULL,
    device            VARCHAR(300)  NOT NULL,
    company_time      TIMESTAMPTZ   NOT NULL,
    status            VARCHAR(16)   NOT NULL,
    failure           VARCHAR(500),
    spec_hash         CHAR(64),
    cleanup           JSONB,
    started_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
    finished_at       TIMESTAMPTZ,
    CONSTRAINT run_status_chk CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED'))
);

CREATE INDEX run_scenario_idx ON run (scenario_key, started_at);

-- The HTTP response and business outcome of one step in one control (deck p.24: HTTP response, business result).
CREATE TABLE run_arm_result (
    run_id            VARCHAR(40)   NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    step_no           INTEGER       NOT NULL,
    control           VARCHAR(4)    NOT NULL,
    request_id        UUID          NOT NULL,
    operation         VARCHAR(24)   NOT NULL,
    method            VARCHAR(8)    NOT NULL,
    path              VARCHAR(300)  NOT NULL,
    company_time      TIMESTAMPTZ   NOT NULL,
    http_status       INTEGER,
    outcome           VARCHAR(16)   NOT NULL,
    delivered_items   INTEGER       NOT NULL DEFAULT 0,
    rule_id           VARCHAR(48),
    reason            VARCHAR(500),
    response_excerpt  TEXT,
    elapsed_ms        BIGINT,
    sent_at           TIMESTAMPTZ   NOT NULL,
    PRIMARY KEY (run_id, step_no, control),
    CONSTRAINT run_arm_result_control_chk CHECK (control IN ('A', 'B', 'C1', 'C2', 'D')),
    CONSTRAINT run_arm_result_outcome_chk CHECK (outcome IN ('DELIVERED', 'REFUSED', 'NOT_FOUND', 'ERROR', 'CUT'))
);

-- The engine decision of a control D step (deck p.24: engine decision, time of application).
CREATE TABLE run_decision (
    request_id          UUID          PRIMARY KEY,
    run_id              VARCHAR(40)   NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    step_no             INTEGER       NOT NULL,
    final_action        VARCHAR(24),
    proposed_action     VARCHAR(24),
    risk_score          DOUBLE PRECISION,
    confidence          DOUBLE PRECISION,
    technical_fallback  BOOLEAN,
    success             BOOLEAN,
    failure_type        VARCHAR(64),
    fallback_category   VARCHAR(64),
    reasoning           TEXT,
    mitre               VARCHAR(32),
    applied             VARCHAR(16)   NOT NULL,
    total_analysis_ms   BIGINT,
    llm_latency_ms      BIGINT,
    prompt_tokens       BIGINT,
    completion_tokens   BIGINT,
    total_tokens        BIGINT,
    model_calls         INTEGER,
    decided_at          TIMESTAMPTZ,
    records             JSONB         NOT NULL,
    events              JSONB         NOT NULL,
    CONSTRAINT run_decision_applied_chk CHECK (applied IN ('BEFORE_RESPONSE', 'NEXT_REQUEST', 'NONE'))
);

CREATE INDEX run_decision_run_idx ON run_decision (run_id, step_no);

-- Business evidence the plain controls stored for the run (export outcomes, rule decisions).
CREATE TABLE run_business_evidence (
    run_id          VARCHAR(40)  PRIMARY KEY REFERENCES run (run_id) ON DELETE CASCADE,
    exports         JSONB        NOT NULL,
    rule_decisions  JSONB        NOT NULL
);

-- Model usage per run or template (P1-OPS-01 measurement, later the daily allotment).
CREATE TABLE cost_ledger (
    entry_id           UUID          PRIMARY KEY,
    run_id             VARCHAR(40),
    template_id        VARCHAR(48),
    request_id         UUID,
    kind               VARCHAR(16)   NOT NULL,
    model              VARCHAR(128),
    prompt_tokens      BIGINT        NOT NULL,
    completion_tokens  BIGINT        NOT NULL,
    total_tokens       BIGINT        NOT NULL,
    elapsed_ms         BIGINT,
    recorded_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT cost_ledger_kind_chk CHECK (kind IN ('CHAT', 'EMBEDDING'))
);

CREATE INDEX cost_ledger_run_idx ON cost_ledger (run_id);
CREATE INDEX cost_ledger_template_idx ON cost_ledger (template_id);
