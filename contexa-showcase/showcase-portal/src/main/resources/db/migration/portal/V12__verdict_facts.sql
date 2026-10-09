-- W1 of docs/showcase/데모-재설계.md: the facts behind every verdict, kept as they happened, so the screens show recorded
-- data only and never data made up afterwards.

-- The scenario definition each run executed, ground truth included (F-19): the catalogue keeps only the current
-- version, so an older run is scored against the definition it really ran.
ALTER TABLE run ADD COLUMN scenario_definition JSONB;
ALTER TABLE run ADD COLUMN scenario_sha256 CHAR(64);

-- The model settings sent with every analysis (reasoning effort, verbosity, output limit per layer; R-20): they change
-- the verdicts, so they are part of the execution specification. Older specifications have none.
ALTER TABLE execution_spec ADD COLUMN model_settings JSONB;

-- The engine's system prompt, stored once per hash (it is the same for every user, about 14 KB).
CREATE TABLE run_system_prompt (
    system_prompt_sha256  CHAR(64)     PRIMARY KEY,
    prompt_text           TEXT         NOT NULL,
    first_seen_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Every model call of a decision as control D saw it (5.1, R-22, R-23): the user prompt as sent, the provider request
-- options without the messages, the provider response body and the answer, finish reason and tokens read from it.
-- Only HTTP session identifiers are masked; masked_places counts them. Kept 90 days (K-5).
CREATE TABLE run_model_exchange (
    request_id            UUID          NOT NULL,
    call_no               INTEGER       NOT NULL,
    run_id                VARCHAR(40)   NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    step_no               INTEGER       NOT NULL,
    model                 VARCHAR(80),
    system_prompt_sha256  CHAR(64)      REFERENCES run_system_prompt (system_prompt_sha256),
    user_prompt           TEXT,
    answer                TEXT,
    finish_reason         VARCHAR(32),
    prompt_tokens         BIGINT,
    completion_tokens     BIGINT,
    reasoning_tokens      BIGINT,
    elapsed_ms            BIGINT,
    success               BOOLEAN       NOT NULL,
    failure               VARCHAR(120),
    request_options       JSONB,
    http_status           INTEGER,
    provider_response     TEXT,
    masked_places         INTEGER       NOT NULL DEFAULT 0,
    finished_at           TIMESTAMPTZ,
    captured_at           TIMESTAMPTZ   NOT NULL DEFAULT now(),
    PRIMARY KEY (request_id, call_no)
);

CREATE INDEX run_model_exchange_run_idx ON run_model_exchange (run_id, step_no);
CREATE INDEX run_model_exchange_captured_idx ON run_model_exchange (captured_at);

-- The assembled verdict anatomy of a decision (5.2): what the engine received, what the model answered, what the
-- engine recorded, and the ground truth. Built from the rows above when the step ends; kept with the run.
CREATE TABLE run_decision_anatomy (
    request_id       UUID         PRIMARY KEY REFERENCES run_decision (request_id) ON DELETE CASCADE,
    anatomy          JSONB        NOT NULL,
    builder_version  INTEGER      NOT NULL,
    built_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- A release from a block of control D (F-23, ADR-34): the check of the blocked account, the release request, the
-- approver's decision with the engine's block record as the approver read it, and the re-issued request.
CREATE TABLE run_release (
    run_id              VARCHAR(40)   NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    step_no             INTEGER       NOT NULL,
    request_id          UUID,
    released            BOOLEAN       NOT NULL,
    reason              VARCHAR(40)   NOT NULL,
    blocked_at          TIMESTAMPTZ,
    code_requested_at   TIMESTAMPTZ,
    verified_at         TIMESTAMPTZ,
    requested_at        TIMESTAMPTZ,
    approved_at         TIMESTAMPTZ,
    block_record        JSONB,
    reissue_request_id  UUID,
    reissue_sent_at     TIMESTAMPTZ,
    reissue_status      INTEGER,
    reissue_outcome     VARCHAR(16),
    reissue_delivered   INTEGER,
    reissue_elapsed_ms  BIGINT,
    PRIMARY KEY (run_id, step_no)
);
