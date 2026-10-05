-- Execution specification: every recorded or live result references the exact configuration that produced it.
-- The hash rule is documented in docs/showcase/실행명세.md and implemented by ExecutionSpecHasher.
CREATE TABLE execution_spec (
    spec_id               UUID         PRIMARY KEY,
    spec_hash             CHAR(64)     NOT NULL UNIQUE,
    code_commit           VARCHAR(64)  NOT NULL,
    engine_version        VARCHAR(64)  NOT NULL,
    effective_mode        VARCHAR(16)  NOT NULL,
    endpoint_protection   JSONB        NOT NULL,
    chat_model            VARCHAR(128) NOT NULL,
    embedding_model       VARCHAR(128) NOT NULL,
    embedding_dimensions  INTEGER      NOT NULL CHECK (embedding_dimensions > 0),
    prompt_hash           CHAR(64)     NOT NULL,
    template_id           VARCHAR(64),
    rule_version          CHAR(64)     NOT NULL,
    contract_version      CHAR(64),
    time_zone             VARCHAR(64)  NOT NULL,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT execution_spec_mode_chk CHECK (effective_mode IN ('ENFORCE', 'SHADOW', 'OBSERVE', 'DISABLED'))
);
