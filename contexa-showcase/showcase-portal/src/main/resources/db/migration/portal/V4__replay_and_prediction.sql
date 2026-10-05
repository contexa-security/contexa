-- P2 quick start (docs/showcase/P2-설계.md 5절): recorded replays of the representative pairs and visitor predictions.
-- A visitor is known only by the SHA-256 of the identifier inside the signed visitor cookie; no address is stored
-- (P2-DB-01, docs/showcase/개인정보-데이터목록.md).
CREATE TABLE visitor (
    visitor_hash   CHAR(64)    PRIMARY KEY,
    first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One prediction per visitor and scene; a second vote for the same scene is refused.
CREATE TABLE prediction (
    visitor_hash  CHAR(64)    NOT NULL REFERENCES visitor (visitor_hash) ON DELETE CASCADE,
    scene_key     VARCHAR(40) NOT NULL,
    choice        VARCHAR(16) NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (visitor_hash, scene_key),
    CONSTRAINT prediction_choice_chk CHECK (choice IN ('ALLOW', 'BLOCK'))
);

CREATE INDEX prediction_created_idx ON prediction (created_at);

-- A recorded scene: one scenario of a pair run n times on fresh principals under one execution specification. The
-- step evidence is not copied: it is read from the representative run (run_arm_result, run_decision,
-- run_business_evidence), so each fact has one source.
CREATE TABLE replay_record (
    record_id              VARCHAR(48)  PRIMARY KEY,
    pair_key               VARCHAR(16)  NOT NULL,
    scene                  VARCHAR(16)  NOT NULL,
    scenario_key           VARCHAR(48)  NOT NULL,
    scenario_version       INTEGER      NOT NULL,
    spec_hash              CHAR(64)     NOT NULL REFERENCES execution_spec (spec_hash),
    repetitions            INTEGER      NOT NULL CHECK (repetitions > 0),
    agreeing               INTEGER      NOT NULL CHECK (agreeing > 0),
    representative_run_id  VARCHAR(40)  NOT NULL REFERENCES run (run_id),
    outcome_signature      TEXT         NOT NULL,
    status                 VARCHAR(16)  NOT NULL,
    recorded_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    published_at           TIMESTAMPTZ,
    CONSTRAINT replay_record_scene_chk CHECK (scene IN ('ATTACK', 'LEGITIMATE')),
    CONSTRAINT replay_record_status_chk CHECK (status IN ('DRAFT', 'PUBLISHED', 'RETIRED')),
    CONSTRAINT replay_record_agreeing_chk CHECK (agreeing <= repetitions)
);

-- At most one published record per pair and scene.
CREATE UNIQUE INDEX replay_record_published_idx ON replay_record (pair_key, scene) WHERE status = 'PUBLISHED';

CREATE TABLE replay_run (
    record_id          VARCHAR(48) NOT NULL REFERENCES replay_record (record_id) ON DELETE CASCADE,
    run_id             VARCHAR(40) NOT NULL REFERENCES run (run_id),
    repetition         INTEGER     NOT NULL CHECK (repetition > 0),
    outcome_signature  TEXT        NOT NULL,
    PRIMARY KEY (record_id, run_id),
    CONSTRAINT replay_run_repetition_uq UNIQUE (record_id, repetition)
);
