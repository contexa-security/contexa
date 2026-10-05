-- A run that used a development-only forced decision (never recorded or published, docs/showcase/P3-설계.md).
ALTER TABLE run ADD COLUMN forced_action VARCHAR(24);

-- The additional check of a control D step (deck p.12, P3-BE-01): the challenged request, whether the run principal
-- answered it (a legitimate user reads the demo inbox; an attacker has no mailbox), the one-time code round trip and
-- the re-issued original request with whether the engine analysed it again.
CREATE TABLE run_challenge (
    run_id              VARCHAR(40)   NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    step_no             INTEGER       NOT NULL,
    request_id          UUID          NOT NULL,
    challenged_at       TIMESTAMPTZ   NOT NULL,
    answered            BOOLEAN       NOT NULL,
    reason              VARCHAR(200),
    code_requested_at   TIMESTAMPTZ,
    verified_at         TIMESTAMPTZ,
    reissue_request_id  UUID,
    reissue_sent_at     TIMESTAMPTZ,
    reissue_status      INTEGER,
    reissue_outcome     VARCHAR(16),
    reissue_delivered   INTEGER,
    reissue_elapsed_ms  BIGINT,
    reissue_reanalysed  BOOLEAN,
    PRIMARY KEY (run_id, step_no)
);
