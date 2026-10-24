-- docs/agent A7-3: the business agent group (화면설계 4절): the main flow is eight groups, the agent group coming
-- sixth after the insider group, so the place is before the first (0) or one of the groups 1-8. A place kept in the
-- groups that moved (the comparison, sixth until now, and the summary, seventh until now) moves with them.
ALTER TABLE visitor_journey DROP CONSTRAINT visitor_journey_act_chk;
UPDATE visitor_journey SET act = act + 1 WHERE act >= 6;
ALTER TABLE visitor_journey ADD CONSTRAINT visitor_journey_act_chk CHECK (act BETWEEN 0 AND 8);

-- docs/agent A7-3: the confirmation control D asked of an agent's request in a run (A5-2): the delegating person's
-- answer, the confirmation as the agent read it after, and the engine's answers to the request sent again with it
-- (the request itself, the same once more, another request; A5-9).
CREATE TABLE run_agent_confirmation (
    run_id          VARCHAR(40)   PRIMARY KEY REFERENCES run (run_id) ON DELETE CASCADE,
    step_no         INTEGER       NOT NULL,
    confirmation_id VARCHAR(64),
    trigger         VARCHAR(40),
    expires_at      VARCHAR(40),
    decision        VARCHAR(8),
    reason          VARCHAR(300),
    asked_at        TIMESTAMPTZ,
    decided_at      TIMESTAMPTZ,
    decide_status   INTEGER,
    status_after    JSONB,
    resend          JSONB,
    reuse           JSONB,
    other           JSONB
);
