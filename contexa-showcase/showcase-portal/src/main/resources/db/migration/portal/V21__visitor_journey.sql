-- Where a visitor is in the demo (work 14 of docs/showcase/화면설계서-v2-구현계획.md): the route, the act and the step,
-- the differences the visitor has seen, and the visitor's own calls before sending each experience. It goes with the
-- visitor when the visitor's 30 days are over (the retention job deletes the visitor row).
CREATE TABLE visitor_journey (
    visitor_hash   CHAR(64)      PRIMARY KEY REFERENCES visitor (visitor_hash) ON DELETE CASCADE,
    route          VARCHAR(8)    NOT NULL,
    act            INTEGER       NOT NULL,
    step           VARCHAR(40)   NOT NULL,
    differences    JSONB         NOT NULL DEFAULT '[]'::jsonb,
    predictions    JSONB         NOT NULL DEFAULT '{}'::jsonb,
    acts_reached   JSONB         NOT NULL DEFAULT '[]'::jsonb,
    quiz_answered  BOOLEAN       NOT NULL DEFAULT false,
    updated_at     TIMESTAMPTZ   NOT NULL,
    CONSTRAINT visitor_journey_route_chk CHECK (route IN ('DEFAULT', 'INTRO')),
    CONSTRAINT visitor_journey_act_chk CHECK (act BETWEEN 0 AND 4)
);
