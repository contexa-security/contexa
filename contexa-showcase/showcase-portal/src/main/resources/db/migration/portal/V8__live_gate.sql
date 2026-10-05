-- Live runs of visitors (P4): which runs were live and for whom, so the daily allotment counts only their cost.
ALTER TABLE run ADD COLUMN live_visitor_hash CHAR(64);

-- Daily live-run counts per visitor and per address (deck p.28). The address is kept only as a keyed hash that
-- changes every day, never as the address itself (P2-DB-01).
CREATE TABLE live_quota (
    day           DATE         NOT NULL,
    subject_kind  VARCHAR(8)   NOT NULL,
    subject_hash  CHAR(64)     NOT NULL,
    used          INTEGER      NOT NULL DEFAULT 0,
    PRIMARY KEY (day, subject_kind, subject_hash),
    CONSTRAINT live_quota_kind_chk CHECK (subject_kind IN ('VISITOR', 'ADDRESS'))
);

-- The day the 80 percent alert of the daily allotment was raised, so it is raised once a day.
CREATE TABLE live_allotment_alert (
    day         DATE          PRIMARY KEY,
    alerted_at  TIMESTAMPTZ   NOT NULL DEFAULT now()
);
