-- Registered business trips (deck A1: "a normal sign-in from a business trip"). A trip names the network the
-- employee works from while away; run_id NULL = company fact, otherwise a fact chosen for one run.
CREATE TABLE travel_plan (
    plan_key      VARCHAR(48)   PRIMARY KEY,
    run_id        VARCHAR(40),
    employee_key  VARCHAR(64)   NOT NULL REFERENCES employee (employee_key),
    city          VARCHAR(64)   NOT NULL,
    country       CHAR(2)       NOT NULL,
    network_cidr  VARCHAR(43)   NOT NULL,
    valid_from    TIMESTAMPTZ   NOT NULL,
    valid_until   TIMESTAMPTZ   NOT NULL,
    CONSTRAINT travel_plan_period_chk CHECK (valid_until > valid_from)
);

CREATE INDEX travel_plan_employee_idx ON travel_plan (employee_key, valid_from);
CREATE INDEX travel_plan_run_idx ON travel_plan (run_id);
