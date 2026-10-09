-- The representative runs the visitor's first screen replays (work 17 of docs/showcase/화면설계서-v2-구현계획.md): one
-- measured run of the attacker's case and one of the real employee's, designated by the operator. A designation goes
-- with its run.
CREATE TABLE hook_designation (
    slot           VARCHAR(16)   PRIMARY KEY,
    run_id         VARCHAR(40)   NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    designated_at  TIMESTAMPTZ   NOT NULL,
    CONSTRAINT hook_designation_slot_chk CHECK (slot IN ('ATTACKER', 'OWNER'))
);
