-- The company's export approval policy as data both control C2 and control D read (docs/showcase/데모-재설계.md H-15,
-- fabricated-data survey D1): before this, each side kept its own copy of the rule in code. It is a company rule, not
-- generated company data, so the company fingerprint and the engine templates do not change with it.
CREATE TABLE company_policy (
    policy_key                 VARCHAR(48)   PRIMARY KEY,
    description                VARCHAR(400)  NOT NULL,
    assigned_export_limit      INTEGER       NOT NULL CHECK (assigned_export_limit >= 0),
    ticket_and_oncall_exempt   BOOLEAN       NOT NULL,
    effective_from             DATE          NOT NULL
);

INSERT INTO company_policy (policy_key, description, assigned_export_limit, ticket_and_oncall_exempt, effective_from)
VALUES ('EXPORT_APPROVAL',
        'An export of project documents needs an approval that covers the project and the item count, except an '
            || 'export of an assigned project of at most the assigned export limit, or an export covered by a '
            || 'ticket while the requester is on call.',
        500, true, DATE '2026-01-01');

-- When an approval was decided (survey D5); unknown for approvals recorded without it.
ALTER TABLE approval ADD COLUMN approved_at TIMESTAMPTZ;
