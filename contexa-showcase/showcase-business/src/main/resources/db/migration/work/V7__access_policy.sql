-- The company's access approval rules for role grants, customer records and project documents as data both control C2
-- and control D read (docs/showcase/데모-재설계.md Q-A4, approval Q-45), the way V6 made the export rule data (H-15).
-- Before this, control C2 kept these rules in code and control D told the engine none of them, so the engine never
-- knew whether the company required an approval for these requests (ApprovalRequired stayed UNKNOWN). A ticket that
-- covers the request is the approval record of these rules. Company rules, not generated company data: the company
-- fingerprint and the engine templates do not change with them.
ALTER TABLE company_policy ALTER COLUMN assigned_export_limit DROP NOT NULL;
ALTER TABLE company_policy ALTER COLUMN ticket_and_oncall_exempt DROP NOT NULL;
ALTER TABLE company_policy ADD COLUMN account_manager_exempt BOOLEAN;
ALTER TABLE company_policy ADD COLUMN assigned_exempt BOOLEAN;
ALTER TABLE company_policy ADD COLUMN recent_work_days INTEGER CHECK (recent_work_days IS NULL OR recent_work_days > 0);

INSERT INTO company_policy (policy_key, description, account_manager_exempt, assigned_exempt, recent_work_days,
                            effective_from)
VALUES ('ROLE_GRANT_APPROVAL',
        'A role on a project is given only under an approved change ticket for that project.',
        false, false, NULL, DATE '2026-01-01'),
       ('CUSTOMER_ACCESS_APPROVAL',
        'A customer record is read by its account manager, or under a ticket that covers the customer''s project.',
        true, false, NULL, DATE '2026-01-01'),
       ('DOCUMENT_ACCESS_APPROVAL',
        'A project document is read by an employee assigned to the project or who worked on it in the last 90 days, '
            || 'or under a ticket that covers the project.',
        false, true, 90, DATE '2026-01-01');
