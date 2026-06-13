-- System Settings Singleton Seed
-- Loaded by IamSeedDataAutoConfiguration after data.sql / data-menu.sql.
-- WHERE NOT EXISTS makes it idempotent across restarts and re-applies.
-- Schema source-of-truth: contexa_tables.sql (operational DB dump 2026-05-07).
--   Required NOT NULL columns: audit_log_retention_days, registration_enabled,
--   created_at, policy_combining_algorithm, default_role.
INSERT INTO system_settings (audit_log_retention_days, default_role, policy_combining_algorithm, registration_enabled, created_at)
SELECT 90, 'ROLE_USER', 'FIRST_APPLICABLE', FALSE, CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT 1 FROM system_settings);

-- Keep future settings rows safe when manual data was loaded with explicit ids.
DO $$
DECLARE
    max_id BIGINT;
BEGIN
    BEGIN
        SELECT MAX(id) INTO max_id FROM system_settings;
        IF max_id IS NOT NULL THEN
            EXECUTE format('SELECT setval(%L, %s, true)', 'system_settings_id_seq', max_id);
        END IF;
    EXCEPTION WHEN undefined_table OR undefined_column OR undefined_object OR insufficient_privilege THEN
        NULL;
    END;
END $$;
