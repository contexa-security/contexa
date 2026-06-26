-- System Settings Singleton Seed
-- Loaded by IamSeedDataAutoConfiguration after data.sql / data-menu.sql.
-- WHERE NOT EXISTS makes it idempotent across restarts and re-applies.
-- Schema source-of-truth: db/schema.sql.
INSERT INTO system_settings (
    audit_log_retention_days,
    default_role,
    policy_combining_algorithm,
    registration_enabled,
    hcad_medium_risk_score,
    hcad_high_risk_score,
    hcad_redline_score,
    hcad_failed_login_burst_threshold,
    hcad_request_burst_threshold,
    hcad_semantic_risk_similarity_threshold,
    hcad_semantic_normal_similarity_threshold,
    mvc_resource_scanner_base_packages,
    created_at)
SELECT
    90,
    'ROLE_USER',
    'FIRST_APPLICABLE',
    FALSE,
    30,
    50,
    70,
    3,
    12,
    0.80,
    0.85,
    'io.contexa.contexaiam.',
    CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT 1 FROM system_settings);

-- Keep future settings rows safe when manual data was loaded with explicit ids.
-- Use a plain statement because Spring SQL initialization splits this file on
-- semicolons and cannot safely execute procedural blocks.
SELECT setval('system_settings_id_seq', GREATEST(COALESCE((SELECT MAX(id) FROM system_settings), 0), 1), COALESCE((SELECT MAX(id) FROM system_settings), 0) > 0)
WHERE to_regclass('system_settings_id_seq') IS NOT NULL;