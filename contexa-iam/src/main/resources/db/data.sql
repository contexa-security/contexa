-- ============================================================
-- Contexa IAM Seed Data
-- Schema source-of-truth: contexa_tables.sql (operational DB dump 2026-05-07).
-- All INSERTs satisfy NOT NULL columns and are idempotent (ON CONFLICT DO NOTHING).
-- ============================================================

-- ----------------------------------------------------------------
-- USERS — required NOT NULL: account_locked, bridge_managed,
-- credentials_expired, enabled, external_auth_only,
-- failed_login_attempts, mfa_enabled, created_at, name, username, password.
-- ----------------------------------------------------------------
INSERT INTO USERS (id, username, password, name, email, mfa_enabled, enabled, account_locked, bridge_managed, credentials_expired, external_auth_only, failed_login_attempts, created_at) VALUES
    (1, 'admin',     '{bcrypt}$2a$06$8zyaQFyvO1gn1gbPp.bjrumKfRFif3CiDgpqK4aB4n8Gl2cbTOxJy', '최고관리자', 'admin@gmail.com', TRUE,  TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP),
    (2, 'manager',   '{bcrypt}$2a$06$8zyaQFyvO1gn1gbPp.bjrumKfRFif3CiDgpqK4aB4n8Gl2cbTOxJy', '김팀장',     'manager@gmail.com',TRUE,  TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP),
    (3, 'developer', '{bcrypt}$2a$06$8zyaQFyvO1gn1gbPp.bjrumKfRFif3CiDgpqK4aB4n8Gl2cbTOxJy', '박개발',     'developer@gmail.com',FALSE, TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP),
    (4, 'user',      '{bcrypt}$2a$06$8zyaQFyvO1gn1gbPp.bjrumKfRFif3CiDgpqK4aB4n8Gl2cbTOxJy', '이운영',     'user@gmail.com',FALSE, TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP),
    (5, 'finance',   '{bcrypt}$2a$06$8zyaQFyvO1gn1gbPp.bjrumKfRFif3CiDgpqK4aB4n8Gl2cbTOxJy', '최재무',     'finance@gmail.com',TRUE,  TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP)
ON CONFLICT (id) DO NOTHING;

-- ----------------------------------------------------------------
-- APP_GROUP — required NOT NULL: enabled, created_at, group_name.
-- ----------------------------------------------------------------
INSERT INTO APP_GROUP (group_id, group_name, description, enabled, created_at) VALUES
    (1, '시스템관리자',  '시스템 전체 관리 및 최고 권한 보유',  TRUE, CURRENT_TIMESTAMP),
    (2, '개발본부',      '소프트웨어 개발 및 연구 부서',        TRUE, CURRENT_TIMESTAMP),
    (3, '인프라보안팀',  '서버, 네트워크, 보안 인프라 관리팀',  TRUE, CURRENT_TIMESTAMP),
    (4, '재무회계팀',    '회사의 재무 및 회계 업무 담당팀',     TRUE, CURRENT_TIMESTAMP)
ON CONFLICT (group_id) DO NOTHING;

-- ----------------------------------------------------------------
-- ROLE — required NOT NULL: enabled, expression, created_at, role_name.
-- ----------------------------------------------------------------
INSERT INTO ROLE (role_id, role_name, role_desc, enabled, expression, created_at) VALUES
    (1, 'ROLE_ADMIN',     '시스템 전체 관리자 역할',                                   TRUE, FALSE, CURRENT_TIMESTAMP),
    (2, 'ROLE_DEVELOPER', '개발팀 역할 - 소프트웨어 개발 및 고객 데이터 관리',         TRUE, FALSE, CURRENT_TIMESTAMP),
    (3, 'ROLE_INFRA',     '인프라팀 역할 - 시스템 운영 및 보안 관리',                  TRUE, FALSE, CURRENT_TIMESTAMP),
    (4, 'ROLE_FINANCE',   '재무팀 역할 - 회계 및 재무 데이터 관리',                    TRUE, FALSE, CURRENT_TIMESTAMP),
    (5, 'ROLE_USER',      '일반 사용자 역할',                                          TRUE, FALSE, CURRENT_TIMESTAMP)
ON CONFLICT (role_id) DO NOTHING;

-- ----------------------------------------------------------------
-- USER_GROUPS — required NOT NULL: assigned_at, group_id, user_id.
-- ----------------------------------------------------------------
INSERT INTO USER_GROUPS (user_id, group_id, assigned_at) VALUES
    (1, 1, CURRENT_TIMESTAMP),
    (2, 2, CURRENT_TIMESTAMP),
    (3, 2, CURRENT_TIMESTAMP),
    (4, 3, CURRENT_TIMESTAMP),
    (5, 4, CURRENT_TIMESTAMP)
ON CONFLICT (group_id, user_id) DO NOTHING;

-- ----------------------------------------------------------------
-- GROUP_ROLES — required NOT NULL: assigned_at, group_id, role_id.
-- ----------------------------------------------------------------
INSERT INTO GROUP_ROLES (group_id, role_id, assigned_at) VALUES
    (1, 1, CURRENT_TIMESTAMP),
    (2, 2, CURRENT_TIMESTAMP),
    (3, 3, CURRENT_TIMESTAMP),
    (4, 4, CURRENT_TIMESTAMP)
ON CONFLICT (group_id, role_id) DO NOTHING;

-- ----------------------------------------------------------------
-- ROLE_HIERARCHY_CONFIG — required NOT NULL: is_active, hierarchy_string.
-- ----------------------------------------------------------------
INSERT INTO ROLE_HIERARCHY_CONFIG (hierarchy_id, description, hierarchy_string, is_active) VALUES
    (1, '표준 4단계 역할 계층', 'ROLE_ADMIN > ROLE_DEVELOPER\nROLE_DEVELOPER > ROLE_INFRA\nROLE_INFRA > ROLE_USER', TRUE)
ON CONFLICT (hierarchy_id) DO NOTHING;



-- ----------------------------------------------------------------
-- POLICY — canonical seed policies.
-- id=1 is the public login page. id=2 protects the remaining admin area.
-- NOT NULL: is_active, priority, created_at, effect, name.
-- ----------------------------------------------------------------
INSERT INTO POLICY (
    id, name, description, effect, priority, is_active,
    source, approval_status, friendly_description, created_at
) VALUES
    (
        1,
        'ALLOW_CONTEXA_ADMIN_LOGIN',
        '/contexa/admin/login 로그인 화면은 인증 전에도 접근할 수 있습니다.',
        'ALLOW',
        10,
        TRUE,
        'MANUAL',
        'NOT_REQUIRED',
        '로그인 화면은 모든 사용자에게 공개됩니다.',
        CURRENT_TIMESTAMP
    ),
    (
        2,
        'ALLOW_CONTEXA_ADMIN_AUTHENTICATED',
        '/contexa/admin/** 관리자 영역은 인증된 사용자만 접근할 수 있습니다.',
        'ALLOW',
        100,
        TRUE,
        'MANUAL',
        'NOT_REQUIRED',
        '인증된 사용자만 관리자 보호 리소스에 접근할 수 있습니다.',
        CURRENT_TIMESTAMP
    )
ON CONFLICT (id) DO UPDATE SET
                               name = EXCLUDED.name,
                               description = EXCLUDED.description,
                               effect = EXCLUDED.effect,
                               priority = EXCLUDED.priority,
                               is_active = EXCLUDED.is_active,
                               source = EXCLUDED.source,
                               approval_status = EXCLUDED.approval_status,
                               friendly_description = EXCLUDED.friendly_description,
                               updated_at = CURRENT_TIMESTAMP;

-- ----------------------------------------------------------------
-- POLICY_TARGET — canonical child rows of seed policies.
-- ----------------------------------------------------------------
INSERT INTO POLICY_TARGET (
    id, policy_id, target_type, target_identifier, http_method, target_order, source_type
) VALUES
    (1, 1, 'URL', '/contexa/admin/login', 'ANY', 1, 'MANUAL'),
    (2, 2, 'URL', '/contexa/admin/**', 'ANY', 1, 'MANUAL')
ON CONFLICT (id) DO UPDATE SET
                               policy_id = EXCLUDED.policy_id,
                               target_type = EXCLUDED.target_type,
                               target_identifier = EXCLUDED.target_identifier,
                               http_method = EXCLUDED.http_method,
                               target_order = EXCLUDED.target_order,
                               source_type = EXCLUDED.source_type;

-- ----------------------------------------------------------------
-- POLICY_RULE — canonical child rows of seed policies.
-- ----------------------------------------------------------------
INSERT INTO POLICY_RULE (id, policy_id, description)
VALUES
    (1, 1, '로그인 화면은 인증 전 접근을 허용합니다.'),
    (2, 2, '인증된 사용자만 관리자 영역에 접근할 수 있습니다.')
ON CONFLICT (id) DO UPDATE SET
                               policy_id = EXCLUDED.policy_id,
                               description = EXCLUDED.description;

-- ----------------------------------------------------------------
-- POLICY_CONDITION — canonical child rows of seed policies.
-- ----------------------------------------------------------------
INSERT INTO POLICY_CONDITION (
    id, rule_id, condition_expression, authorization_phase, description
) VALUES
    (
        1,
        1,
        'permitAll',
        'PRE_AUTHORIZE',
        '로그인 화면은 인증 없이 접근할 수 있습니다.'
    ),
    (
        2,
        2,
        'isAuthenticated()',
        'PRE_AUTHORIZE',
        '요청 사용자가 인증되어 있어야 합니다.'
    )
ON CONFLICT (id) DO UPDATE SET
                               rule_id = EXCLUDED.rule_id,
                               condition_expression = EXCLUDED.condition_expression,
                               authorization_phase = EXCLUDED.authorization_phase,
                               description = EXCLUDED.description;

-- ----------------------------------------------------------------
-- CONDITION_TEMPLATE — required NOT NULL: spel_template, name.
-- ----------------------------------------------------------------
INSERT INTO CONDITION_TEMPLATE (id, name, spel_template, category, parameter_count, description) VALUES
    (1, '업무 시간 제약',     '#isBusinessHours()',                  '시간 기반', 0, '오전 9시부터 오후 6시 사이에만 접근을 허용합니다.'),
    (2, '사내 IP 대역 접근',  'hasIpAddress(''192.168.1.0/24'')',    '위치 기반', 0, '사내 네트워크 IP 주소에서의 접근만 허용합니다.')
ON CONFLICT (id) DO NOTHING;

-- ----------------------------------------------------------------
-- SECURITY_SPEL — SpEL expression catalog.
-- ----------------------------------------------------------------
INSERT INTO SECURITY_SPEL (name, expression, description, category) VALUES
    ('AUTHENTICATED',        'isAuthenticated()',      'Authenticated user only',                'AUTH'),
    ('FULLY_AUTHENTICATED',  'isFullyAuthenticated()', 'Fully authenticated (not remember-me)',  'AUTH'),
    ('REMEMBER_ME',          'isRememberMe()',         'Remember-me authentication',             'AUTH'),
    ('ANONYMOUS',            'isAnonymous()',          'Anonymous user only',                    'AUTH'),
    ('PERMIT_ALL',           'permitAll',              'Allow all access',                       'AUTH'),
    ('DENY_ALL',             'denyAll',                'Deny all access',                        'AUTH'),
    ('POLICY_1_ADMIN_LOGIN_PERMIT_ALL',
     'permitAll',
     'policy id=1: /contexa/admin/login 로그인 화면은 인증 없이 접근할 수 있습니다.',
     'POLICY'),
    ('POLICY_2_ADMIN_AUTHENTICATED',
     'isAuthenticated()',
     'policy id=2: /contexa/admin/** 관리자 영역은 인증된 사용자만 접근할 수 있습니다.',
     'POLICY')
ON CONFLICT (name) DO UPDATE SET
                                  expression = EXCLUDED.expression,
                                  description = EXCLUDED.description,
                                  category = EXCLUDED.category;

-- ----------------------------------------------------------------
-- SHEDLOCK — no seed row.
-- ShedLock rows are runtime lock state. Pre-seeding lock_until/locked_by can
-- create stale scheduler locks, so only the table schema is required.
-- ----------------------------------------------------------------


-- ----------------------------------------------------------------
-- Sequence sync (PostgreSQL identity columns).
-- Keep future inserted rows from reusing ids after fixed seed rows.
-- Use plain statements because Spring SQL initialization splits this file on
-- semicolons and cannot safely execute procedural blocks.
-- ----------------------------------------------------------------
SELECT setval('users_id_seq', GREATEST(COALESCE((SELECT MAX(id) FROM users), 0), 1), COALESCE((SELECT MAX(id) FROM users), 0) > 0)
WHERE to_regclass('users_id_seq') IS NOT NULL;

SELECT setval('app_group_group_id_seq', GREATEST(COALESCE((SELECT MAX(group_id) FROM app_group), 0), 1), COALESCE((SELECT MAX(group_id) FROM app_group), 0) > 0)
WHERE to_regclass('app_group_group_id_seq') IS NOT NULL;

SELECT setval('role_role_id_seq', GREATEST(COALESCE((SELECT MAX(role_id) FROM role), 0), 1), COALESCE((SELECT MAX(role_id) FROM role), 0) > 0)
WHERE to_regclass('role_role_id_seq') IS NOT NULL;

SELECT setval('role_hierarchy_config_hierarchy_id_seq', GREATEST(COALESCE((SELECT MAX(hierarchy_id) FROM role_hierarchy_config), 0), 1), COALESCE((SELECT MAX(hierarchy_id) FROM role_hierarchy_config), 0) > 0)
WHERE to_regclass('role_hierarchy_config_hierarchy_id_seq') IS NOT NULL;

SELECT setval('policy_id_seq', GREATEST(COALESCE((SELECT MAX(id) FROM policy), 0), 1), COALESCE((SELECT MAX(id) FROM policy), 0) > 0)
WHERE to_regclass('policy_id_seq') IS NOT NULL;

SELECT setval('policy_target_id_seq', GREATEST(COALESCE((SELECT MAX(id) FROM policy_target), 0), 1), COALESCE((SELECT MAX(id) FROM policy_target), 0) > 0)
WHERE to_regclass('policy_target_id_seq') IS NOT NULL;

SELECT setval('policy_rule_id_seq', GREATEST(COALESCE((SELECT MAX(id) FROM policy_rule), 0), 1), COALESCE((SELECT MAX(id) FROM policy_rule), 0) > 0)
WHERE to_regclass('policy_rule_id_seq') IS NOT NULL;

SELECT setval('policy_condition_id_seq', GREATEST(COALESCE((SELECT MAX(id) FROM policy_condition), 0), 1), COALESCE((SELECT MAX(id) FROM policy_condition), 0) > 0)
WHERE to_regclass('policy_condition_id_seq') IS NOT NULL;

SELECT setval('condition_template_id_seq', GREATEST(COALESCE((SELECT MAX(id) FROM condition_template), 0), 1), COALESCE((SELECT MAX(id) FROM condition_template), 0) > 0)
WHERE to_regclass('condition_template_id_seq') IS NOT NULL;

SELECT setval('security_spel_id_seq', GREATEST(COALESCE((SELECT MAX(id) FROM security_spel), 0), 1), COALESCE((SELECT MAX(id) FROM security_spel), 0) > 0)
WHERE to_regclass('security_spel_id_seq') IS NOT NULL;

SELECT setval('official_metric_evaluation_contract_id_seq', GREATEST(COALESCE((SELECT MAX(id) FROM official_metric_evaluation_contract), 0), 1), COALESCE((SELECT MAX(id) FROM official_metric_evaluation_contract), 0) > 0)
WHERE to_regclass('official_metric_evaluation_contract_id_seq') IS NOT NULL;

SELECT setval('official_prompt_signal_contract_id_seq', GREATEST(COALESCE((SELECT MAX(id) FROM official_prompt_signal_contract), 0), 1), COALESCE((SELECT MAX(id) FROM official_prompt_signal_contract), 0) > 0)
WHERE to_regclass('official_prompt_signal_contract_id_seq') IS NOT NULL;

-- ----------------------------------------------------------------
-- OSS PQA Official Inspection Contract Seed Data
-- ----------------------------------------------------------------
-- Source of truth: classpath:pqa/final-prompt-metric-contracts.json.
-- OfficialMetricPurposeContractCatalogWriter persists the complete official_metric_*
-- contract catalog at startup/runtime. Do not duplicate contract rows here.
