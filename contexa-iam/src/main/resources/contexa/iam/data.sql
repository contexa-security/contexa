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
    (1, 'admin',     '{bcrypt}$2a$10$22n9G82e9Y7jC/qXjW1.0O.Z/l.X.1K.0F/l.X.1K', '최고관리자', 'admin@gmail.com', TRUE,  TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP),
    (2, 'manager',   '{bcrypt}$2a$10$22n9G82e9Y7jC/qXjW1.0O.Z/l.X.1K.0F/l.X.1K', '김팀장',     'manager@gmail.com',TRUE,  TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP),
    (3, 'developer', '{bcrypt}$2a$10$22n9G82e9Y7jC/qXjW1.0O.Z/l.X.1K.0F/l.X.1K', '박개발',     'developer@gmail.com',FALSE, TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP),
    (4, 'user',      '{bcrypt}$2a$10$22n9G82e9Y7jC/qXjW1.0O.Z/l.X.1K.0F/l.X.1K', '이운영',     'user@gmail.com',FALSE, TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP),
    (5, 'finance',   '{bcrypt}$2a$10$22n9G82e9Y7jC/qXjW1.0O.Z/l.X.1K.0F/l.X.1K', '최재무',     'finance@gmail.com',TRUE,  TRUE, FALSE, FALSE, FALSE, FALSE, 0, CURRENT_TIMESTAMP)
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
-- PERMISSION — Customer-data permission set.
-- Required NOT NULL: auto_created, created_at, permission_name.
-- ----------------------------------------------------------------
INSERT INTO PERMISSION (permission_id, permission_name, friendly_name, description, target_type, action_type, auto_created, created_at) VALUES
    (301, 'CUSTOMER_DATA_READ',        '고객 데이터 조회',           '고객의 개인정보 및 프로필 데이터를 조회할 수 있습니다',                  'BUSINESS', 'READ',   FALSE, CURRENT_TIMESTAMP),
    (302, 'CUSTOMER_DATA_DELETE',      '고객 데이터 삭제',           '고객의 개인정보를 영구적으로 삭제할 수 있습니다 - 매우 위험한 작업입니다', 'BUSINESS', 'DELETE', FALSE, CURRENT_TIMESTAMP),
    (303, 'CUSTOMER_DATA_UPDATE',      '고객 데이터 수정',           '고객의 개인정보 및 프로필을 수정할 수 있습니다',                          'BUSINESS', 'UPDATE', FALSE, CURRENT_TIMESTAMP),
    (304, 'CUSTOMER_DATA_EXPORT',      '고객 데이터 내보내기',       '고객 데이터를 외부 시스템으로 내보낼 수 있습니다',                        'BUSINESS', 'EXPORT', FALSE, CURRENT_TIMESTAMP),
    (305, 'CUSTOMER_PROFILE_READ',     '고객 프로필 조회',           '고객의 기본 프로필 정보를 조회할 수 있습니다',                            'BUSINESS', 'READ',   FALSE, CURRENT_TIMESTAMP),
    (306, 'CUSTOMER_TRANSACTION_READ', '고객 거래내역 조회',         '고객의 결제 및 거래 이력을 조회할 수 있습니다',                           'BUSINESS', 'READ',   FALSE, CURRENT_TIMESTAMP)
ON CONFLICT (permission_id) DO NOTHING;

-- ----------------------------------------------------------------
-- ROLE_PERMISSIONS — required NOT NULL: assigned_at, permission_id, role_id.
-- ----------------------------------------------------------------
INSERT INTO ROLE_PERMISSIONS (role_id, permission_id, assigned_at) VALUES
    (1, 301, CURRENT_TIMESTAMP), (1, 302, CURRENT_TIMESTAMP), (1, 303, CURRENT_TIMESTAMP), (1, 304, CURRENT_TIMESTAMP), (1, 305, CURRENT_TIMESTAMP), (1, 306, CURRENT_TIMESTAMP),
    (2, 301, CURRENT_TIMESTAMP), (2, 302, CURRENT_TIMESTAMP), (2, 303, CURRENT_TIMESTAMP), (2, 305, CURRENT_TIMESTAMP), (2, 306, CURRENT_TIMESTAMP),
    (3, 301, CURRENT_TIMESTAMP), (3, 305, CURRENT_TIMESTAMP),
    (4, 306, CURRENT_TIMESTAMP)
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO PERMISSION (permission_id, permission_name, friendly_name, description, target_type, action_type, managed_resource_id, auto_created, created_at) VALUES
    (102, 'METHOD_DOCUMENTSERVICE_GETDOCUMENTBYID', '문서 조회', '문서를 조회하는 권한입니다.',  'METHOD', 'EXECUTE', 102, FALSE, CURRENT_TIMESTAMP),
    (103, 'METHOD_GROUPSERVICEIMPL_GETGROUP',       '그룹 조회', '그룹 정보를 조회하는 권한입니다.', 'METHOD', 'EXECUTE', 103, FALSE, CURRENT_TIMESTAMP),
    (201, 'METHOD_DOCUMENTSERVICE_UPDATEDOCUMENT',  '문서 수정', '문서 내용을 수정하는 권한',     'METHOD', 'EXECUTE', 201, FALSE, CURRENT_TIMESTAMP)
ON CONFLICT (permission_id) DO NOTHING;

-- ROLE_ADMIN → resource-bound permissions
INSERT INTO ROLE_PERMISSIONS (role_id, permission_id, assigned_at) VALUES
    (1, 102, CURRENT_TIMESTAMP),
    (1, 103, CURRENT_TIMESTAMP),
    (1, 201, CURRENT_TIMESTAMP),
    (2, 102, CURRENT_TIMESTAMP),
    (2, 201, CURRENT_TIMESTAMP),
    (4, 102, CURRENT_TIMESTAMP)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- ----------------------------------------------------------------
-- POLICY — canonical seed policy id=2. NOT NULL: is_active, priority, created_at, effect, name.
-- ----------------------------------------------------------------
INSERT INTO POLICY (
    id, name, description, effect, priority, is_active,
    source, approval_status, friendly_description, created_at
) VALUES
    (
        2,
        'ALLOW_READ_admin_**',
        '모든 관리자 화면과 API는 인증된 사용자만 접근할 수 있습니다.',
        'ALLOW',
        100,
        TRUE,
        'MANUAL',
        'NOT_REQUIRED',
        '인증된 사용자만 /admin/** 보호 리소스에 접근할 수 있습니다.',
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
-- POLICY_TARGET — canonical child row of policy id=2.
-- ----------------------------------------------------------------
INSERT INTO POLICY_TARGET (
    id, policy_id, target_type, target_identifier, http_method, target_order, source_type
) VALUES (
    2, 2, 'URL', '/admin/**', 'ANY', 1, 'MANUAL'
)
ON CONFLICT (id) DO UPDATE SET
                               policy_id = EXCLUDED.policy_id,
                               target_type = EXCLUDED.target_type,
                               target_identifier = EXCLUDED.target_identifier,
                               http_method = EXCLUDED.http_method,
                               target_order = EXCLUDED.target_order,
                               source_type = EXCLUDED.source_type;

-- ----------------------------------------------------------------
-- POLICY_RULE — canonical child row of policy id=2.
-- ----------------------------------------------------------------
INSERT INTO POLICY_RULE (id, policy_id, description)
VALUES (2, 2, '인증된 사용자만 관리자 영역에 접근할 수 있습니다.')
ON CONFLICT (id) DO UPDATE SET
                               policy_id = EXCLUDED.policy_id,
                               description = EXCLUDED.description;

-- ----------------------------------------------------------------
-- POLICY_CONDITION — canonical child row of policy id=2.
-- ----------------------------------------------------------------
INSERT INTO POLICY_CONDITION (
    id, rule_id, condition_expression, authorization_phase, description
) VALUES (
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
    ('POLICY_2_ADMIN_AUTHENTICATED',
     'isAuthenticated()',
     'policy id=2: /admin/** 보호 리소스는 인증된 사용자만 접근할 수 있습니다.',
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
-- PERMISSION — common CRUD permissions.
-- ----------------------------------------------------------------
INSERT INTO PERMISSION (permission_name, friendly_name, description, auto_created, target_type, action_type, created_at) VALUES
    ('READ',   'Read Access',   'Permission to read/view resources',         FALSE, 'CRUD', 'READ',   CURRENT_TIMESTAMP),
    ('WRITE',  'Write Access',  'Permission to create new resources',        FALSE, 'CRUD', 'WRITE',  CURRENT_TIMESTAMP),
    ('UPDATE', 'Update Access', 'Permission to modify existing resources',   FALSE, 'CRUD', 'UPDATE', CURRENT_TIMESTAMP),
    ('DELETE', 'Delete Access', 'Permission to remove resources',            FALSE, 'CRUD', 'DELETE', CURRENT_TIMESTAMP)
ON CONFLICT (permission_name) DO NOTHING;

-- ----------------------------------------------------------------
-- Sequence sync (PostgreSQL identity columns).
-- Wrapped in DO block so absent sequences (Hibernate-controlled) do not abort load.
-- ----------------------------------------------------------------
DO $$
DECLARE
    pairs TEXT[][] := ARRAY[
        ARRAY['users_id_seq',              'users',              'id'],
        ARRAY['app_group_group_id_seq',    'app_group',          'group_id'],
        ARRAY['role_role_id_seq',          'role',               'role_id'],
        ARRAY['permission_permission_id_seq','permission',       'permission_id'],
        ARRAY['policy_id_seq',             'policy',             'id'],
        ARRAY['policy_target_id_seq',      'policy_target',      'id'],
        ARRAY['policy_rule_id_seq',        'policy_rule',        'id'],
        ARRAY['policy_condition_id_seq',   'policy_condition',   'id'],
        ARRAY['condition_template_id_seq', 'condition_template', 'id'],
        ARRAY['security_spel_id_seq',      'security_spel',      'id']
    ];
    pair TEXT[];
    max_id BIGINT;
BEGIN
    FOREACH pair SLICE 1 IN ARRAY pairs LOOP
        BEGIN
            EXECUTE format('SELECT MAX(%I) FROM %I', pair[3], pair[2]) INTO max_id;
            IF max_id IS NOT NULL THEN
                EXECUTE format('SELECT setval(%L, %s, true)', pair[1], max_id);
            END IF;
        EXCEPTION WHEN undefined_table OR undefined_column OR undefined_object OR insufficient_privilege THEN
            -- Sequence or table absent in this profile; skip silently.
            NULL;
        END;
    END LOOP;
END $$;
