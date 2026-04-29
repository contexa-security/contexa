-- PostgreSQL 기준 최종 스키마

-- 테이블 초기화 (순서 보장)
DROP TABLE IF EXISTS
    WIZARD_SESSION,
    POLICY_TEMPLATE,
    AUDIT_LOG,
    ROLE_HIERARCHY_CONFIG,
    POLICY_CONDITION,
    POLICY_RULE,
    POLICY_TARGET,
    POLICY,
    ROLE_PERMISSIONS,
    PERMISSION,
    MANAGED_RESOURCE, -- FunctionCatalog 대신 직접 Permission과 연결
    GROUP_ROLES,
    ROLE,
    USER_GROUPS,
    APP_GROUP,
    USERS,
    BUSINESS_RESOURCE_ACTION,
    BUSINESS_ACTION,
    BUSINESS_RESOURCE,
    CONDITION_TEMPLATE,
    DOCUMENT CASCADE;

-- 사용자 테이블
CREATE TABLE USERS (
                       id BIGSERIAL PRIMARY KEY,
                       username VARCHAR(255) UNIQUE NOT NULL,
                       password VARCHAR(255) NOT NULL,
                       name VARCHAR(255) NOT NULL,
                       mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                       last_mfa_used_at TIMESTAMP,
                       enabled BOOLEAN NOT NULL DEFAULT TRUE
);

-- 그룹 테이블
CREATE TABLE APP_GROUP (
                           group_id BIGSERIAL PRIMARY KEY,
                           group_name VARCHAR(255) UNIQUE NOT NULL,
                           description VARCHAR(255)
);

-- 역할 테이블
CREATE TABLE ROLE (
                      role_id BIGSERIAL PRIMARY KEY,
                      role_name VARCHAR(255) UNIQUE NOT NULL,
                      role_desc VARCHAR(255),
                      is_expression VARCHAR(1) DEFAULT 'N'
);

-- 기술 리소스 테이블 (워크벤치 관리 대상)
CREATE TABLE MANAGED_RESOURCE (
                                  id BIGSERIAL PRIMARY KEY,
                                  resource_identifier VARCHAR(512) UNIQUE NOT NULL,
                                  resource_type VARCHAR(255) NOT NULL,
                                  http_method VARCHAR(255),
                                  friendly_name VARCHAR(255),
                                  description VARCHAR(1024),
                                  service_owner VARCHAR(255),
                                  parameter_types VARCHAR(512),
                                  return_type VARCHAR(255),
                                  api_docs_url VARCHAR(255),
                                  source_code_location VARCHAR(255),
                                  status VARCHAR(50) NOT NULL DEFAULT 'NEEDS_DEFINITION',
                                  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 권한 테이블 (비즈니스 권한)
CREATE TABLE PERMISSION (
                            permission_id BIGSERIAL PRIMARY KEY,
                            permission_name VARCHAR(255) UNIQUE NOT NULL,
                            friendly_name VARCHAR(255),
                            description VARCHAR(1024),
                            target_type VARCHAR(255),
                            action_type VARCHAR(255),
                            condition_expression VARCHAR(255),
                            managed_resource_id BIGINT UNIQUE REFERENCES MANAGED_RESOURCE(id) ON DELETE SET NULL,
                            auto_created BOOLEAN NOT NULL DEFAULT FALSE
);

-- 사용자-그룹 조인 테이블
CREATE TABLE USER_GROUPS (
                             user_id BIGINT NOT NULL REFERENCES USERS(id) ON DELETE CASCADE,
                             group_id BIGINT NOT NULL REFERENCES APP_GROUP(group_id) ON DELETE CASCADE,
                             PRIMARY KEY (user_id, group_id)
);

-- 그룹-역할 조인 테이블
CREATE TABLE GROUP_ROLES (
                             group_id BIGINT NOT NULL REFERENCES APP_GROUP(group_id) ON DELETE CASCADE,
                             role_id BIGINT NOT NULL REFERENCES ROLE(role_id) ON DELETE CASCADE,
                             PRIMARY KEY (group_id, role_id)
);

-- 역할-권한 조인 테이블
CREATE TABLE ROLE_PERMISSIONS (
                                  role_id BIGINT NOT NULL REFERENCES ROLE(role_id) ON DELETE CASCADE,
                                  permission_id BIGINT NOT NULL REFERENCES PERMISSION(permission_id) ON DELETE CASCADE,
                                  PRIMARY KEY (role_id, permission_id)
);



-- 정책 테이블
CREATE TABLE POLICY (
                        id BIGSERIAL PRIMARY KEY,
                        name VARCHAR(255) UNIQUE NOT NULL,
                        description VARCHAR(1024),
                        effect VARCHAR(50) NOT NULL,
                        priority INT NOT NULL,
                        friendly_description VARCHAR(2048)
);

-- 정책 대상 테이블
CREATE TABLE POLICY_TARGET (
                               id BIGSERIAL PRIMARY KEY,
                               policy_id BIGINT NOT NULL REFERENCES POLICY(id) ON DELETE CASCADE,
                               target_type VARCHAR(255) NOT NULL,
                               target_identifier VARCHAR(512) NOT NULL,
                               http_method VARCHAR(50),
                               target_order INTEGER NOT NULL DEFAULT 0,
                               source_type VARCHAR(20) DEFAULT 'RESOURCE'
);

-- 정책 규칙 테이블
CREATE TABLE POLICY_RULE (
                             id BIGSERIAL PRIMARY KEY,
                             policy_id BIGINT NOT NULL REFERENCES POLICY(id) ON DELETE CASCADE,
                             description VARCHAR(255)
);

-- 정책 조건 테이블
CREATE TABLE POLICY_CONDITION (
                                  id BIGSERIAL PRIMARY KEY,
                                  rule_id BIGINT NOT NULL REFERENCES POLICY_RULE(id) ON DELETE CASCADE,
                                  condition_expression VARCHAR(2048) NOT NULL,
                                  authorization_phase VARCHAR(20) NOT NULL DEFAULT 'PRE_AUTHORIZE', -- [신규] Pre/Post 인가 구분
                                  description VARCHAR(255)
);

-- 역할 계층 테이블
CREATE TABLE ROLE_HIERARCHY_CONFIG (
                                       id BIGSERIAL PRIMARY KEY,
                                       description VARCHAR(255),
                                       hierarchy_string TEXT NOT NULL,
                                       is_active BOOLEAN NOT NULL DEFAULT FALSE
);

-- 감사 로그 테이블
CREATE TABLE AUDIT_LOG (
                           id BIGSERIAL PRIMARY KEY,
                           timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                           principal_name VARCHAR(255) NOT NULL,
                           resource_identifier VARCHAR(512) NOT NULL,
                           action VARCHAR(255),
                           decision VARCHAR(255) NOT NULL,
                           reason VARCHAR(1024),
                           outcome VARCHAR(255),
                           resource_uri VARCHAR(1024),
                           client_ip VARCHAR(255),
                           session_id VARCHAR(255),
                           status VARCHAR(255),
                           parameters TEXT,
                           details TEXT,
                           event_category VARCHAR(50),
                           user_agent VARCHAR(512),
                           http_method VARCHAR(10),
                           request_uri VARCHAR(2048),
                           risk_score DOUBLE PRECISION,
                           event_source VARCHAR(50),
                           correlation_id VARCHAR(64)
);

CREATE INDEX idx_audit_log_principal_ts ON AUDIT_LOG (principal_name, timestamp DESC);
CREATE INDEX idx_audit_log_category_ts ON AUDIT_LOG (event_category, timestamp DESC);
CREATE INDEX idx_audit_log_timestamp ON AUDIT_LOG (timestamp DESC);
CREATE INDEX idx_audit_log_client_ip ON AUDIT_LOG (client_ip);
CREATE INDEX idx_audit_log_session_id ON AUDIT_LOG (session_id);
CREATE INDEX idx_audit_log_correlation_id ON AUDIT_LOG (correlation_id);
CREATE INDEX idx_audit_log_decision_ts ON AUDIT_LOG (decision, timestamp DESC);

-- 비즈니스 정책 생성용 메타데이터 테이블들
CREATE TABLE BUSINESS_RESOURCE (
                                   id BIGSERIAL PRIMARY KEY,
                                   name VARCHAR(255) UNIQUE NOT NULL,
                                   resource_type VARCHAR(255) NOT NULL,
                                   description VARCHAR(1024)
);
CREATE TABLE BUSINESS_ACTION (
                                 id BIGSERIAL PRIMARY KEY,
                                 name VARCHAR(255) UNIQUE NOT NULL,
                                 action_type VARCHAR(255) NOT NULL,
                                 description VARCHAR(1024)
);
CREATE TABLE BUSINESS_RESOURCE_ACTION (
                                          business_resource_id BIGINT NOT NULL REFERENCES BUSINESS_RESOURCE(id) ON DELETE CASCADE,
                                          business_action_id BIGINT NOT NULL REFERENCES BUSINESS_ACTION(id) ON DELETE CASCADE,
                                          mapped_permission_name VARCHAR(255) NOT NULL,
                                          PRIMARY KEY (business_resource_id, business_action_id)
);
CREATE TABLE CONDITION_TEMPLATE (
                                    id BIGSERIAL PRIMARY KEY,
                                    name VARCHAR(255) UNIQUE NOT NULL,
                                    spel_template VARCHAR(2048) NOT NULL,
                                    category VARCHAR(255),
                                    parameter_count INT NOT NULL DEFAULT 0,
                                    description VARCHAR(1024)
);

-- 마법사 세션 테이블
CREATE TABLE WIZARD_SESSION (
                                session_id VARCHAR(36) PRIMARY KEY,
                                context_data TEXT NOT NULL,
                                owner_user_id BIGINT NOT NULL,
                                created_at TIMESTAMP NOT NULL,
                                expires_at TIMESTAMP NOT NULL
);

-- SpEL 표현식 테이블
CREATE TABLE SECURITY_SPEL (
                               id BIGSERIAL PRIMARY KEY,
                               name VARCHAR(255) NOT NULL UNIQUE,
                               expression VARCHAR(2048) NOT NULL,
                               description VARCHAR(1024),
                               category VARCHAR(100),
                               created_at TIMESTAMP DEFAULT NOW()
);

-- 테스트용 문서 테이블
CREATE TABLE DOCUMENT (
                          document_id BIGSERIAL PRIMARY KEY,
                          title VARCHAR(255) NOT NULL,
                          content TEXT,
                          owner_username VARCHAR(255) NOT NULL,
                          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                          updated_at TIMESTAMP
);
-- Password History
CREATE TABLE IF NOT EXISTS password_history (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    password_hash VARCHAR(512) NOT NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Per-IP failed login throttling counter (Phase 3 — IP-dimension lockout)
CREATE TABLE IF NOT EXISTS login_attempt_ip (
    id              BIGSERIAL PRIMARY KEY,
    ip_address      VARCHAR(64) NOT NULL UNIQUE,
    failed_attempts INT NOT NULL DEFAULT 0,
    window_start_at TIMESTAMP NOT NULL,
    blocked_until   TIMESTAMP,
    last_failure_at TIMESTAMP,
    last_username   VARCHAR(255)
);
CREATE INDEX IF NOT EXISTS idx_login_attempt_ip_window ON login_attempt_ip (window_start_at);
CREATE INDEX IF NOT EXISTS idx_login_attempt_ip_blocked ON login_attempt_ip (blocked_until);

-- Add IP-dimension columns to password_policy (idempotent, safe across re-runs and
-- across rows that may have been created without the new columns set).
--
-- Done in three steps because "ADD COLUMN IF NOT EXISTS ... NOT NULL DEFAULT" is
-- skipped entirely when the column already exists, leaving any pre-existing NULL
-- values in place. Hibernate's NOT NULL validation (driven by the primitive int
-- field on PasswordPolicy) then fails on startup with:
--   ERROR: column "ip_window_minutes" of relation "password_policy" contains null values
-- The sequence below: (1) ensure the column exists as nullable, (2) backfill any
-- NULL rows with the policy default, (3) promote the column to NOT NULL and set
-- the column default for future inserts.
ALTER TABLE password_policy ADD COLUMN IF NOT EXISTS ip_max_failed_attempts INT;
ALTER TABLE password_policy ADD COLUMN IF NOT EXISTS ip_window_minutes      INT;
UPDATE password_policy SET ip_max_failed_attempts = 30 WHERE ip_max_failed_attempts IS NULL;
UPDATE password_policy SET ip_window_minutes      = 15 WHERE ip_window_minutes      IS NULL;
ALTER TABLE password_policy ALTER COLUMN ip_max_failed_attempts SET NOT NULL;
ALTER TABLE password_policy ALTER COLUMN ip_window_minutes      SET NOT NULL;
ALTER TABLE password_policy ALTER COLUMN ip_max_failed_attempts SET DEFAULT 30;
ALTER TABLE password_policy ALTER COLUMN ip_window_minutes      SET DEFAULT 15;

-- System Settings
CREATE TABLE IF NOT EXISTS system_settings (
    id BIGSERIAL PRIMARY KEY,
    audit_log_retention_days INT NOT NULL DEFAULT 90,
    default_role VARCHAR(100) NOT NULL DEFAULT 'ROLE_USER',
    policy_combining_algorithm VARCHAR(50) NOT NULL DEFAULT 'FIRST_APPLICABLE',
    registration_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

-- Seed the singleton row at boot so concurrent application calls cannot race two INSERTs
-- against a table that has no unique constraint beyond the surrogate primary key. The
-- WHERE NOT EXISTS guard makes the seed idempotent across restarts.
INSERT INTO system_settings (audit_log_retention_days, default_role, policy_combining_algorithm, registration_enabled)
SELECT 90, 'ROLE_USER', 'FIRST_APPLICABLE', FALSE
WHERE NOT EXISTS (SELECT 1 FROM system_settings);

-- Admin Menu
CREATE TABLE IF NOT EXISTS admin_menu (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    url VARCHAR(255),
    icon VARCHAR(2000),
    parent_id BIGINT,
    menu_order INT NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    menu_type VARCHAR(20) NOT NULL DEFAULT 'CORE',
    data_page VARCHAR(50)
);

-- Admin Menu Role Mapping
CREATE TABLE IF NOT EXISTS admin_menu_role (
    id BIGSERIAL PRIMARY KEY,
    menu_id BIGINT NOT NULL REFERENCES admin_menu(id) ON DELETE CASCADE,
    role_name VARCHAR(100) NOT NULL,
    UNIQUE(menu_id, role_name)
);

-- User-Role CRUD Permission (activated CRUD per user-role)
CREATE TABLE IF NOT EXISTS user_role_permissions (
    user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id       BIGINT NOT NULL REFERENCES role(role_id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permission(permission_id) ON DELETE CASCADE,
    assigned_at   TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP NOT NULL,
    assigned_by   VARCHAR(100),
    PRIMARY KEY (user_id, role_id, permission_id)
);

-- Group-Role CRUD Permission (activated CRUD per group-role)
CREATE TABLE IF NOT EXISTS group_role_permissions (
    group_id      BIGINT NOT NULL REFERENCES app_group(group_id) ON DELETE CASCADE,
    role_id       BIGINT NOT NULL REFERENCES role(role_id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permission(permission_id) ON DELETE CASCADE,
    assigned_at   TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP NOT NULL,
    assigned_by   VARCHAR(100),
    PRIMARY KEY (group_id, role_id, permission_id)
);

-- ShedLock keeps @Scheduled methods exclusive across JVM instances. Each row
-- represents a single lock name (typically the scheduled method) with the
-- current holder and the expiry timestamp. The table is managed by
-- JdbcTemplateLockProvider; application code must not write to it directly.
CREATE TABLE IF NOT EXISTS shedlock (
    name       VARCHAR(64)  NOT NULL,
    lock_until TIMESTAMP    NOT NULL,
    locked_at  TIMESTAMP    NOT NULL,
    locked_by  VARCHAR(255) NOT NULL,
    PRIMARY KEY (name)
);
