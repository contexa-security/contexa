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
                            managed_resource_id BIGINT UNIQUE REFERENCES MANAGED_RESOURCE(id) ON DELETE SET NULL
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
                               http_method VARCHAR(50)
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

-- 테스트용 문서 테이블
CREATE TABLE DOCUMENT (
                          document_id BIGSERIAL PRIMARY KEY,
                          title VARCHAR(255) NOT NULL,
                          content TEXT,
                          owner_username VARCHAR(255) NOT NULL,
                          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                          updated_at TIMESTAMP
);