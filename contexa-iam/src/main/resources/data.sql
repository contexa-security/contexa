-- 사용자 (비밀번호: 1234)
INSERT INTO USERS (id, username, password, name, mfa_enabled, enabled) VALUES
                                                                           (1, 'admin@example.com', '{bcrypt}$2a$10$22n9G82e9Y7jC/qXjW1.0O.Z/l.X.1K.0F/l.X.1K', '최고관리자', true, true),
                                                                           (2, 'manager@example.com', '{bcrypt}$2a$10$22n9G82e9Y7jC/qXjW1.0O.Z/l.X.1K.0F/l.X.1K', '김팀장', true, true),
                                                                           (3, 'developer@example.com', '{bcrypt}$2a$10$22n9G82e9Y7jC/qXjW1.0O.Z/l.X.1K.0F/l.X.1K', '박개발', false, true),
                                                                           (4, 'user@example.com', '{bcrypt}$2a$10$22n9G82e9Y7jC/qXjW1.0O.Z/l.X.1K.0F/l.X.1K', '이운영', false, true),
                                                                           (5, 'finance@example.com', '{bcrypt}$2a$10$22n9G82e9Y7jC/qXjW1.0O.Z/l.X.1K.0F/l.X.1K', '최재무', true, true)
ON CONFLICT (id) DO NOTHING;

-- 그룹 (한국어 이름으로 변경하여 AI 질의 대응 개선)
INSERT INTO APP_GROUP (group_id, group_name, description) VALUES
                                                              (1, '시스템관리자', '시스템 전체 관리 및 최고 권한 보유'),
                                                              (2, '개발본부', '소프트웨어 개발 및 연구 부서'),
                                                              (3, '인프라보안팀', '서버, 네트워크, 보안 인프라 관리팀'),
                                                              (4, '재무회계팀', '회사의 재무 및 회계 업무 담당팀')
ON CONFLICT (group_id) DO UPDATE SET
    group_name = EXCLUDED.group_name,
    description = EXCLUDED.description;

-- 역할
INSERT INTO ROLE (role_id, role_name, role_desc) VALUES
                                                     (1, 'ROLE_ADMIN', '시스템 전체 관리자 역할'),
                                                     (2, 'ROLE_DEVELOPER', '개발팀 역할 - 소프트웨어 개발 및 고객 데이터 관리'),
                                                     (3, 'ROLE_INFRA', '인프라팀 역할 - 시스템 운영 및 보안 관리'),
                                                     (4, 'ROLE_FINANCE', '재무팀 역할 - 회계 및 재무 데이터 관리'),
                                                     (5, 'ROLE_USER', '일반 사용자 역할')
ON CONFLICT (role_id) DO NOTHING;

-- 사용자-그룹 관계
INSERT INTO USER_GROUPS (user_id, group_id) VALUES 
    (1, 1),  -- 최고관리자 → 시스템관리자
    (2, 2),  -- 김팀장 → 개발본부  
    (3, 2),  -- 박개발 → 개발본부
    (4, 3),  -- 이운영 → 인프라보안팀
    (5, 4);  -- 최재무 → 재무회계팀

-- 그룹-역할 관계 (올바른 구조로 수정)
INSERT INTO GROUP_ROLES (group_id, role_id) VALUES 
    (1, 1),  -- 시스템관리자 → ROLE_ADMIN
    (2, 2),  -- 개발본부 → ROLE_DEVELOPER
    (3, 3),  -- 인프라보안팀 → ROLE_INFRA
    (4, 4);  -- 재무회계팀 → ROLE_FINANCE

-- 역할 계층 (ADMIN > DEVELOPER > USER)
INSERT INTO ROLE_HIERARCHY_CONFIG (id, description, hierarchy_string, is_active) VALUES
    (1, '표준 4단계 역할 계층', 'ROLE_ADMIN > ROLE_DEVELOPER\nROLE_DEVELOPER > ROLE_INFRA\nROLE_INFRA > ROLE_USER', true)
ON CONFLICT (id) DO NOTHING;

-- 🔥 고객 데이터 관련 권한 생성 (기존 PERMISSION 테이블 활용) --
INSERT INTO PERMISSION (permission_id, permission_name, friendly_name, description, target_type, action_type) VALUES
    (301, 'CUSTOMER_DATA_READ', '고객 데이터 조회', '고객의 개인정보 및 프로필 데이터를 조회할 수 있습니다', 'BUSINESS', 'READ'),
    (302, 'CUSTOMER_DATA_DELETE', '고객 데이터 삭제', '고객의 개인정보를 영구적으로 삭제할 수 있습니다 - 매우 위험한 작업입니다', 'BUSINESS', 'DELETE'),
    (303, 'CUSTOMER_DATA_UPDATE', '고객 데이터 수정', '고객의 개인정보 및 프로필을 수정할 수 있습니다', 'BUSINESS', 'UPDATE'),
    (304, 'CUSTOMER_DATA_EXPORT', '고객 데이터 내보내기', '고객 데이터를 외부 시스템으로 내보낼 수 있습니다', 'BUSINESS', 'EXPORT'),
    (305, 'CUSTOMER_PROFILE_READ', '고객 프로필 조회', '고객의 기본 프로필 정보를 조회할 수 있습니다', 'BUSINESS', 'READ'),
    (306, 'CUSTOMER_TRANSACTION_READ', '고객 거래내역 조회', '고객의 결제 및 거래 이력을 조회할 수 있습니다', 'BUSINESS', 'READ')
ON CONFLICT (permission_id) DO NOTHING;

-- 🔥 개발팀 역할에 고객 데이터 권한 할당 --
INSERT INTO ROLE_PERMISSIONS (role_id, permission_id) VALUES
    -- ROLE_ADMIN (최고관리자) - 모든 권한
    (1, 301), (1, 302), (1, 303), (1, 304), (1, 305), (1, 306),
    -- ROLE_DEVELOPER (개발팀) - 조회, 수정, 삭제 권한 (단, 삭제는 매우 제한적)
    (2, 301), (2, 302), (2, 303), (2, 305), (2, 306),
    -- ROLE_INFRA (인프라팀) - 조회만 가능
    (3, 301), (3, 305),
    -- ROLE_FINANCE (재무팀) - 거래내역 조회만 가능
    (4, 306),
    -- 문서 관련 권한 할당
    -- ROLE_ADMIN (최고관리자) - 모든 문서 권한
    (1, 102), (1, 201),
    -- ROLE_DEVELOPER (개발팀) - 문서 조회, 수정 권한
    (2, 102), (2, 201),
    -- ROLE_FINANCE (재무팀) - 문서 조회 권한만
    (4, 102);

-- 리소스 워크벤치 테스트용 데이터 --
-- 1. 스캔 후 초기 상태 (정의 필요)
INSERT INTO MANAGED_RESOURCE (id, resource_identifier, resource_type, friendly_name, status) VALUES
    (101, '/api/documents', 'URL', 'getDocumentList', 'NEEDS_DEFINITION')
ON CONFLICT (id) DO NOTHING;

-- 2. 권한은 생성되었으나 정책은 없는 상태
INSERT INTO MANAGED_RESOURCE (id, resource_identifier, resource_type, friendly_name, description, status) VALUES
    (102, 'io.contexa.contexaiam.admin.web.service.impl.DocumentService.getDocumentById(java.lang.Long)', 'METHOD', '특정 문서 조회', 'AI 추천을 받지 못한 리소스입니다.', 'PERMISSION_CREATED')
ON CONFLICT (id) DO NOTHING;
INSERT INTO PERMISSION (permission_id, permission_name, friendly_name, description, target_type, action_type, managed_resource_id) VALUES
    (102, 'METHOD_DOCUMENTSERVICE_GETDOCUMENTBYID', '문서 조회', '문서를 조회하는 권한입니다.', 'METHOD', 'EXECUTE', 102)
ON CONFLICT (permission_id) DO NOTHING;

-- 3. 정책까지 모두 연결된 상태
INSERT INTO MANAGED_RESOURCE (id, resource_identifier, resource_type, friendly_name, description, status) VALUES
    (103, '/admin/**', 'URL', 'GROUP 관리', '시스템에서 자동 생성된 GROUP 리소스', 'POLICY_CONNECTED')
ON CONFLICT (id) DO NOTHING;
INSERT INTO PERMISSION (permission_id, permission_name, friendly_name, description, target_type, action_type, managed_resource_id) VALUES
    (103, 'METHOD_GROUPSERVICEIMPL_GETGROUP', '그룹 조회', '그룹 정보를 조회하는 권한입니다.', 'METHOD', 'EXECUTE', 103)
ON CONFLICT (permission_id) DO NOTHING;
INSERT INTO ROLE_PERMISSIONS (role_id, permission_id) VALUES (1, 103);  -- ROLE_ADMIN → METHOD_GROUPSERVICEIMPL_GETGROUP

-- 4. 관리 제외 상태
INSERT INTO MANAGED_RESOURCE (id, resource_identifier, resource_type, friendly_name, status) VALUES
    (104, '/api/internal/health', 'URL', 'Health Check API', 'EXCLUDED')
ON CONFLICT (id) DO NOTHING;

-- Pre/Post 인가 테스트용 정책 데이터 --
INSERT INTO POLICY (id, name, description, effect, priority, friendly_description) VALUES
    (201, 'FINANCE_REPORT_POLICY', '재무팀 문서 접근 정책', 'ALLOW', 500, '(역할(재무팀) 보유) 그리고 (반환된 문서의 소유자가 본인임)')
ON CONFLICT (id) DO NOTHING;

INSERT INTO POLICY_TARGET (id, policy_id, target_type, target_identifier) VALUES
    (201, 201, 'METHOD', 'io.contexa.contexaiam.admin.web.service.impl.DocumentService.getDocumentById(java.lang.Long)')
ON CONFLICT (id) DO NOTHING;

INSERT INTO POLICY_RULE (id, policy_id, description) VALUES
    (201, 201, '재무팀 역할 및 본인 소유 문서 확인 규칙')
ON CONFLICT (id) DO NOTHING;

-- PreAuthorize 조건
INSERT INTO POLICY_CONDITION (id, rule_id, condition_expression, authorization_phase) VALUES
    (201, 201, 'hasAuthority(''ROLE_FINANCE_VIEWER'')', 'PRE_AUTHORIZE')
ON CONFLICT (id) DO NOTHING;
-- PostAuthorize 조건
INSERT INTO POLICY_CONDITION (id, rule_id, condition_expression, authorization_phase) VALUES
    (202, 201, 'returnObject.ownerUsername == authentication.name', 'POST_AUTHORIZE')
ON CONFLICT (id) DO NOTHING;

-- 조건 템플릿 (정책 빌더용) --
INSERT INTO CONDITION_TEMPLATE (id, name, spel_template, category, parameter_count, description) VALUES
                                                                                                     (1, '업무 시간 제약', '#isBusinessHours()', '시간 기반', 0, '오전 9시부터 오후 6시 사이에만 접근을 허용합니다.'),
                                                                                                     (2, '사내 IP 대역 접근', 'hasIpAddress(''192.168.1.0/24'')', '위치 기반', 0, '사내 네트워크 IP 주소에서의 접근만 허용합니다.')
ON CONFLICT (id) DO NOTHING;

-- 테스트용 문서 데이터 --
INSERT INTO DOCUMENT (document_id, title, content, owner_username) VALUES
                                                                       (1, '2025년 1분기 영업 비밀 보고서', '1분기 매출은 전년 대비 15% 상승했습니다...', 'manager@example.com'),
                                                                       (2, '개인 연말정산 자료', '2024년 귀속 연말정산 내역입니다.', 'user@example.com'),
                                                                       (3, '재무팀 전용 감사 보고서', '외부 감사법인 최종 보고서입니다.', 'finance@example.com')
ON CONFLICT (document_id) DO NOTHING;

-- Pre/Post 인가 테스트용 메서드에 대한 권한 (리소스 ID: 201, 가상)
INSERT INTO MANAGED_RESOURCE (id, resource_identifier, resource_type, friendly_name, description, status) VALUES
    (201, 'io.contexa.contexaiam.admin.web.service.impl.DocumentService.updateDocument(java.lang.Long,java.lang.String)', 'METHOD', '문서 업데이트', 'ID와 새로운 내용으로 문서를 업데이트하는 기능', 'POLICY_CONNECTED')
ON CONFLICT (id) DO NOTHING;

INSERT INTO PERMISSION (permission_id, permission_name, friendly_name, description, target_type, action_type, managed_resource_id) VALUES
    (201, 'METHOD_DOCUMENTSERVICE_UPDATEDOCUMENT', '문서 수정', '문서 내용을 수정하는 권한', 'METHOD', 'EXECUTE', 201)
ON CONFLICT (permission_id) DO UPDATE SET
                                          permission_name = EXCLUDED.permission_name,
                                          friendly_name = EXCLUDED.friendly_name,
                                          description = EXCLUDED.description,
                                          target_type = EXCLUDED.target_type,
                                          action_type = EXCLUDED.action_type,
                                          managed_resource_id = EXCLUDED.managed_resource_id;

-- ID 시퀀스 수동 업데이트 (PostgreSQL 기준)
SELECT setval('users_id_seq', (SELECT MAX(id) FROM USERS), true);
SELECT setval('app_group_group_id_seq', (SELECT MAX(group_id) FROM APP_GROUP), true);
SELECT setval('role_role_id_seq', (SELECT MAX(role_id) FROM ROLE), true);
SELECT setval('managed_resource_id_seq', (SELECT MAX(id) FROM MANAGED_RESOURCE), true);
SELECT setval('permission_permission_id_seq', (SELECT MAX(permission_id) FROM PERMISSION), true);
SELECT setval('policy_id_seq', (SELECT MAX(id) FROM POLICY), true);
SELECT setval('policy_target_id_seq', (SELECT MAX(id) FROM POLICY_TARGET), true);
SELECT setval('policy_rule_id_seq', (SELECT MAX(id) FROM POLICY_RULE), true);
SELECT setval('policy_condition_id_seq', (SELECT MAX(id) FROM POLICY_CONDITION), true);
SELECT setval('condition_template_id_seq', (SELECT MAX(id) FROM CONDITION_TEMPLATE), true);
SELECT setval('document_document_id_seq', (SELECT MAX(document_id) FROM DOCUMENT), true);

