-- ============================================================================
-- @Protectable 보안 플로우 테스트용 정책 데이터
-- ============================================================================
--
-- 이 SQL 파일은 TestSecurityService의 @Protectable 메서드들에 대한
-- 실제 보안 정책을 정의합니다.
--
-- 테이블 구조:
-- - POLICY: 정책 기본 정보
-- - POLICY_RULE: 정책 규칙 (1:N with Policy)
-- - POLICY_CONDITION: SpEL 조건 표현식 (1:N with PolicyRule)
-- - POLICY_TARGET: 정책 적용 대상 (1:N with Policy)
--
-- 메서드 식별자 형식: {패키지}.{클래스}.{메서드}({파라미터타입})
--
-- ============================================================================


-- ============================================================================
-- 1. 정책 생성 (POLICY 테이블)
-- ============================================================================
-- Effect: ALLOW = 조건 충족 시 허용, DENY = 조건 충족 시 거부

INSERT INTO POLICY (id, name, description, effect, priority, is_active, source, approval_status, created_at)
VALUES
-- 공개 데이터 정책: 인증만 확인 (Action 무관)
(10001, 'TEST_PUBLIC_DATA_ACCESS',
 '공개 데이터 조회 정책 - 인증된 사용자만 허용, LLM Action 확인 없음',
 'ALLOW', 100, true, 'MANUAL', 'NOT_REQUIRED', CURRENT_TIMESTAMP),

-- 일반 데이터 정책: ALLOW/MONITOR Action 허용
(10002, 'TEST_NORMAL_DATA_ACCESS',
 '일반 데이터 조회 정책 - ALLOW 또는 MONITOR Action일 때 허용',
 'ALLOW', 100, true, 'MANUAL', 'NOT_REQUIRED', CURRENT_TIMESTAMP),

-- 민감 데이터 정책: 분석 완료 + ALLOW/MONITOR 필수
(10003, 'TEST_SENSITIVE_DATA_ACCESS',
 '민감 데이터 조회 정책 - LLM 분석 완료 + ALLOW/MONITOR Action 필수',
 'ALLOW', 100, true, 'MANUAL', 'NOT_REQUIRED', CURRENT_TIMESTAMP),

-- 중요 데이터 정책: ADMIN 권한 + ALLOW만 허용
(10004, 'TEST_CRITICAL_DATA_ACCESS',
 '중요 데이터 조회 정책 - ADMIN 권한 + LLM 분석 완료 + ALLOW Action만 허용',
 'ALLOW', 100, true, 'MANUAL', 'NOT_REQUIRED', CURRENT_TIMESTAMP),

-- 대량 데이터 정책: BLOCK이 아니면 허용 (기본 MONITOR)
(10005, 'TEST_BULK_DATA_ACCESS',
 '대량 데이터 조회 정책 - BLOCK Action이 아니면 허용 (분석 미완료 시 MONITOR로 처리)',
 'ALLOW', 100, true, 'MANUAL', 'NOT_REQUIRED', CURRENT_TIMESTAMP);


-- ============================================================================
-- 2. 정책 규칙 생성 (POLICY_RULE 테이블)
-- ============================================================================
-- 각 정책에 대한 규칙 정의
-- 하나의 정책은 여러 규칙을 가질 수 있으며, 모든 조건이 충족되어야 규칙이 참이 됨

INSERT INTO POLICY_RULE (id, policy_id, description)
VALUES
-- 공개 데이터 규칙
(10001, 10001, '공개 데이터 접근 규칙 - 인증만 확인'),

-- 일반 데이터 규칙
(10002, 10002, '일반 데이터 접근 규칙 - Action 기반 접근 제어'),

-- 민감 데이터 규칙
(10003, 10003, '민감 데이터 접근 규칙 - 분석 완료 필수'),

-- 중요 데이터 규칙
(10004, 10004, '중요 데이터 접근 규칙 - ADMIN + ALLOW 필수'),

-- 대량 데이터 규칙
(10005, 10005, '대량 데이터 접근 규칙 - 기본 MONITOR 허용');


-- ============================================================================
-- 3. 정책 조건 생성 (POLICY_CONDITION 테이블) - Action 기반 SpEL 표현식
-- ============================================================================
-- SpEL 표현식에서 사용 가능한 변수:
-- - #trust: TrustSecurityExpressionRoot (Hot Path - Redis 기반)
-- - #ai: RealtimeAISecurityExpressionRoot (Cold Path - LLM 실시간 분석)
--
-- TrustSecurityExpressionRoot의 Action 기반 메서드:
-- - hasAction(String): 특정 Action인지 확인
-- - hasActionIn(String...): 허용된 Action 목록에 포함되는지 확인
-- - isAllowed(): Action이 ALLOW인지 확인
-- - isBlocked(): Action이 BLOCK인지 확인
-- - isMonitored(): Action이 MONITOR인지 확인
-- - isPendingAnalysis(): 분석 미완료 상태인지 확인
-- - requiresAnalysisWithAction(String...): 분석 완료 + 허용된 Action인지 확인
-- - hasActionOrDefault(String, String...): 분석 미완료 시 기본값 사용
--
-- 기본 SpEL 메서드:
-- - isAuthenticated(): 인증 여부
-- - hasRole(String): 역할 보유 여부
-- - hasAuthority(String): 권한 보유 여부

INSERT INTO POLICY_CONDITION (id, rule_id, condition_expression, authorization_phase, description)
VALUES
-- ============================================================================
-- 공개 데이터: 인증만 확인 (Action 무관)
-- ============================================================================
-- 공개 경로 예제
-- LLM 분석 결과와 무관하게 인증된 사용자만 허용
(10001, 10001,
 'isAuthenticated()',
 'PRE_AUTHORIZE',
 '인증된 사용자만 접근 허용 - LLM Action 확인 없음'),

-- ============================================================================
-- 일반 데이터: Action이 ALLOW 또는 MONITOR일 때 허용
-- ============================================================================
-- 일반 경로 예제
-- 분석 결과가 있으면 사용하고, 없으면 defaultAction(MONITOR) 적용
-- hasActionIn(): 현재 Action이 허용 목록에 포함되는지 확인
(10002, 10002,
 '#trust.hasActionIn(''ALLOW'', ''MONITOR'') and hasRole(''USER'')',
 'PRE_AUTHORIZE',
 'ALLOW 또는 MONITOR Action이고 USER 역할 보유 시 허용'),

-- ============================================================================
-- 민감 데이터: 분석 완료 + ALLOW/MONITOR Action 필수
-- ============================================================================
-- 민감 경로 예제
-- LLM 분석이 반드시 완료되어야 함 (PENDING_ANALYSIS는 차단)
-- requiresAnalysisWithAction(): 분석 완료 여부 + Action 검증을 동시에 수행
(10003, 10003,
 '#trust.requiresAnalysisWithAction(''ALLOW'', ''MONITOR'') and hasRole(''USER'')',
 'PRE_AUTHORIZE',
 'LLM 분석 완료 + ALLOW/MONITOR Action + USER 역할 보유 시 허용'),

-- ============================================================================
-- 중요 데이터: ADMIN 권한 + 분석 완료 + ALLOW만 허용
-- ============================================================================
-- 최고 중요 경로 예제
-- 가장 엄격한 보안 수준: ALLOW Action만 허용 (MONITOR도 차단)
-- requiresAnalysisWithAction('ALLOW'): ALLOW만 허용, MONITOR/BLOCK/PENDING 모두 차단
(10004, 10004,
 'hasRole(''ADMIN'') and #trust.requiresAnalysisWithAction(''ALLOW'')',
 'PRE_AUTHORIZE',
 'ADMIN 권한 + LLM 분석 완료 + ALLOW Action만 허용'),

-- ============================================================================
-- 대량 데이터: BLOCK이 아니면 허용 (분석 미완료 시 기본 MONITOR)
-- ============================================================================
-- 대용량 경로 예제
-- hasActionOrDefault(defaultAction, allowedActions...):
-- - 분석 완료: 현재 Action이 allowedActions에 포함되면 허용
-- - 분석 미완료(PENDING_ANALYSIS): defaultAction을 사용하여 판단
-- 여기서는 PENDING_ANALYSIS일 때 MONITOR로 처리하여 ALLOW/MONITOR 목록에서 허용
(10005, 10005,
 '#trust.hasActionOrDefault(''MONITOR'', ''ALLOW'', ''MONITOR'')',
 'PRE_AUTHORIZE',
 'BLOCK Action이 아니면 허용 - 분석 미완료 시 MONITOR로 기본 처리');


-- ============================================================================
-- 4. 정책 대상 설정 (POLICY_TARGET 테이블) - 메서드 매핑
-- ============================================================================
-- targetType: 'METHOD' = 서비스 메서드, 'URL' = HTTP 엔드포인트
-- targetIdentifier: 메서드의 경우 FQN(Fully Qualified Name) + 파라미터 타입
-- httpMethod: 'ANY' = 모든 HTTP 메서드에 적용
--
-- 메서드 식별자 형식:
-- {패키지명}.{클래스명}.{메서드명}({파라미터타입1}, {파라미터타입2}, ...)
--
-- 주의: 파라미터 타입은 SimpleName 사용 (String, Long 등)

INSERT INTO POLICY_TARGET (id, policy_id, target_type, target_identifier, http_method)
VALUES
-- ============================================================================
-- 공개 데이터 조회 메서드 매핑
-- ============================================================================
-- TestSecurityService.getPublicData(String resourceId)
-- @Protectable
(10001, 10001, 'METHOD',
 'io.contexa.springbootstartercontexa.service.TestSecurityService.getPublicData(String)',
 'ANY'),

-- ============================================================================
-- 일반 데이터 조회 메서드 매핑
-- ============================================================================
-- TestSecurityService.getNormalData(String resourceId)
-- @Protectable
(10002, 10002, 'METHOD',
 'io.contexa.springbootstartercontexa.service.TestSecurityService.getNormalData(String)',
 'ANY'),

-- ============================================================================
-- 민감 데이터 조회 메서드 매핑
-- ============================================================================
-- TestSecurityService.getSensitiveData(String resourceId)
-- @Protectable
(10003, 10003, 'METHOD',
 'io.contexa.springbootstartercontexa.service.TestSecurityService.getSensitiveData(String)',
 'ANY'),

-- ============================================================================
-- 중요 데이터 조회 메서드 매핑
-- ============================================================================
-- TestSecurityService.getCriticalData(String resourceId)
-- @Protectable
(10004, 10004, 'METHOD',
 'io.contexa.springbootstartercontexa.service.TestSecurityService.getCriticalData(String)',
 'ANY'),

-- ============================================================================
-- 대량 데이터 조회 메서드 매핑
-- ============================================================================
-- TestSecurityService.getBulkData()
-- @Protectable
(10005, 10005, 'METHOD',
 'io.contexa.springbootstartercontexa.service.TestSecurityService.getBulkData()',
 'ANY');


-- ============================================================================
-- 정책 적용 검증 쿼리 (테스트용)
-- ============================================================================
-- 아래 쿼리로 정책이 올바르게 적용되었는지 확인할 수 있습니다.

-- 전체 정책 조회
-- SELECT p.id, p.name, p.effect, p.is_active
-- FROM POLICY p
-- WHERE p.name LIKE 'TEST_%'
-- ORDER BY p.id;

-- 정책별 조건 조회
-- SELECT p.name, pc.condition_expression, pc.authorization_phase
-- FROM POLICY p
-- JOIN POLICY_RULE pr ON p.id = pr.policy_id
-- JOIN POLICY_CONDITION pc ON pr.id = pc.rule_id
-- WHERE p.name LIKE 'TEST_%'
-- ORDER BY p.id;

-- 정책별 대상 조회
-- SELECT p.name, pt.target_type, pt.target_identifier
-- FROM POLICY p
-- JOIN POLICY_TARGET pt ON p.id = pt.policy_id
-- WHERE p.name LIKE 'TEST_%'
-- ORDER BY p.id;

-- 특정 메서드에 적용된 정책 조회
-- SELECT p.name, pc.condition_expression
-- FROM POLICY p
-- JOIN POLICY_TARGET pt ON p.id = pt.policy_id
-- JOIN POLICY_RULE pr ON p.id = pr.policy_id
-- JOIN POLICY_CONDITION pc ON pr.id = pc.rule_id
-- WHERE pt.target_identifier = 'io.contexa.springbootstartercontexa.service.TestSecurityService.getSensitiveData(String)';
