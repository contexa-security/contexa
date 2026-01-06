package io.contexa.contexacore.autonomous.utils;

/**
 * Zero Trust Redis Key Management
 * 
 * Zero Trust 아키텍처를 위한 Redis 키 관리 유틸리티
 * 모든 Redis 키는 userId를 기준으로 구성됩니다.
 * 
 * 핵심 원칙:
 * 1. userId가 Primary Key - 모든 사용자 데이터의 기준점
 * 2. sessionId는 Reference - 세션 참조용으로만 사용
 * 3. 사용자 컨텍스트 누적 - AI 학습을 위한 지속적 데이터 축적
 * 
 * @author AI Security Framework
 * @since 3.0.0
 */
public class ZeroTrustRedisKeys {
    
    // 기본 네임스페이스
    private static final String NAMESPACE = "security";
    
    // ============================================
    // USER-CENTRIC KEYS (userId 기반 - Primary)
    // ============================================
    
    /**
     * 사용자 보안 컨텍스트 (핵심)
     * 사용자의 모든 보안 관련 데이터 누적 저장
     * Format: security:user:context:{userId}
     * TTL: 30 days (지속적 학습)
     */
    public static String userContext(String userId) {
        validateUserId(userId);
        return String.format("%s:user:context:%s", NAMESPACE, userId);
    }
    
    /**
     * 사용자 위협 점수 (Primary)
     * Zero Trust 평가의 핵심 지표
     * Format: threat_score:{userId}
     * TTL: 90 days (휴면 사용자 자동 정리)
     *
     * 주의: Trust Score = 1.0 - Threat Score
     */
    public static String threatScore(String userId) {
        validateUserId(userId);
        return String.format("threat_score:%s", userId);
    }

    // AI Native: trustHistory() 제거 (v3.1.0) - 미사용

    /**
     * HCAD 베이스라인 벡터
     * 사용자별 행동 베이스라인 벡터 저장
     * Format: security:baseline:vector:{userId}
     * TTL: 30 days
     */
    public static String baselineVector(String userId) {
        validateUserId(userId);
        return String.format("%s:baseline:vector:%s", NAMESPACE, userId);
    }

    // AI Native: trustScoreHistory() 제거 (v3.1.0) - @Deprecated 완전 제거

    /**
     * 사용자 권한 캐시
     * 동적으로 조정된 권한 정보
     * Format: security:trust:authorities:{userId}
     * TTL: 1 hour
     */
    public static String userAuthorities(String userId) {
        validateUserId(userId);
        return String.format("%s:trust:authorities:%s", NAMESPACE, userId);
    }
    
    /**
     * 사용자의 활성 세션 목록
     * 사용자가 가진 모든 세션 추적
     * Format: security:user:sessions:{userId}
     * Type: Set
     * TTL: 24 hours
     */
    public static String userSessions(String userId) {
        validateUserId(userId);
        return String.format("%s:user:sessions:%s", NAMESPACE, userId);
    }
    
    // AI Native: userBehavior() 제거 (v3.1.0) - 미사용
    // AI Native: userThreats() 제거 (v3.1.0) - 미사용

    /**
     * 이상 탐지 플래그
     * 갑작스러운 점수 변화 감지 시 설정
     * Format: anomaly_detected:{userId}
     * TTL: 10 minutes
     */
    public static String anomalyDetected(String userId) {
        validateUserId(userId);
        return String.format("anomaly_detected:%s", userId);
    }

    /**
     * Phase 14: LLM 분석 락 키
     * 동시 @Protectable 접근 시 중복 LLM 분석 방지
     * Format: security:analysis:lock:{userId}
     * TTL: 30 seconds
     *
     * 사용처:
     * - ZeroTrustEventListener: SETNX 락 획득/해제
     */
    public static String analysisLock(String userId) {
        validateUserId(userId);
        return String.format("%s:analysis:lock:%s", NAMESPACE, userId);
    }

    /**
     * Phase 14: LLM 분석 캐시 유효 시간 키
     * 분석 결과 캐시 만료 시간 저장
     * Format: security:analysis:validUntil:{userId}
     * TTL: 30 seconds (분석 결과와 동일)
     */
    public static String analysisValidUntil(String userId) {
        validateUserId(userId);
        return String.format("%s:analysis:validUntil:%s", NAMESPACE, userId);
    }

    /**
     * HCAD 분석 결과 (Primary - Single Source of Truth)
     *
     * AI Native: LLM이 분석한 전체 결과를 Hash로 저장
     * Format: security:hcad:analysis:{userId}
     * Type: Hash
     * Fields:
     *   - action: ALLOW, MONITOR, CHALLENGE, INVESTIGATE, ESCALATE, BLOCK
     *   - riskScore: 0.0 ~ 1.0
     *   - confidence: 0.0 ~ 1.0
     *   - threatLevel: CRITICAL, HIGH, MEDIUM, LOW, INFO
     *   - isAnomaly: true/false
     *   - threatType: 위협 유형 문자열
     *   - threatEvidence: 위협 증거 문자열
     *   - updatedAt: ISO-8601 타임스탬프
     *
     * TTL: Action별 상이 (BLOCK: 영구, INVESTIGATE: 5분, MONITOR: 10분, ALLOW: 1시간)
     *
     * 사용처:
     * - ColdPathEventProcessor: 저장 (Dual-Write)
     * - HCADAnalysisService: 조회 (전체 필드)
     * - ZeroTrustSecurityService: 조회 (action 필드만, Dual-Read)
     * - AbstractMfaAuthenticationSuccessHandler: 삭제 (action 필드, Dual-Delete)
     */
    public static String hcadAnalysis(String userId) {
        validateUserId(userId);
        return String.format("%s:hcad:analysis:%s", NAMESPACE, userId);
    }

    /**
     * 사용자 차단 상태
     * RealtimeBlockStrategy가 CRITICAL 위협 시 설정
     * Format: security:blocked:users:{userId}
     * Value: true/false
     * TTL: 없음 (관리자 해제 필요)
     */
    public static String userBlocked(String userId) {
        validateUserId(userId);
        return String.format("security:blocked:users:%s", userId);
    }

    /**
     * 사용자 BLOCK 횟수 (AI Native v5.1.0)
     *
     * 플랫폼 명제: "인증된 사용자가 진짜인가?" 검증
     * - IP 기반이 아닌 userId 기반으로 과거 이력 추적
     * - 이 사용자가 과거에 몇 번 BLOCK 판정을 받았는지 기록
     *
     * Format: security:user:block:count:{userId}
     * Type: Integer
     * TTL: 30 days
     *
     * 사용처:
     * - Layer2ExpertStrategy: HISTORICAL CONTEXT 구성
     * - ColdPathEventProcessor: BLOCK 판정 시 증가
     */
    public static String userBlockCount(String userId) {
        validateUserId(userId);
        return String.format("%s:user:block:count:%s", NAMESPACE, userId);
    }

    /**
     * 사용자 CHALLENGE 횟수 (AI Native v5.1.0)
     *
     * 플랫폼 명제: "인증된 사용자가 진짜인가?" 검증
     * - 이 사용자가 과거에 몇 번 MFA 인증 요청을 받았는지 기록
     *
     * Format: security:user:challenge:count:{userId}
     * Type: Integer
     * TTL: 30 days
     *
     * 사용처:
     * - Layer2ExpertStrategy: HISTORICAL CONTEXT 구성
     * - MfaAuthenticationSuccessHandler: CHALLENGE 성공 시 증가
     */
    public static String userChallengeCount(String userId) {
        validateUserId(userId);
        return String.format("%s:user:challenge:count:%s", NAMESPACE, userId);
    }

    // ============================================
    // THREAT INTELLIGENCE KEYS
    // ============================================

    /**
     * IP Reputation 점수
     * IP별 평판 점수 (0.0 ~ 1.0)
     * Format: security:ip:reputation:{ip}
     * TTL: 30 days
     */
    public static String ipReputation(String ip) {
        if (ip == null || ip.trim().isEmpty()) {
            throw new IllegalArgumentException("IP address cannot be null or empty");
        }
        return String.format("%s:ip:reputation:%s", NAMESPACE, ip);
    }

    /**
     * 공격 카운트
     * IP별 공격 시도 횟수
     * Format: security:attacks:count:{sourceIp}
     * TTL: 7 days
     */
    public static String attackCount(String sourceIp) {
        if (sourceIp == null || sourceIp.trim().isEmpty()) {
            throw new IllegalArgumentException("Source IP cannot be null or empty");
        }
        return String.format("%s:attacks:count:%s", NAMESPACE, sourceIp);
    }

    /**
     * 자산 메타데이터
     * 리소스별 중요도 및 메타데이터
     * Format: security:asset:metadata:{resource}
     * TTL: 30 days
     */
    public static String assetMetadata(String resource) {
        if (resource == null || resource.trim().isEmpty()) {
            throw new IllegalArgumentException("Resource cannot be null or empty");
        }
        return String.format("%s:asset:metadata:%s", NAMESPACE, resource);
    }

    /**
     * 인시던트 정보
     * 인시던트 ID별 상세 정보
     * Format: security:incident:{incidentId}
     * TTL: 90 days
     */
    public static String incident(String incidentId) {
        if (incidentId == null || incidentId.trim().isEmpty()) {
            throw new IllegalArgumentException("Incident ID cannot be null or empty");
        }
        return String.format("%s:incident:%s", NAMESPACE, incidentId);
    }

    /**
     * SOAR 실행 기록
     * 이벤트별 SOAR 플레이북 실행 기록
     * Format: security:soar:execution:{eventId}
     * TTL: 48 hours
     */
    public static String soarExecution(String eventId) {
        if (eventId == null || eventId.trim().isEmpty()) {
            throw new IllegalArgumentException("Event ID cannot be null or empty");
        }
        return String.format("%s:soar:execution:%s", NAMESPACE, eventId);
    }

    /**
     * 레이어별 피드백 데이터
     * Layer1/2/3의 이벤트별 피드백 저장
     * Format: security:feedback:layer{N}:{eventId}
     * TTL: 24-48 hours
     */
    public static String feedbackLayer(int layer, String eventId) {
        if (layer < 1 || layer > 3) {
            throw new IllegalArgumentException("Layer must be 1, 2, or 3");
        }
        if (eventId == null || eventId.trim().isEmpty()) {
            throw new IllegalArgumentException("Event ID cannot be null or empty");
        }
        return String.format("%s:feedback:layer%d:%s", NAMESPACE, layer, eventId);
    }

    /**
     * 정상 행동 패턴 (HotPath)
     * 사용자별 정상 패턴 학습 데이터
     * Format: security:user:normal:pattern:{userId}
     * TTL: 7 days
     */
    public static String normalPattern(String userId) {
        validateUserId(userId);
        return String.format("%s:user:normal:pattern:%s", NAMESPACE, userId);
    }

    /**
     * 세션-사용자 역매핑
     * sessionId로부터 userId를 찾기 위한 키
     * Format: security:session:user:{sessionId}
     * Value: userId
     * TTL: Session lifetime
     */
    public static String sessionUser(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:user:%s", NAMESPACE, sessionId);
    }

    // ============================================
    // SESSION MAPPING KEYS (참조용)
    // ============================================
    
    /**
     * 세션-사용자 매핑 (역참조)
     * 세션 ID로 사용자 찾기
     * Format: security:session:user:{sessionId}
     * Value: userId
     * TTL: Session lifetime
     */
    public static String sessionToUser(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:user:%s", NAMESPACE, sessionId);
    }
    
    /**
     * 세션 메타데이터 (보조)
     * 세션별 임시 데이터
     * Format: security:session:meta:{sessionId}
     * TTL: Session lifetime
     */
    public static String sessionMetadata(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:meta:%s", NAMESPACE, sessionId);
    }
    
    /**
     * 무효화된 세션 표시
     * Format: security:session:invalid:{sessionId}
     * TTL: 1 hour
     */
    public static String invalidSession(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:invalid:%s", NAMESPACE, sessionId);
    }

    /**
     * 세션별 액션 이력
     * 세션 내에서 수행된 최근 액션 목록
     * Format: security:session:actions:{sessionId}
     * Type: List
     * TTL: Session lifetime
     */
    public static String sessionActions(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:actions:%s", NAMESPACE, sessionId);
    }

    /**
     * 세션별 리스크 점수
     * 세션의 현재 리스크 수준
     * Format: security:session:risk:{sessionId}
     * TTL: Session lifetime
     */
    public static String sessionRisk(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:risk:%s", NAMESPACE, sessionId);
    }

    // AI Native: LEGACY KEYS 섹션 제거 (v3.1.0) - @Deprecated 완전 제거
    // legacySessionContext() 삭제됨

    // ============================================
    // PUB/SUB CHANNELS
    // ============================================
    
    /**
     * 세션 하이재킹 이벤트 채널
     * Format: security:session:hijack:event
     */
    public static String sessionHijackChannel() {
        return String.format("%s:session:hijack:event", NAMESPACE);
    }
    
    /**
     * 세션 무효화 이벤트 채널
     * Format: security:session:invalidation:event
     */
    public static String sessionInvalidationChannel() {
        return String.format("%s:session:invalidation:event", NAMESPACE);
    }
    
    /**
     * 사용자 위협 이벤트 채널
     * Format: security:user:threat:event
     */
    public static String userThreatChannel() {
        return String.format("%s:user:threat:event", NAMESPACE);
    }
    
    // ============================================
    // UTILITY METHODS
    // ============================================
    
    /**
     * userId에서 sessionId로 변환을 위한 조회 키
     * 두 단계 조회: userId → sessions → sessionId → context
     */
    public static String getUserSessionKey(String userId, String sessionId) {
        validateUserId(userId);
        validateSessionId(sessionId);
        return String.format("%s:user:%s:session:%s", NAMESPACE, userId, sessionId);
    }
    
    /**
     * 마이그레이션 지원: 레거시 키에서 신규 키로 변환
     */
    public static String migrateKey(String legacyKey) {
        if (legacyKey.contains(":session:context:")) {
            // session context를 user context로 변환하려면 userId 필요
            // 이는 실제 마이그레이션 로직에서 처리
            return legacyKey.replace(":session:context:", ":migration:pending:");
        }
        return legacyKey;
    }
    
    // ============================================
    // VALIDATION
    // ============================================
    
    private static void validateUserId(String userId) {
        if (userId == null || userId.trim().isEmpty()) {
            throw new IllegalArgumentException("UserId is required for Zero Trust architecture");
        }
    }
    
    private static void validateSessionId(String sessionId) {
        if (sessionId == null || sessionId.trim().isEmpty()) {
            throw new IllegalArgumentException("SessionId cannot be null or empty");
        }
    }
    
    // ============================================
    // KEY PATTERNS FOR SCANNING
    // ============================================
    
    /**
     * 사용자 관련 모든 키 패턴
     */
    public static String userKeyPattern(String userId) {
        validateUserId(userId);
        return String.format("%s:user:*:%s", NAMESPACE, userId);
    }
    
    /**
     * 특정 사용자의 모든 컨텍스트 키 패턴
     */
    public static String userContextPattern(String userId) {
        validateUserId(userId);
        return String.format("%s:*:*:%s", NAMESPACE, userId);
    }
    
    /**
     * 레거시 세션 키 패턴 (마이그레이션용)
     */
    public static String legacySessionPattern() {
        return String.format("%s:session:context:*", NAMESPACE);
    }

    // ============================================
    // EVENT COLLECTOR KEYS
    // ============================================

    /**
     * 이벤트 캐시 (Collector용)
     * Distributed cache for security events
     * Format: security:events:cache
     * TTL: Configured per entry
     */
    public static String eventsCache() {
        return String.format("%s:events:cache", NAMESPACE);
    }

    /**
     * 글로벌 이벤트 카운터
     * Global event counter across all collectors
     * Format: security:events:counter
     * TTL: No expiry
     */
    public static String eventsCounter() {
        return String.format("%s:events:counter", NAMESPACE);
    }

    /**
     * 이벤트 Rate Limiter
     * Rate limiting for event processing
     * Format: security:events:limiter
     * TTL: Managed by rate limiter
     */
    public static String eventsLimiter() {
        return String.format("%s:events:limiter", NAMESPACE);
    }

    /**
     * 이벤트 중복 제거 필터
     * Bloom filter for event deduplication
     * Format: security:events:dedup
     * TTL: No expiry (self-managed)
     */
    public static String eventsDedup() {
        return String.format("%s:events:dedup", NAMESPACE);
    }

    // ============================================
    // EVENT PUBLISHER KEYS
    // ============================================

    /**
     * 거부된 인증 이벤트 스트림
     * Authentication denial events stored in stream
     * Format: security:auth:denied:stream
     * TTL: Events auto-trimmed by stream MAXLEN
     */
    public static String authDeniedStream() {
        return String.format("%s:auth:denied:stream", NAMESPACE);
    }

    // AI Native: authDenied() 제거 (v3.1.0) - @Deprecated 완전 제거, authDeniedStream() 사용

    /**
     * Critical 사고 스트림
     * Critical incidents stored in stream
     * Format: security:incident:critical:stream
     * TTL: Events auto-trimmed by stream MAXLEN
     */
    public static String incidentCriticalStream() {
        return String.format("%s:incident:critical:stream", NAMESPACE);
    }

    // AI Native: incidentCritical() 제거 (v3.1.0) - @Deprecated 완전 제거, incidentCriticalStream() 사용

    /**
     * 고위험 위협 스트림
     * High-risk threats stored in stream
     * Format: security:threat:high:stream
     * TTL: Events auto-trimmed by stream MAXLEN
     */
    public static String threatHighStream() {
        return String.format("%s:threat:high:stream", NAMESPACE);
    }

    // AI Native: threatHigh() 제거 (v3.1.0) - @Deprecated 완전 제거, threatHighStream() 사용

    /**
     * 위협 타입별 카운터
     * Counter for each threat type
     * Format: security:threat:counter:{threatType}
     * TTL: No expiry (permanent counter)
     */
    public static String threatCounter(String threatType) {
        if (threatType == null || threatType.isBlank()) {
            throw new IllegalArgumentException("Threat type cannot be null or empty");
        }
        return String.format("%s:threat:counter:%s", NAMESPACE, threatType);
    }

    /**
     * 인증 이상 징후 스트림
     * Authentication anomaly events in stream
     * Format: security:auth:anomaly:stream:{userId}
     * TTL: Events auto-trimmed by stream MAXLEN
     */
    public static String authAnomalyStream(String userId) {
        validateUserId(userId);
        return String.format("%s:auth:anomaly:stream:%s", NAMESPACE, userId);
    }

    // AI Native: authAnomaly() 제거 (v3.1.0) - @Deprecated 완전 제거, authAnomalyStream() 사용

    /**
     * 이상 징후 카운터
     * Anomaly counter per user
     * Format: security:auth:anomaly:counter:{userId}
     * TTL: 7 days
     */
    public static String authAnomalyCounter(String userId) {
        validateUserId(userId);
        return String.format("%s:auth:anomaly:counter:%s", NAMESPACE, userId);
    }

    /**
     * 사용자별 인증 이력 스트림
     * User authentication history in stream (replacing list)
     * Format: security:user:auth:stream:{userId}
     * TTL: 7 days
     */
    public static String userAuthStream(String userId) {
        validateUserId(userId);
        return String.format("%s:user:auth:stream:%s", NAMESPACE, userId);
    }

    /**
     * 사용자별 인증 실패 이력
     * User authentication failures
     * Format: security:auth:failures:{username}
     * TTL: 1 day
     */
    public static String authFailures(String username) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }
        return String.format("%s:auth:failures:%s", NAMESPACE, username);
    }

    /**
     * IP별 공격 이벤트 스트림
     * Attack events per IP in stream
     * Format: security:auth:attack:stream:{sourceIp}
     * TTL: 48 hours
     */
    public static String authAttackStream(String sourceIp) {
        if (sourceIp == null || sourceIp.isBlank()) {
            throw new IllegalArgumentException("Source IP cannot be null or empty");
        }
        return String.format("%s:auth:attack:stream:%s", NAMESPACE, sourceIp);
    }

    // AI Native: authAttack() 제거 (v3.1.0) - @Deprecated 완전 제거, authAttackStream() 사용

    /**
     * IP별 공격 카운터
     * Attack counter per IP
     * Format: security:auth:attack:counter:{sourceIp}
     * TTL: 24 hours (aligned with IP blocking)
     */
    public static String authAttackCounter(String sourceIp) {
        if (sourceIp == null || sourceIp.isBlank()) {
            throw new IllegalArgumentException("Source IP cannot be null or empty");
        }
        return String.format("%s:auth:attack:counter:%s", NAMESPACE, sourceIp);
    }

    /**
     * IP 차단 목록
     * Blocked IP list
     * Format: security:auth:blocked:ip:{sourceIp}
     * TTL: 24 hours
     */
    public static String authBlockedIp(String sourceIp) {
        if (sourceIp == null || sourceIp.isBlank()) {
            throw new IllegalArgumentException("Source IP cannot be null or empty");
        }
        return String.format("%s:auth:blocked:ip:%s", NAMESPACE, sourceIp);
    }

    // ============================================
    // GOVERNANCE & APPROVAL KEYS
    // ============================================

    /**
     * 정책 승인 워크플로우
     * AI 정책 제안의 승인 워크플로우 저장
     * Format: security:governance:approval:workflow:{proposalId}
     * Type: Hash (직렬화된 ApprovalWorkflow)
     * TTL: 7 days
     */
    public static String approvalWorkflow(Long proposalId) {
        if (proposalId == null) {
            throw new IllegalArgumentException("Proposal ID cannot be null");
        }
        return String.format("%s:governance:approval:workflow:%d", NAMESPACE, proposalId);
    }

    /**
     * 활성 승인 워크플로우 인덱스
     * 모든 활성 워크플로우의 proposalId 목록
     * Format: security:governance:approval:index
     * Type: Set (Long - proposalId)
     * TTL: No expiry
     */
    public static String approvalWorkflowIndex() {
        return String.format("%s:governance:approval:index", NAMESPACE);
    }

    /**
     * 승인 요청 개별 키
     * 빠른 조회를 위한 requestId → proposalId 매핑
     * Format: security:governance:approval:request:{requestId}
     * Value: proposalId
     * TTL: 7 days
     */
    public static String approvalRequest(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            throw new IllegalArgumentException("Request ID cannot be null or empty");
        }
        return String.format("%s:governance:approval:request:%s", NAMESPACE, requestId);
    }

    // ============================================
    // AGENT OPERATION KEYS
    // ============================================

    /**
     * 이벤트 처리 완료 표시
     * SecurityPlaneAgent가 이벤트 처리 완료 후 설정
     * Format: security:processed:{eventId}
     * Type: String (boolean)
     * TTL: 1 hour
     */
    public static String eventProcessed(String eventId) {
        if (eventId == null || eventId.isBlank()) {
            throw new IllegalArgumentException("Event ID cannot be null or empty");
        }
        return String.format("%s:processed:%s", NAMESPACE, eventId);
    }

    // processingMetrics() 제거: Dead Code - 저장만 하고 조회 코드 없음
}