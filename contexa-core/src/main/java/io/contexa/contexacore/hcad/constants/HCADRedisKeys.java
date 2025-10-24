package io.contexa.contexacore.hcad.constants;

/**
 * HCAD Redis Key Management
 *
 * HCAD (Hyper-lightweight Context Anomaly Detector) Redis 키 관리 유틸리티
 * ZeroTrustRedisKeys 패턴을 준수하며 HCAD 전용 키를 정의합니다.
 *
 * 핵심 원칙:
 * 1. userId가 Primary Key - 모든 사용자 데이터의 기준점
 * 2. "security" 네임스페이스 사용 (ZeroTrustRedisKeys와 통일)
 * 3. 명시적 TTL 정책
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
public class HCADRedisKeys {

    // 기본 네임스페이스 (ZeroTrustRedisKeys와 동일)
    private static final String NAMESPACE = "security";

    // HCAD 서브 네임스페이스
    private static final String HCAD_NS = NAMESPACE + ":hcad";

    // ============================================
    // USER-CENTRIC KEYS (userId 기반 - Primary)
    // ============================================

    /**
     * HCAD 베이스라인 벡터
     * 사용자별 행동 베이스라인 384차원 벡터
     * Format: security:baseline:vector:{userId}
     * TTL: 30 days (지속적 학습)
     * Type: BaselineVector (Serialized)
     *
     * IMPORTANT: ZeroTrustRedisKeys.baselineVector()와 동일한 키 사용
     * 중앙집중식 키 관리를 위해 표준화됨
     */
    public static String baselineVector(String userId) {
        validateUserId(userId);
        // ZeroTrustRedisKeys와 동일한 키 반환
        return String.format("%s:baseline:vector:%s", NAMESPACE, userId);
    }



    /**
     * 글로벌 통계
     * 전체 시스템 통계 (사용자 무관)
     * Format: security:hcad:stats:global:v2
     * TTL: 없음 (영구)
     * Type: Hash
     */
    public static String globalStats() {
        return String.format("%s:stats:global:v2", HCAD_NS);
    }



    // ============================================
    // SESSION MAPPING KEYS (참조용)
    // ============================================

    /**
     * 세션 위협 Grace Period
     * 세션 무효화 유예 기간 플래그
     * Format: security:hcad:session:grace:{sessionId}
     * TTL: 5 minutes
     * Type: Boolean
     */
    public static String sessionThreatGrace(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:grace:%s", HCAD_NS, sessionId);
    }

    /**
     * 세션 지연 무효화
     * 점진적 세션 무효화 상태
     * Format: security:hcad:session:delayed:{sessionId}
     * TTL: 1 hour
     * Type: DelayedInvalidationInfo
     */
    public static String sessionThreatDelayed(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:delayed:%s", HCAD_NS, sessionId);
    }

    /**
     * 세션 모니터링 상태
     * 세션 모니터링 활성화 플래그
     * Format: security:hcad:session:monitoring:{sessionId}
     * TTL: 1 hour
     * Type: Boolean
     */
    public static String sessionThreatMonitoring(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:monitoring:%s", HCAD_NS, sessionId);
    }

    // ============================================
    // THRESHOLD MANAGEMENT KEYS (임계값 관리)
    // ============================================


    /**
     * 피드백 기반 임계값 조정
     * FeedbackLoopSystem이 관리하는 임계값 조정값
     * Format: security:hcad:threshold:feedback:{userId}
     * TTL: 7 days
     * Type: Double
     */
    public static String feedbackThreshold(String userId) {
        validateUserId(userId);
        return String.format("%s:threshold:feedback:%s", HCAD_NS, userId);
    }

    /**
     * 통합 임계값 캐시
     * UnifiedThresholdManager가 계산한 최종 임계값
     * Format: security:hcad:threshold:unified:{userId}
     * TTL: 1 hour
     * Type: Double
     */
    public static String unifiedThreshold(String userId) {
        validateUserId(userId);
        return String.format("%s:threshold:unified:%s", HCAD_NS, userId);
    }

    /**
     * 임계값 프로파일
     * 사용자별 임계값 프로파일 (시간대, 위험도 등)
     * Format: security:hcad:threshold:profile:{userId}
     * TTL: 7 days (30일)
     * Type: UserThresholdProfile
     */
    public static String thresholdProfile(String userId) {
        validateUserId(userId);
        return String.format("%s:threshold:profile:%s", HCAD_NS, userId);
    }

    /**
     * 임계값 설정 캐시
     * 사용자별 임계값 설정 (5분 캐시)
     * Format: security:hcad:threshold:config:{userId}
     * TTL: 5 minutes
     * Type: ThresholdConfiguration
     */
    public static String thresholdConfig(String userId) {
        validateUserId(userId);
        return String.format("%s:threshold:config:%s", HCAD_NS, userId);
    }

    /**
     * 업무 시간 패턴
     * 사용자별 업무 시간 패턴 (시간대별 활동 패턴)
     * Format: security:hcad:threshold:work:hours:{userId}
     * TTL: 30 days
     * Type: Map<String, Object>
     */
    public static String thresholdWorkHours(String userId) {
        validateUserId(userId);
        return String.format("%s:threshold:work:hours:%s", HCAD_NS, userId);
    }

    /**
     * 계절성 패턴 (조직 전체)
     * 조직 전체의 계절성 패턴 (월별 활동 패턴)
     * Format: security:hcad:threshold:seasonal:patterns
     * TTL: 90 days
     * Type: Map<String, Object>
     */
    public static String thresholdSeasonalPatterns() {
        return String.format("%s:threshold:seasonal:patterns", HCAD_NS);
    }



    // ============================================
    // FEEDBACK & LEARNING KEYS (피드백 및 학습)
    // ============================================

    /**
     * 피드백 레코드
     * 사용자 피드백 기록 (False Positive/Negative 등)
     * Format: security:hcad:feedback:{userId}:{timestamp}
     * TTL: 30 days
     * Type: FeedbackRecord
     */
    public static String feedbackRecord(String userId, long timestamp) {
        validateUserId(userId);
        return String.format("%s:feedback:%s:%d", HCAD_NS, userId, timestamp);
    }

    /**
     * False Positive 패턴
     * 오탐 패턴 저장 (학습용)
     * Format: security:hcad:patterns:fp:{userId}
     * TTL: 7 days
     * Type: List<HCADContext>
     */
    public static String falsePositivePatterns(String userId) {
        validateUserId(userId);
        return String.format("%s:patterns:fp:%s", HCAD_NS, userId);
    }

    /**
     * Blacklist 패턴
     * 미탐 패턴 블랙리스트 (위협 패턴)
     * Format: security:hcad:patterns:blacklist:{userId}
     * TTL: 없음 (영구)
     * Type: Set<Vector>
     */
    public static String blacklistPatterns(String userId) {
        validateUserId(userId);
        return String.format("%s:patterns:blacklist:%s", HCAD_NS, userId);
    }

    /**
     * True Positive 패턴
     * 정탐 패턴 저장 (강화 학습용)
     * Format: security:hcad:patterns:tp:{userId}
     * TTL: 7 days
     * Type: List<HCADContext>
     */
    public static String truePositivePatterns(String userId) {
        validateUserId(userId);
        return String.format("%s:patterns:tp:%s", HCAD_NS, userId);
    }

    /**
     * 모델 신뢰도
     * 사용자별 HCAD 모델 신뢰도
     * Format: security:hcad:model:confidence:{userId}
     * TTL: 없음 (영구)
     * Type: Double
     */
    public static String modelConfidence(String userId) {
        validateUserId(userId);
        return String.format("%s:model:confidence:%s", HCAD_NS, userId);
    }

    /**
     * 노이즈 레벨
     * 사용자별 탐지 노이즈 수준
     * Format: security:hcad:noise:level:{userId}
     * TTL: 7 days
     * Type: Double
     */
    public static String noiseLevel(String userId) {
        validateUserId(userId);
        return String.format("%s:noise:level:%s", HCAD_NS, userId);
    }

    /**
     * 피드백 가중치
     * FeedbackLoopSystem이 관리하는 계층별 가중치
     * Format: security:hcad:feedback:weights:{userId}
     * TTL: 30 days
     * Type: Map<String, Double>
     */
    public static String feedbackWeights(String userId) {
        validateUserId(userId);
        return String.format("%s:feedback:weights:%s", HCAD_NS, userId);
    }

    /**
     * 피드백 신뢰도
     * 사용자별 피드백 신뢰도 카운터
     * Format: security:hcad:feedback:confidence:{userId}
     * TTL: 없음 (영구)
     * Type: Integer
     */
    public static String feedbackConfidence(String userId) {
        validateUserId(userId);
        return String.format("%s:feedback:confidence:%s", HCAD_NS, userId);
    }

    /**
     * Cold Path 위협 조정값
     * AI 진단 결과의 threatScoreAdjustment
     * Format: security:hcad:threat:adjustment:{userId}
     * TTL: 1 hour
     * Type: Double
     */
    public static String threatAdjustment(String userId) {
        validateUserId(userId);
        return String.format("%s:threat:adjustment:%s", HCAD_NS, userId);
    }

    // ============================================
    // SIGNAL INCONSISTENCY KEYS (신호 불일치 탐지)
    // ============================================

    /**
     * 신호 불일치 StdDev 임계값
     * SignalInconsistencyDetector가 사용하는 표준편차 임계값
     * Format: security:hcad:signal:inconsistency:stddev:threshold:{userId}
     * TTL: 30 days
     * Type: Double
     */
    public static String inconsistencyStdDevThreshold(String userId) {
        validateUserId(userId);
        return String.format("%s:signal:inconsistency:stddev:threshold:%s", HCAD_NS, userId);
    }

    /**
     * 신호 불일치 Outlier 임계값
     * SignalInconsistencyDetector가 사용하는 Mahalanobis Distance 임계값
     * Format: security:hcad:signal:inconsistency:outlier:threshold:{userId}
     * TTL: 30 days
     * Type: Double
     */
    public static String inconsistencyOutlierThreshold(String userId) {
        validateUserId(userId);
        return String.format("%s:signal:inconsistency:outlier:threshold:%s", HCAD_NS, userId);
    }

    /**
     * 신호 불일치 탐지 이력
     * 자동 튜닝을 위한 탐지 이력 (최근 100개)
     * Format: security:hcad:signal:inconsistency:history:{userId}
     * TTL: 7 days
     * Type: List<Map<String, Object>>
     */
    public static String inconsistencyHistory(String userId) {
        validateUserId(userId);
        return String.format("%s:signal:inconsistency:history:%s", HCAD_NS, userId);
    }

    // ============================================
    // CONTEXT EXTRACTION KEYS (컨텍스트 추출)
    // ============================================

    /**
     * 세션 정보 캐시
     * 세션 메타데이터 캐시
     * Format: security:hcad:session:info:{sessionId}
     * TTL: 24 hours
     * Type: SessionInfo
     */
    public static String sessionInfo(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:info:%s", HCAD_NS, sessionId);
    }

    /**
     * 요청 카운터
     * 사용자별 최근 요청 카운터 (5분 윈도우)
     * Format: security:hcad:request:counter:{userId}
     * TTL: 10 minutes
     * Type: ZSet (timestamp as score)
     */
    public static String requestCounter(String userId) {
        validateUserId(userId);
        return String.format("%s:request:counter:%s", HCAD_NS, userId);
    }

    /**
     * 마지막 요청 타임스탬프
     * 사용자의 마지막 요청 시간
     * Format: security:hcad:last:request:{userId}
     * TTL: 10 minutes
     * Type: Long
     */
    public static String lastRequest(String userId) {
        validateUserId(userId);
        return String.format("%s:last:request:%s", HCAD_NS, userId);
    }

    /**
     * 이전 경로
     * 사용자의 이전 요청 경로
     * Format: security:hcad:previous:path:{userId}
     * TTL: 10 minutes
     * Type: String
     */
    public static String previousPath(String userId) {
        validateUserId(userId);
        return String.format("%s:previous:path:%s", HCAD_NS, userId);
    }

    /**
     * 로그인 실패 카운터
     * 사용자별 로그인 실패 횟수
     * Format: security:hcad:failed:login:{userId}
     * TTL: 1 hour
     * Type: Integer
     */
    public static String failedLoginCounter(String userId) {
        validateUserId(userId);
        return String.format("%s:failed:login:%s", HCAD_NS, userId);
    }

    /**
     * MFA 검증 상태
     * 사용자의 MFA 검증 여부
     * Format: security:hcad:mfa:verified:{userId}
     * TTL: 24 hours
     * Type: Boolean
     */
    public static String mfaVerified(String userId) {
        validateUserId(userId);
        return String.format("%s:mfa:verified:%s", HCAD_NS, userId);
    }

    // ============================================
    // SYNC & ORCHESTRATION KEYS (동기화 및 오케스트레이션)
    // ============================================

    /**
     * Cold Path 동기화 타임아웃 카운터
     * 사용자별 동기화 타임아웃 발생 횟수
     * Format: security:hcad:sync:timeout:counter:{userId}
     * TTL: 1 hour
     * Type: Integer
     */
    public static String syncTimeoutCounter(String userId) {
        validateUserId(userId);
        return String.format("%s:sync:timeout:counter:%s", HCAD_NS, userId);
    }

    /**
     * Cold Path 동기화 마지막 성공 시간
     * Format: security:hcad:sync:last:success:{userId}
     * TTL: 24 hours
     * Type: Long (timestamp)
     */
    public static String syncLastSuccess(String userId) {
        validateUserId(userId);
        return String.format("%s:sync:last:success:%s", HCAD_NS, userId);
    }

    // ============================================
    // PUB/SUB CHANNELS (이벤트 채널)
    // ============================================

    /**
     * 모델 재학습 채널
     * Format: security:hcad:retrain:channel
     */
    public static String retrainChannel() {
        return String.format("%s:retrain:channel", HCAD_NS);
    }

    /**
     * 임계값 업데이트 채널
     * Format: security:hcad:threshold:update:channel
     */
    public static String thresholdUpdateChannel() {
        return String.format("%s:threshold:update:channel", HCAD_NS);
    }

    /**
     * Cold Path 동기화 실패 알림 채널
     * Format: security:hcad:sync:failure:channel
     */
    public static String syncFailureChannel() {
        return String.format("%s:sync:failure:channel", HCAD_NS);
    }

    // ============================================
    // TTL CONSTANTS (TTL 상수)
    // ============================================

    public static final int TTL_BASELINE_DAYS = 30;
    public static final int TTL_SESSION_EMBEDDING_HOURS = 1;
    public static final int TTL_CRITICAL_METRICS_HOURS = 24;
    public static final int TTL_SCENARIO_DAYS = 30;
    public static final int TTL_SCENARIO_EMBEDDING_DAYS = 7;
    public static final int TTL_THRESHOLD_DAYS = 7;
    public static final int TTL_THRESHOLD_UNIFIED_HOURS = 1;
    public static final int TTL_FEEDBACK_DAYS = 30;
    public static final int TTL_FP_PATTERNS_DAYS = 7;
    public static final int TTL_TP_PATTERNS_DAYS = 7;
    public static final int TTL_SESSION_INFO_HOURS = 24;
    public static final int TTL_REQUEST_COUNTER_MINUTES = 10;
    public static final int TTL_SESSION_GRACE_MINUTES = 5;
    public static final int TTL_SESSION_DELAYED_HOURS = 1;
    public static final int TTL_SYNC_TIMEOUT_HOURS = 1;

    // ============================================
    // VALIDATION (검증)
    // ============================================

    private static void validateUserId(String userId) {
        if (userId == null || userId.trim().isEmpty()) {
            throw new IllegalArgumentException("UserId is required for HCAD Redis keys");
        }
    }

    private static void validateSessionId(String sessionId) {
        if (sessionId == null || sessionId.trim().isEmpty()) {
            throw new IllegalArgumentException("SessionId cannot be null or empty");
        }
    }

    private static void validateScenario(String scenario) {
        if (scenario == null || scenario.trim().isEmpty()) {
            throw new IllegalArgumentException("Scenario cannot be null or empty");
        }
    }

    // ============================================
    // KEY PATTERNS FOR SCANNING (스캔용 패턴)
    // ============================================

    /**
     * 사용자의 모든 HCAD 키 패턴
     */
    public static String userHcadPattern(String userId) {
        validateUserId(userId);
        return String.format("%s:*:%s*", HCAD_NS, userId);
    }

    /**
     * 사용자의 모든 임계값 키 패턴
     */
    public static String userThresholdPattern(String userId) {
        validateUserId(userId);
        return String.format("%s:threshold:*:%s", HCAD_NS, userId);
    }

    /**
     * 사용자의 모든 패턴 키 패턴
     */
    public static String userPatternPattern(String userId) {
        validateUserId(userId);
        return String.format("%s:patterns:*:%s", HCAD_NS, userId);
    }
}
