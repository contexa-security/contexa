package io.contexa.contexacore.std.rag.constants;

/**
 * Vector Store 문서 메타데이터 표준 필드 상수
 *
 * 모든 Lab 서비스에서 사용하는 메타데이터 필드를 표준화합니다.
 *
 * 메타데이터 계층:
 * 1. 공통 필드 (모든 문서): id, timestamp, documentType, version
 * 2. Lab별 필드 (선택적): 각 Lab에서 정의 및 사용
 *
 * 일관성 규칙:
 * - 필드명은 camelCase 사용
 * - 타임스탬프는 ISO-8601 형식 (yyyy-MM-ddTHH:mm:ss)
 * - documentType은 소문자_스네이크_케이스
 * - ID는 UUID v4 형식
 *
 * @author contexa
 * @since 3.0
 */
public final class VectorDocumentMetadata {

    // ==================== 공통 필드 (모든 문서) ====================

    /**
     * 문서 고유 ID (UUID v4)
     */
    public static final String ID = "id";

    /**
     * 문서 생성 타임스탬프 (ISO-8601 형식)
     */
    public static final String TIMESTAMP = "timestamp";

    /**
     * 문서 타입 (라우팅에 사용)
     */
    public static final String DOCUMENT_TYPE = "documentType";

    /**
     * 문서 버전 (기본값: "1.0")
     */
    public static final String VERSION = "version";

    // ==================== 청킹 관련 ====================

    /**
     * 청크 ID (문서 분할 시)
     */
    public static final String CHUNK_ID = "chunkId";

    /**
     * 원본 문서 ID (청크의 원본)
     */
    public static final String ORIGINAL_DOCUMENT_ID = "originalDocumentId";

    /**
     * 청크 인덱스 (0부터 시작)
     */
    public static final String CHUNK_INDEX = "chunkIndex";

    /**
     * 총 청크 수
     */
    public static final String TOTAL_CHUNKS = "totalChunks";

    // ==================== 검색 관련 ====================

    /**
     * 유사도 점수 (0.0 ~ 1.0)
     */
    public static final String SIMILARITY_SCORE = "similarityScore";

    /**
     * 검색 순위
     */
    public static final String SEARCH_RANK = "searchRank";

    /**
     * 키워드 목록
     */
    public static final String KEYWORDS = "keywords";

    /**
     * 요약 텍스트
     */
    public static final String SUMMARY = "summary";

    // ==================== 문서 타입 값 ====================

    /**
     * 표준 문서 타입 (기본값)
     */
    public static final String TYPE_STANDARD = "standard";

    /**
     * 행동 분석 문서 타입
     */
    public static final String TYPE_BEHAVIOR_ANALYSIS = "behavior_analysis";

    /**
     * 위험 평가 문서 타입
     */
    public static final String TYPE_RISK_ASSESSMENT = "risk_assessment";

    /**
     * HCAD 학습 패턴 문서 타입
     */
    public static final String TYPE_HCAD_PATTERN = "hcad_pattern";

    /**
     * Layer1 피드백 문서 타입
     */
    public static final String TYPE_LAYER1_FEEDBACK = "layer1_feedback";

    /**
     * Layer2 피드백 문서 타입
     */
    public static final String TYPE_LAYER2_FEEDBACK = "layer2_feedback";

    /**
     * Layer3 피드백 문서 타입
     */
    public static final String TYPE_LAYER3_FEEDBACK = "layer3_feedback";

    // ==================== Behavior Lab 전용 ====================

    /**
     * 사용자 ID
     */
    public static final String USER_ID = "userId";

    /**
     * 현재 활동
     */
    public static final String CURRENT_ACTIVITY = "currentActivity";

    /**
     * 활동 시퀀스
     */
    public static final String ACTIVITY_SEQUENCE = "activitySequence";

    /**
     * 행동 이상 점수 (0.0 ~ 1.0)
     */
    public static final String BEHAVIOR_ANOMALY_SCORE = "behaviorAnomalyScore";

    /**
     * 위협 타입
     */
    public static final String THREAT_TYPE = "threatType";

    /**
     * MITRE ATT&CK 전술
     */
    public static final String MITRE_TACTIC = "mitreTactic";

    /**
     * MITRE ATT&CK 기술
     */
    public static final String MITRE_TECHNIQUE = "mitreTechnique";

    // ==================== Risk Assessment Lab 전용 ====================

    /**
     * Zero Trust 준수 여부
     */
    public static final String ZERO_TRUST_COMPLIANCE = "zeroTrustCompliance";

    /**
     * 위험 카테고리 목록
     */
    public static final String RISK_CATEGORIES = "riskCategories";

    /**
     * 신뢰 점수 (0.0 ~ 1.0)
     */
    public static final String TRUST_SCORE = "trustScore";

    /**
     * 위험 레벨 (LOW, MEDIUM, HIGH, CRITICAL)
     */
    public static final String RISK_LEVEL = "riskLevel";

    /**
     * 컴플라이언스 프레임워크
     */
    public static final String COMPLIANCE_FRAMEWORK = "complianceFramework";

    // ==================== HCAD 관련 ====================

    /**
     * HCAD 점수 (0.0 ~ 1.0)
     */
    public static final String HCAD_SCORE = "hcadScore";

    /**
     * Cold Path 여부
     */
    public static final String IS_COLD_PATH = "isColdPath";

    /**
     * Hot Path 여부
     */
    public static final String IS_HOT_PATH = "isHotPath";

    /**
     * 베이스라인 버전
     */
    public static final String BASELINE_VERSION = "baselineVersion";

    // ==================== Layer 피드백 관련 ====================

    /**
     * Layer 번호 (1, 2, 3)
     */
    public static final String LAYER_NUMBER = "layerNumber";

    /**
     * 결정 타입 (ALLOW, BLOCK, CHALLENGE)
     */
    public static final String DECISION_TYPE = "decisionType";

    /**
     * 이벤트 ID
     */
    public static final String EVENT_ID = "eventId";

    /**
     * 신뢰 레벨
     */
    public static final String CONFIDENCE_LEVEL = "confidenceLevel";

    /**
     * 거짓 양성 여부
     */
    public static final String IS_FALSE_POSITIVE = "isFalsePositive";

    // ==================== 헬퍼 메서드 ====================

    /**
     * Private constructor to prevent instantiation
     */
    private VectorDocumentMetadata() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    /**
     * 필수 필드 검증
     *
     * @param metadata 검증할 메타데이터
     * @return 모든 필수 필드가 존재하면 true
     */
    public static boolean hasRequiredFields(java.util.Map<String, Object> metadata) {
        return metadata != null &&
               metadata.containsKey(ID) &&
               metadata.containsKey(TIMESTAMP) &&
               metadata.containsKey(DOCUMENT_TYPE);
    }

    /**
     * 표준 문서 타입 여부 확인
     *
     * @param documentType 확인할 문서 타입
     * @return 표준 문서 타입이면 true
     */
    public static boolean isStandardType(String documentType) {
        return TYPE_STANDARD.equals(documentType);
    }

    /**
     * Lab 문서 타입 여부 확인
     *
     * @param documentType 확인할 문서 타입
     * @return Lab 문서 타입이면 true
     */
    public static boolean isLabType(String documentType) {
        return TYPE_BEHAVIOR_ANALYSIS.equals(documentType) ||
               TYPE_RISK_ASSESSMENT.equals(documentType);
    }

    /**
     * Layer 피드백 타입 여부 확인
     *
     * @param documentType 확인할 문서 타입
     * @return Layer 피드백 타입이면 true
     */
    public static boolean isLayerFeedbackType(String documentType) {
        return TYPE_LAYER1_FEEDBACK.equals(documentType) ||
               TYPE_LAYER2_FEEDBACK.equals(documentType) ||
               TYPE_LAYER3_FEEDBACK.equals(documentType);
    }
}
