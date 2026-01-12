package io.contexa.contexacore.autonomous.tiered.template;

/**
 * AI Native v6.2: Baseline 상태 enum
 *
 * 복잡한 조건문 기반 상태 판단을 명확한 enum으로 단순화합니다.
 * Layer1PromptTemplate, Layer2PromptTemplate에서 공통 사용.
 *
 * 기존 문제점:
 * - 7가지 경우의 수
 * - 상호 배타적이지 않은 조건
 * - 유지보수 어려움
 *
 * 개선:
 * - 명확한 상태 정의
 * - 상호 배타적 상태
 * - 일관된 프롬프트 출력
 *
 * @since AI Native v6.2
 */
public enum BaselineStatus {

    /**
     * 유효한 baseline 데이터가 존재함
     * - Redis에 사용자 baseline 저장됨
     * - confidence > 0
     * - 정상적인 행동 패턴 비교 가능
     */
    ESTABLISHED("Available", "User baseline data is available for comparison"),

    /**
     * 신규 사용자 - baseline이 아직 확립되지 않음
     * - Redis에 baseline 없음
     * - 첫 번째 접근 또는 baseline 만료
     * - Zero Trust: ALLOW 불가, CHALLENGE 또는 ESCALATE 권장
     */
    NEW_USER("[NEW_USER] No baseline established", "Cannot compare against historical patterns"),

    /**
     * Baseline이 존재하지만 로드 실패
     * - Redis 조회 성공, 데이터 파싱 실패
     * - 또는 BehaviorAnalysis에서 baselineEstablished=true지만 컨텍스트 없음
     */
    NOT_LOADED("[NO_DATA] Baseline available but not loaded", "Anomaly detection unavailable"),

    /**
     * Baseline 서비스 자체가 사용 불가
     * - Redis 연결 실패
     * - BaselineLearningService 미구성
     */
    SERVICE_UNAVAILABLE("[SERVICE_UNAVAILABLE] Baseline service not available", "Anomaly detection unavailable"),

    /**
     * 사용자 ID가 없어서 baseline 조회 불가
     * - 인증되지 않은 요청
     * - 세션에서 userId 추출 실패
     */
    MISSING_USER_ID("[NO_USER_ID] Cannot lookup baseline without user identifier", "Anomaly detection unavailable"),

    /**
     * BehaviorAnalysis 자체가 null
     * - 행동 분석 시스템 오류 또는 초기화 실패
     */
    ANALYSIS_UNAVAILABLE("[NO_DATA] Behavior analysis unavailable", "ESCALATE recommended");

    private final String statusLabel;
    private final String impactDescription;

    BaselineStatus(String statusLabel, String impactDescription) {
        this.statusLabel = statusLabel;
        this.impactDescription = impactDescription;
    }

    /**
     * 프롬프트에 표시할 STATUS 라벨
     */
    public String getStatusLabel() {
        return statusLabel;
    }

    /**
     * 프롬프트에 표시할 IMPACT 설명
     */
    public String getImpactDescription() {
        return impactDescription;
    }

    /**
     * Zero Trust 위반 여부 (baseline 없이 ALLOW 불가능한 상태)
     *
     * @return true면 ALLOW 불가, CHALLENGE/ESCALATE 권장
     */
    public boolean isZeroTrustViolation() {
        return this != ESTABLISHED;
    }

    /**
     * 프롬프트 섹션 문자열 생성
     *
     * @param baselineContext 유효한 baseline인 경우 컨텍스트 문자열
     * @return 프롬프트에 포함할 BASELINE 섹션
     */
    public String buildPromptSection(String baselineContext) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== BASELINE ===\n");
        sb.append("STATUS: ").append(statusLabel).append("\n");

        if (this == ESTABLISHED && baselineContext != null) {
            sb.append(baselineContext).append("\n");
        } else {
            sb.append("IMPACT: ").append(impactDescription).append("\n");
        }

        return sb.toString();
    }
}
