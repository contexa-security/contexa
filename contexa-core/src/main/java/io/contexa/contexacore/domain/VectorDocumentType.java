package io.contexa.contexacore.domain;

/**
 * ✅ Phase 3: Vector Store Document Type 표준화 Enum
 *
 * vector_store 테이블의 metadata.documentType 필드 표준화를 위한 Enum
 * RAG 검색 시 documentType 기반 필터링으로 정확한 컨텍스트 검색 가능
 *
 * @since 1.0.0
 */
public enum VectorDocumentType {

    /**
     * 위협 패턴 (Threat Pattern)
     * - 고위험 이벤트의 위협 패턴
     * - Layer1/2/3에서 riskScore >= 임계값일 때 저장
     * - MITRE ATT&CK 매핑 포함
     */
    THREAT("threat"),

    /**
     * 정상/비정상 행동 패턴 (Behavior Pattern)
     * - 일반적인 보안 이벤트 행동
     * - Layer1/2/3에서 기본 저장
     */
    BEHAVIOR("behavior"),

    /**
     * 행동 분석 결과 (Behavior Analysis)
     * - AI 분석 결과 (HCADVectorIntegrationService)
     * - Layer1/2/3 피드백 인덱싱
     */
    BEHAVIOR_ANALYSIS("behavior_analysis"),

    /**
     * 정책 진화 패턴 (Policy Evolution)
     * - PolicyEvolutionHelper의 정책 학습 결과
     * - 자율 진화 정책 패턴
     */
    POLICY_EVOLUTION("policy_evolution"),

    /**
     * 장기 메모리 (Long-Term Memory)
     * - MemorySystemHelper의 LTM consolidation 결과
     * - 중요한 단기 메모리의 장기 저장
     */
    MEMORY_LTM("memory_ltm"),

    /**
     * 위험 평가 (Risk Assessment)
     * - RiskAssessmentVectorService의 위험 분석
     */
    RISK_ASSESSMENT("risk_assessment"),

    /**
     * 접근 거버넌스 (Access Governance)
     * - AccessGovernanceLabConnector의 접근 제어 패턴
     */
    ACCESS_GOVERNANCE("access_governance");

    private final String value;

    VectorDocumentType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    /**
     * 문자열로부터 Enum 변환
     *
     * @param value 문자열 값
     * @return VectorDocumentType
     */
    public static VectorDocumentType fromValue(String value) {
        if (value == null) {
            return BEHAVIOR; // 기본값
        }

        for (VectorDocumentType type : values()) {
            if (type.value.equalsIgnoreCase(value)) {
                return type;
            }
        }

        return BEHAVIOR; // 기본값
    }

    /**
     * documentType 문자열 반환 (metadata 저장용)
     */
    @Override
    public String toString() {
        return value;
    }

    /**
     * 위협 관련 타입인지 확인
     */
    public boolean isThreatRelated() {
        return this == THREAT || this == BEHAVIOR_ANALYSIS;
    }

    /**
     * 정책 관련 타입인지 확인
     */
    public boolean isPolicyRelated() {
        return this == POLICY_EVOLUTION;
    }

    /**
     * 메모리 관련 타입인지 확인
     */
    public boolean isMemoryRelated() {
        return this == MEMORY_LTM;
    }
}
