package io.contexa.contexacore.autonomous.tiered.routing;

/**
 * 보안 이벤트 처리 모드
 * 
 * 각 계층에서 위험 점수와 신뢰도에 따라 결정되는 처리 방식입니다.
 * AI-Native 보안 플랫폼의 동적 처리 전략을 지원합니다.
 */
public enum ProcessingMode {
    
    /**
     * 즉시 차단
     * - 위험 점수: >= 0.8
     * - 처리: 실시간 차단 후 로깅
     * - 대상: 명백한 공격, 알려진 위협
     * - 계층: 주로 Layer 1
     */
    REALTIME_BLOCK,
    
    /**
     * 통과
     * - 위험 점수: < 0.4
     * - 처리: 즉시 허용
     * - 대상: 정상 트래픽
     * - 계층: 주로 Layer 1
     */
    PASS_THROUGH,

    /**
     * AI 기반 상세 분석
     * - 위험 점수: 0.6 - 0.8 (중간-높은 위험)
     * - 조건: 낮은 유사도 이벤트 (< 0.85) 또는 중간 위험 (riskScore >= 0.6)
     * - 처리: AI 기반 상세 분석 (Layer 1/2/3 분석, MITRE ATT&CK 매핑)
     * - 대상: 새로운 패턴, 복잡한 행동, 이상 징후, 중간-높은 위험 활동
     * - 통합: 기존 REALTIME_MITIGATE, ASYNC_WITH_MONITORING, ASYNC_ESCALATE, INVESTIGATE, COLD_PATH_ANALYSIS
     */
    AI_ANALYSIS,
    
    /**
     * SOAR 통합
     * - 조건: Layer 3 전문가 분석 필요
     * - 처리: SOAR 플레이북 실행
     * - 대상: 복잡한 보안 인시던트
     * - 계층: Layer 3
     */
    SOAR_ORCHESTRATION,
    
    /**
     * 승인 대기
     * - 조건: 고위험 작업 또는 정책 변경
     * - 처리: 인간 승인 대기
     * - 대상: 크리티컬 작업
     * - 계층: Layer 3
     */
    AWAIT_APPROVAL;
    
    /**
     * 실시간 처리가 필요한지 확인
     */
    public boolean isRealtime() {
        return this == REALTIME_BLOCK;
    }
    
    /**
     * 차단 액션인지 확인
     */
    public boolean isBlocking() {
        return this == REALTIME_BLOCK;
    }
    
    /**
     * 에스컬레이션이 필요한지 확인
     */
    public boolean needsEscalation() {
        return this == SOAR_ORCHESTRATION;
    }
    
    /**
     * 모니터링이 필요한지 확인
     */
    public boolean needsMonitoring() {
        return this == AI_ANALYSIS;
    }
    
    /**
     * 인간 개입이 필요한지 확인
     */
    public boolean needsHumanIntervention() {
        return this == AWAIT_APPROVAL;
    }
    
    /**
     * 위험 점수 기반 기본 모드 결정
     *
     * @param riskScore 위험 점수 (0.0 - 1.0)
     * @param confidence 신뢰도 (0.0 - 1.0)
     * @return 권장 처리 모드
     */
    public static ProcessingMode determineMode(double riskScore, double confidence) {
        // 높은 위험 점수 + 높은 신뢰도 = 즉시 차단
        if (riskScore >= 0.8 && confidence >= 0.8) {
            return REALTIME_BLOCK;
        }

        // 중간-높은 위험 = AI 분석 (기존 REALTIME_MITIGATE 통합)
        if (riskScore >= 0.6) {
            return AI_ANALYSIS;
        }

        // 낮은 신뢰도 또는 중간 위험 = AI 분석
        if (confidence < 0.6 || riskScore >= 0.4) {
            return AI_ANALYSIS;
        }

        // 낮은 위험 = 통과
        return PASS_THROUGH;
    }
}