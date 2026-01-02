package io.contexa.contexacommon.hcad.domain;

import lombok.Builder;
import lombok.Getter;

/**
 * HCAD 분석 결과 (AI Native)
 *
 * HCADAnalysisService의 분석 결과를 담는 DTO
 * - HCADFilter: 모든 일반 요청 분석
 * - MySecurityConfig 로그인 핸들러: 로그인 시 인증된 userId로 재계산
 *
 * AI Native 원칙:
 * - LLM이 직접 riskScore, isAnomaly, threatType 등을 판단
 * - 규칙 기반 계산 제거 (similarityScore 제거)
 *
 * @author contexa
 * @since 3.0.0
 */
@Getter
@Builder
public class HCADAnalysisResult {

    /** 사용자 ID (인증 전: anonymous:{IP}, 인증 후: 실제 username) */
    private final String userId;

    /** 신뢰 점수 (LLM이 직접 반환, 0.0 ~ 1.0) */
    private final double trustScore;

    /** 위협 타입 (예: "SQL_INJECTION", "ACCOUNT_TAKEOVER") */
    private final String threatType;

    /** 위협 증거 (구체적인 위협 패턴 설명) */
    private final String threatEvidence;

    /** 이상 여부 (LLM이 직접 판단) */
    private final boolean isAnomaly;

    /** 위험 점수 (LLM이 직접 반환, 0.0 ~ 1.0) */
    private final double anomalyScore;

    /** LLM이 결정한 action (ALLOW/BLOCK/ESCALATE/MONITOR/INVESTIGATE) */
    private final String action;

    /** LLM이 결정한 confidence (0.0 ~ 1.0) */
    private final double confidence;

    // AI Native v4.2.0: threshold 필드 삭제 (Dead Code)
    // - LLM이 action을 직접 결정하므로 임계값 기반 판단 불필요
    // - HCADAnalysisService에서 항상 0.0으로 설정 (의미 없는 값)

    /** 처리 시간 (ms) */
    private final long processingTimeMs;

    /** HCAD 컨텍스트 (선택적, 디버깅용) */
    private final HCADContext context;

    /** BaselineVector (선택적, 디버깅용) */
    private final BaselineVector baseline;

    /**
     * 간단한 로그 출력용 toString
     */
    @Override
    public String toString() {
        return String.format(
            "HCADAnalysisResult{userId='%s', trust=%.3f, anomaly=%s, riskScore=%.3f, time=%dms}",
            userId, trustScore, isAnomaly, anomalyScore, processingTimeMs
        );
    }
}
