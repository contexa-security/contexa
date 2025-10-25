package io.contexa.contexacore.hcad.domain;

import lombok.Builder;
import lombok.Getter;

/**
 * HCAD 분석 결과
 *
 * HCADAnalysisService의 분석 결과를 담는 DTO
 * - HCADFilter: 모든 일반 요청 분석
 * - MySecurityConfig 로그인 핸들러: 로그인 시 인증된 userId로 재계산
 *
 * 설계 목적:
 * 1. Single Source of Truth: 유사도 계산 로직의 중앙 집중화
 * 2. DRY 원칙: 코드 중복 제거
 * 3. Separation of Concerns: 필터와 비즈니스 로직 분리
 *
 * @author contexa
 * @since 3.0.0
 */
@Getter
@Builder
public class HCADAnalysisResult {

    /** 사용자 ID (인증 전: anonymous:{IP}, 인증 후: 실제 username) */
    private final String userId;

    /** 유사도 점수 (0.0 ~ 1.0, 높을수록 정상 패턴과 유사) */
    private final double similarityScore;

    /** 신뢰 점수 (RAG 강화 결과, 0.0 ~ 1.0) */
    private final double trustScore;

    /** 위협 타입 (예: "SQL_INJECTION", "ACCOUNT_TAKEOVER") */
    private final String threatType;

    /** 위협 증거 (구체적인 위협 패턴 설명) */
    private final String threatEvidence;

    /** 이상 여부 (similarityScore < threshold) */
    private final boolean isAnomaly;

    /** 이상 점수 (1.0 - similarityScore) */
    private final double anomalyScore;

    /** 사용된 임계값 (동적으로 조정됨) */
    private final double threshold;

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
            "HCADAnalysisResult{userId='%s', similarity=%.3f, trust=%.3f, anomaly=%s, time=%dms}",
            userId, similarityScore, trustScore, isAnomaly, processingTimeMs
        );
    }
}
