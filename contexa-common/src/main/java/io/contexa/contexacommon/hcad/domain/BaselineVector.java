package io.contexa.contexacommon.hcad.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.Instant;

/**
 * 사용자의 정상 행동 패턴 기준선 벡터 (AI Native v6.5)
 *
 * Redis에 저장되어 LLM 분석 컨텍스트로 제공됨
 *
 * AI Native 원칙:
 * - LLM 분석에 필요한 raw 데이터만 유지
 * - 플랫폼 판단 로직 제거
 * - 불필요한 필드 제거 (죽은 코드)
 *
 * LLM 프롬프트 전달 필드:
 * - normalIpRanges: 정상 IP 대역 (현재 IP와 비교)
 * - normalAccessHours: 정상 접근 시간대 (현재 시간과 비교)
 * - frequentPaths: 자주 접근하는 경로 (현재 경로와 비교)
 * - normalUserAgents: 정상 User-Agent (세션 하이재킹 탐지)
 * - learningMaturity: 기준선 학습 성숙도 (학습 정도 표시)
 * - updateCount: 업데이트 횟수 (학습 정도 표시)
 *
 * v6.5 변경: confidence -> learningMaturity
 * - LLM 분석 결과의 confidence와 혼동 방지
 * - 기준선 학습 정도를 나타내는 지표임을 명확히
 *
 * @author contexa
 * @since 3.1.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class BaselineVector implements Serializable {

    private static final long serialVersionUID = 1L;

    // ========== 핵심 식별자 ==========
    private String userId;

    // ========== LLM 프롬프트 전달 필드 (Zero Trust 필수 데이터) ==========
    private String[] normalIpRanges;      // 정상 IP 대역 - LLM이 현재 IP와 비교
    private Integer[] normalAccessHours;  // 정상 접근 시간대 (0-23) - LLM이 현재 시간과 비교
    private String[] frequentPaths;       // 자주 접근하는 경로 - LLM이 현재 경로와 비교
    private String[] normalUserAgents;    // 정상 User-Agent - LLM이 세션 하이재킹 탐지

    // ========== 학습 메타데이터 (LLM 컨텍스트) ==========
    @Builder.Default
    private Long updateCount = 0L;           // 업데이트 횟수 - LLM에 학습 정도 제공
    @Builder.Default
    private Double learningMaturity = 0.0;   // 기준선 학습 성숙도 (0.0 ~ 1.0) - v6.5: confidence에서 이름 변경
                                             // LLM 분석 결과의 confidence와 혼동 방지

    // ========== EMA 학습 내부 필드 ==========
    private Instant lastUpdated;          // 마지막 업데이트 시간
    private Long avgRequestCount;         // 평균 요청 수 (EMA 계산용)
    private Double avgTrustScore;         // 평균 신뢰 점수 (EMA 계산용)

    // AI Native v3.1: feedbackMetadata 제거 - 죽은 코드
    // - applyLayer3FeedbackToBaseline(), applyAllLayersFeedbackToBaseline() 외부 호출 없음
    // - saveBaseline()에서 Redis 저장 안 함
    // - 데이터 흐름 전체가 죽은 코드

    // AI Native v3.1: 다음 필드 삭제 - LLM 분석에 불필요, 죽은 코드
    // - vector (384차원 벡터) - 저장/사용 안 함
    // - meanRequestInterval, stdDevRequestInterval - 저장/사용 안 함
    // - anomalyScoreMean, anomalyScoreStdDev, recentAnomalyScores - 저장/사용 안 함
    // - lastVectorNorm - 저장/사용 안 함
    // - activityHistory, activityFrequencyMap - 저장/사용 안 함
    // - hourlyActivityRate, weeklyActivityPattern, monthlyActivityPattern - 저장/사용 안 함
    // - averageActivityRate, dailyPeakHours - 저장/사용 안 함
    // - averageSessionDuration, sessionIntervalMean, sessionIntervalStdDev - 저장/사용 안 함
    // - normalNetworkSegments, portAccessPattern, averageBandwidth, trustedProxyChains - 저장/사용 안 함
    // - feedbackMetadata - 저장/사용 안 함
    // - CircularActivityHistory 내부 클래스 - 사용 안 함
    // - NaN 검증 유틸리티 메서드 - 사용 안 함

}
