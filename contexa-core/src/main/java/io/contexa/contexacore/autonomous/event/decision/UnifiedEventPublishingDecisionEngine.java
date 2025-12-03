package io.contexa.contexacore.autonomous.event.decision;

import io.contexa.contexacore.autonomous.event.sampling.AdaptiveSamplingEngine;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;

/**
 * Unified Event Publishing Decision Engine (v3.0 - AI Native)
 *
 * AI Native 아키텍처 기반 이벤트 발행 결정 엔진
 *
 * 핵심 설계 원칙 (AI Native):
 * 1. LLM이 결정한 action 기반 EventTier 분류
 * 2. action 매핑: BLOCK→CRITICAL, ESCALATE→HIGH, MONITOR→MEDIUM, ALLOW→BENIGN/LOW
 * 3. riskScore는 감사 로그/대시보드 시각화용으로만 사용
 * 4. 규칙 기반 임계값 판단 제거 (LLM이 모든 판단 수행)
 * 5. Hot Path(BENIGN)도 10% 샘플링 -> 피드백 루프 연결
 * 6. Event Storm 방지: 인증 사용자도 샘플링 (71% 부하 감소)
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
@Slf4j
@RequiredArgsConstructor
public class UnifiedEventPublishingDecisionEngine {

    private final @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate;
    private final AdaptiveSamplingEngine samplingEngine;

    /**
     * 인증 사용자 이벤트 발행 결정 (v3.0 - AI Native Action 기반)
     *
     * AI Native 핵심 변경:
     * - LLM이 결정한 action을 직접 사용하여 EventTier 분류
     * - riskScore 기반 임계값 판단 제거
     * - riskScore는 감사 로그/대시보드용으로만 사용
     *
     * @param request HTTP 요청
     * @param auth 인증 객체
     * @param userId 사용자 ID
     * @param hcadAction LLM이 결정한 action (ALLOW/BLOCK/ESCALATE/MONITOR/INVESTIGATE)
     * @param hcadIsAnomaly LLM이 판단한 이상 여부
     * @param hcadAnomalyScore LLM이 결정한 위험도 점수 (감사 로그용)
     * @return 발행 결정 결과
     */
    public PublishingDecision decideAuthenticated(HttpServletRequest request, Authentication auth,
                                                  String userId, String hcadAction,
                                                  Boolean hcadIsAnomaly, Double hcadAnomalyScore) {
        try {
            // 1. Trust Score 조회 (Redis: threat_score:{userId})
            double trustScore = getTrustScore(userId);

            // AI Native: LLM이 반환한 riskScore 직접 사용 (감사 로그/대시보드용)
            double riskScore = hcadAnomalyScore != null ? hcadAnomalyScore : Double.NaN;

            // AI Native: action 기반 EventTier 분류 (핵심 변경)
            // LLM이 결정한 action을 직접 사용하여 Tier 분류
            // riskScore 기반 임계값 판단 제거
            EventTier tier = EventTier.fromAction(hcadAction, hcadIsAnomaly);

            // 4. Adaptive Sampling (userId 기반)
            boolean shouldPublish = samplingEngine.shouldSample(tier, userId);

            log.debug("[UnifiedDecisionEngine] Authenticated (v3.0 AI Native) - User: {}, action: {}, isAnomaly: {}, Risk: {:.3f}, Trust: {:.3f}, Tier: {}, Publish: {}",
                    userId, hcadAction, hcadIsAnomaly,
                    riskScore, trustScore, tier, shouldPublish);

            return new PublishingDecision(shouldPublish, tier, riskScore, trustScore, null);

        } catch (Exception e) {
            // Fail-Safe: 에러 발생 시 CRITICAL로 간주하고 100% 발행
            log.error("[UnifiedDecisionEngine] Authenticated decision failed for user: {}, treating as CRITICAL", userId, e);
            return new PublishingDecision(true, EventTier.CRITICAL, 1.0, null, null);
        }
    }

    /**
     * Trust Score 조회 (Redis: threat_score:{userId})
     *
     * AI Native: Trust Score = 1.0 - Threat Score (LLM이 결정한 값)
     * clamp 연산 제거, 기본값은 NaN (분석 미수행)
     *
     * @param userId 사용자 ID
     * @return Trust Score (LLM이 결정, 없으면 NaN)
     */
    private double getTrustScore(String userId) {
        try {
            String key = ZeroTrustRedisKeys.threatScore(userId);
            Object value = redisTemplate.opsForValue().get(key);

            if (value == null) {
                // AI Native: 분석 미수행 상태는 NaN (규칙 기반 기본값 제거)
                return Double.NaN;
            }

            // Redis에서 Integer 또는 Double로 저장될 수 있으므로 Number로 처리
            double threatScore;
            if (value instanceof Number) {
                threatScore = ((Number) value).doubleValue();
            } else {
                log.warn("[UnifiedDecisionEngine] Unexpected threat score type: {} for user: {}", value.getClass(), userId);
                return Double.NaN;
            }

            // AI Native: clamp 제거, LLM 응답 그대로 사용
            double trust = 1.0 - threatScore;
            return trust;

        } catch (Exception e) {
            log.warn("[UnifiedDecisionEngine] Failed to get trust score for user: {}", userId, e);
            return Double.NaN;
        }
    }

    /**
     * 발행 결정 결과
     */
    @Getter
    public static class PublishingDecision {
        private final boolean shouldPublish;
        private final EventTier tier;
        private final double riskScore;
        private final Double trustScore;  // 인증 사용자 전용
        private final Double ipThreatScore;  // 익명 사용자 전용

        public PublishingDecision(boolean shouldPublish, EventTier tier, double riskScore,
                                  Double trustScore, Double ipThreatScore) {
            this.shouldPublish = shouldPublish;
            this.tier = tier;
            this.riskScore = riskScore;
            this.trustScore = trustScore;
            this.ipThreatScore = ipThreatScore;
        }

        @Override
        public String toString() {
            if (trustScore != null) {
                // 인증 사용자
                return String.format("PublishingDecision{publish: %s, tier: %s, risk: %.3f, trust: %.3f}",
                        shouldPublish, tier, riskScore, trustScore);
            } else {
                // 익명 사용자
                return String.format("PublishingDecision{publish: %s, tier: %s, risk: %.3f, IP threat: %.3f}",
                        shouldPublish, tier, riskScore,
                        ipThreatScore != null ? ipThreatScore : 0.0);
            }
        }
    }
}
