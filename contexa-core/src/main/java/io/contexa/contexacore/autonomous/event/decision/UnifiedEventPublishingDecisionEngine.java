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
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * Unified Event Publishing Decision Engine
 *
 * 익명 사용자 + 인증 사용자 통합 이벤트 발행 결정 엔진
 *
 * 핵심 설계 원칙:
 * 1. Risk Score 기반 통합 평가
 * 2. 익명 사용자: (1.0 - HCAD) * 0.7 + ipThreat * 0.3
 * 3. 인증 사용자: (1.0 - HCAD) * 0.5 + (1.0 - trustScore) * 0.5
 * 4. Hot Path(BENIGN)도 10% 샘플링 → 피드백 루프 연결
 * 5. Event Storm 방지: 인증 사용자도 샘플링 (71% 부하 감소)
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UnifiedEventPublishingDecisionEngine {

    private final @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate;
    private final AdaptiveSamplingEngine samplingEngine;

    /**
     * Redis 키 패턴
     * IMPORTANT: ZeroTrustRedisKeys를 통한 중앙집중식 키 관리
     * - IP 위협 점수: ZeroTrustRedisKeys.anonymousIpThreat(ip)
     * - IP 요청 카운트: ZeroTrustRedisKeys.anonymousIpRequestCount(ip)
     * - Threat Score: ZeroTrustRedisKeys.threatScore(userId)
     */

    /**
     * DDoS 방어 임계값 (1분당 요청 수)
     */
    private static final int DDOS_THRESHOLD = 100;

    /**
     * 익명 사용자 이벤트 발행 결정 (v2.0 - 피드백 루프 완전 통합)
     *
     * Risk Score = anomalyScore * 0.7 + ipThreat * 0.3
     * (anomalyScore는 학습된 임계값을 반영한 피드백 조정 유사도 기반)
     *
     * @param request HTTP 요청
     * @param hcadSimilarity HCAD 유사도 (하위호환성 유지)
     * @param hcadIsAnomaly 학습된 임계값 기반 이상 탐지 판정
     * @param hcadAnomalyScore 이상 점수 (1.0 - similarity, 피드백 학습 반영)
     * @return 발행 결정 결과
     */
    public PublishingDecision decideAnonymous(HttpServletRequest request, Double hcadSimilarity,
                                              Boolean hcadIsAnomaly, Double hcadAnomalyScore) {
        try {
            String clientIp = extractClientIp(request);

            // 1. IP 위협 점수 조회 (Cold Path AI 학습 결과)
            double ipThreatScore = getIpThreatScore(clientIp);

            // ✅ 2. Risk Score 계산 (v2.0 - 피드백 루프 완전 통합)
            // anomalyScore 우선 사용 (학습된 임계값 반영), fallback to raw similarity
            double hcadRisk = hcadAnomalyScore != null ? hcadAnomalyScore :
                             (hcadSimilarity != null ? (1.0 - hcadSimilarity) : 1.0);
            double riskScore = hcadRisk * 0.7 + ipThreatScore * 0.3;

            // ✅ 3. EventTier 분류 (isAnomaly 플래그 반영)
            EventTier tier = EventTier.fromRiskScore(riskScore);

            // isAnomaly가 true면 최소 MEDIUM 등급 보장 (학습된 임계값 기반 이상 탐지)
            if (Boolean.TRUE.equals(hcadIsAnomaly) && tier.ordinal() < EventTier.MEDIUM.ordinal()) {
                tier = EventTier.MEDIUM;
                log.debug("[UnifiedDecisionEngine] Tier escalated to MEDIUM due to isAnomaly flag (learned threshold): IP={}", clientIp);
            }

            // 4. 요청 빈도 체크 (DDoS 방어)
            long requestCount = incrementRequestCount(clientIp);
            if (requestCount > DDOS_THRESHOLD) {
                tier = tier.escalate();
                log.warn("[UnifiedDecisionEngine] Tier escalated due to high request frequency: count={}, ip={}",
                        requestCount, clientIp);
            }

            // 5. Adaptive Sampling
            boolean shouldPublish = samplingEngine.shouldSample(tier, clientIp);

            log.debug("[UnifiedDecisionEngine] Anonymous (v2.0) - isAnomaly: {}, anomalyScore: {:.3f}, HCAD: {:.3f}, IP Threat: {:.3f}, Risk: {:.3f}, Tier: {}, Publish: {}",
                    hcadIsAnomaly, hcadAnomalyScore != null ? hcadAnomalyScore : 0.0,
                    hcadSimilarity != null ? hcadSimilarity : 0.0, ipThreatScore, riskScore, tier, shouldPublish);

            return new PublishingDecision(shouldPublish, tier, riskScore, hcadSimilarity, null, ipThreatScore);

        } catch (Exception e) {
            // Fail-Safe: 에러 발생 시 CRITICAL로 간주하고 100% 발행
            log.error("[UnifiedDecisionEngine] Anonymous decision failed, treating as CRITICAL", e);
            return new PublishingDecision(true, EventTier.CRITICAL, 1.0, hcadSimilarity, null, 1.0);
        }
    }

    /**
     * 인증 사용자 이벤트 발행 결정 (v2.0 - 피드백 루프 완전 통합)
     *
     * Risk Score = anomalyScore * 0.5 + (1.0 - trustScore) * 0.5
     * (anomalyScore는 학습된 임계값을 반영한 피드백 조정 유사도 기반)
     *
     * @param request HTTP 요청
     * @param auth 인증 객체
     * @param userId 사용자 ID
     * @param hcadSimilarity HCAD 유사도 (하위호환성 유지)
     * @param hcadIsAnomaly 학습된 임계값 기반 이상 탐지 판정
     * @param hcadAnomalyScore 이상 점수 (1.0 - similarity, 피드백 학습 반영)
     * @return 발행 결정 결과
     */
    public PublishingDecision decideAuthenticated(HttpServletRequest request, Authentication auth,
                                                  String userId, Double hcadSimilarity,
                                                  Boolean hcadIsAnomaly, Double hcadAnomalyScore) {
        try {
            // 1. Trust Score 조회 (Redis: threat_score:{userId})
            double trustScore = getTrustScore(userId);

            // ✅ 2. Risk Score 계산 (v2.0 - 피드백 루프 완전 통합)
            // anomalyScore 우선 사용 (학습된 임계값 반영), fallback to raw similarity
            double hcadRisk = hcadAnomalyScore != null ? hcadAnomalyScore :
                             (hcadSimilarity != null ? (1.0 - hcadSimilarity) : 1.0);
            double trustRisk = 1.0 - trustScore;
            double riskScore = hcadRisk * 0.5 + trustRisk * 0.5;

            // ✅ 3. EventTier 분류 (isAnomaly 플래그 반영)
            EventTier tier = EventTier.fromRiskScore(riskScore);

            // isAnomaly가 true면 최소 MEDIUM 등급 보장 (학습된 임계값 기반 이상 탐지)
            if (Boolean.TRUE.equals(hcadIsAnomaly) && tier.ordinal() < EventTier.MEDIUM.ordinal()) {
                tier = EventTier.MEDIUM;
                log.debug("[UnifiedDecisionEngine] Tier escalated to MEDIUM due to isAnomaly flag (learned threshold): userId={}", userId);
            }

            // 4. Adaptive Sampling (userId 기반)
            boolean shouldPublish = samplingEngine.shouldSample(tier, userId);

            log.debug("[UnifiedDecisionEngine] Authenticated (v2.0) - User: {}, isAnomaly: {}, anomalyScore: {:.3f}, HCAD: {:.3f}, Trust: {:.3f}, Risk: {:.3f}, Tier: {}, Publish: {}",
                    userId, hcadIsAnomaly, hcadAnomalyScore != null ? hcadAnomalyScore : 0.0,
                    hcadSimilarity != null ? hcadSimilarity : 0.0, trustScore, riskScore, tier, shouldPublish);

            return new PublishingDecision(shouldPublish, tier, riskScore, hcadSimilarity, trustScore, null);

        } catch (Exception e) {
            // Fail-Safe: 에러 발생 시 CRITICAL로 간주하고 100% 발행
            log.error("[UnifiedDecisionEngine] Authenticated decision failed for user: {}, treating as CRITICAL", userId, e);
            return new PublishingDecision(true, EventTier.CRITICAL, 1.0, hcadSimilarity, null, null);
        }
    }

    /**
     * IP 위협 점수 조회 (Cold Path AI 학습 결과)
     *
     * @param clientIp 클라이언트 IP
     * @return IP 위협 점수 (0.0 ~ 1.0)
     */
    private double getIpThreatScore(String clientIp) {
        try {
            String key = ZeroTrustRedisKeys.anonymousIpThreat(clientIp);
            Double threat = (Double) redisTemplate.opsForValue().get(key);
            return threat != null ? Math.max(0.0, Math.min(1.0, threat)) : 0.0;
        } catch (Exception e) {
            log.warn("[UnifiedDecisionEngine] Failed to get IP threat score for IP: {}", clientIp, e);
            return 0.0;
        }
    }

    /**
     * Trust Score 조회 (Redis: threat_score:{userId})
     *
     * Trust Score = 1.0 - Threat Score
     *
     * @param userId 사용자 ID
     * @return Trust Score (0.0 ~ 1.0, 높을수록 신뢰)
     */
    private double getTrustScore(String userId) {
        try {
            String key = ZeroTrustRedisKeys.threatScore(userId);
            Object value = redisTemplate.opsForValue().get(key);

            if (value == null) {
                return 0.7;  // 기본 Trust Score (중립)
            }

            // Redis에서 Integer 또는 Double로 저장될 수 있으므로 Number로 처리
            double threatScore;
            if (value instanceof Number) {
                threatScore = ((Number) value).doubleValue();
            } else {
                log.warn("[UnifiedDecisionEngine] Unexpected threat score type: {} for user: {}", value.getClass(), userId);
                return 0.7;
            }

            double trust = 1.0 - Math.max(0.0, Math.min(1.0, threatScore));
            return trust;

        } catch (Exception e) {
            log.warn("[UnifiedDecisionEngine] Failed to get trust score for user: {}", userId, e);
            return 0.7;  // 기본 Trust Score
        }
    }

    /**
     * 요청 빈도 증가 및 카운트 반환 (DDoS 방어용)
     *
     * @param clientIp 클라이언트 IP
     * @return 현재 요청 카운트
     */
    private long incrementRequestCount(String clientIp) {
        try {
            String key = ZeroTrustRedisKeys.anonymousIpRequestCount(clientIp);
            Long count = redisTemplate.opsForValue().increment(key);

            if (count != null && count == 1) {
                redisTemplate.expire(key, 1, TimeUnit.MINUTES);
            }

            return count != null ? count : 0;
        } catch (Exception e) {
            log.warn("[UnifiedDecisionEngine] Failed to increment request count for IP: {}", clientIp, e);
            return 0;
        }
    }

    /**
     * 클라이언트 IP 추출 (프록시 헤더 고려)
     */
    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    /**
     * 발행 결정 결과
     */
    @Getter
    public static class PublishingDecision {
        private final boolean shouldPublish;
        private final EventTier tier;
        private final double riskScore;
        private final Double hcadSimilarity;
        private final Double trustScore;  // 인증 사용자 전용
        private final Double ipThreatScore;  // 익명 사용자 전용

        public PublishingDecision(boolean shouldPublish, EventTier tier, double riskScore,
                                  Double hcadSimilarity, Double trustScore, Double ipThreatScore) {
            this.shouldPublish = shouldPublish;
            this.tier = tier;
            this.riskScore = riskScore;
            this.hcadSimilarity = hcadSimilarity;
            this.trustScore = trustScore;
            this.ipThreatScore = ipThreatScore;
        }

        @Override
        public String toString() {
            if (trustScore != null) {
                // 인증 사용자
                return String.format("PublishingDecision{publish: %s, tier: %s, risk: %.3f, HCAD: %.3f, trust: %.3f}",
                        shouldPublish, tier, riskScore,
                        hcadSimilarity != null ? hcadSimilarity : 0.0, trustScore);
            } else {
                // 익명 사용자
                return String.format("PublishingDecision{publish: %s, tier: %s, risk: %.3f, HCAD: %.3f, IP threat: %.3f}",
                        shouldPublish, tier, riskScore,
                        hcadSimilarity != null ? hcadSimilarity : 0.0,
                        ipThreatScore != null ? ipThreatScore : 0.0);
            }
        }
    }
}
