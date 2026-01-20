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


@Slf4j
@RequiredArgsConstructor
public class UnifiedEventPublishingDecisionEngine {

    private final @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate;
    private final AdaptiveSamplingEngine samplingEngine;

    
    public PublishingDecision decideAuthenticated(HttpServletRequest request, Authentication auth,
                                                  String userId, String hcadAction,
                                                  Boolean hcadIsAnomaly, Double hcadAnomalyScore) {
        try {
            
            double trustScore = getTrustScore(userId);

            
            double riskScore = hcadAnomalyScore != null ? hcadAnomalyScore : Double.NaN;

            
            
            
            EventTier tier = EventTier.fromAction(hcadAction, hcadIsAnomaly);

            
            boolean shouldPublish = samplingEngine.shouldSample(tier, userId);

            log.debug("[UnifiedDecisionEngine] Authenticated (v3.0 AI Native) - User: {}, action: {}, isAnomaly: {}, Risk: {:.3f}, Trust: {:.3f}, Tier: {}, Publish: {}",
                    userId, hcadAction, hcadIsAnomaly,
                    riskScore, trustScore, tier, shouldPublish);

            return new PublishingDecision(shouldPublish, tier, riskScore, trustScore, null);

        } catch (Exception e) {
            
            log.error("[UnifiedDecisionEngine] Authenticated decision failed for user: {}, treating as CRITICAL", userId, e);
            return new PublishingDecision(true, EventTier.CRITICAL, 1.0, null, null);
        }
    }

    
    private double getTrustScore(String userId) {
        try {
            String key = ZeroTrustRedisKeys.threatScore(userId);
            Object value = redisTemplate.opsForValue().get(key);

            if (value == null) {
                
                return Double.NaN;
            }

            
            double threatScore;
            if (value instanceof Number) {
                threatScore = ((Number) value).doubleValue();
            } else {
                log.warn("[UnifiedDecisionEngine] Unexpected threat score type: {} for user: {}", value.getClass(), userId);
                return Double.NaN;
            }

            
            double trust = 1.0 - threatScore;
            return trust;

        } catch (Exception e) {
            log.warn("[UnifiedDecisionEngine] Failed to get trust score for user: {}", userId, e);
            return Double.NaN;
        }
    }

    
    @Getter
    public static class PublishingDecision {
        private final boolean shouldPublish;
        private final EventTier tier;
        private final double riskScore;
        private final Double trustScore;  
        private final Double ipThreatScore;  

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
                
                return String.format("PublishingDecision{publish: %s, tier: %s, risk: %.3f, trust: %.3f}",
                        shouldPublish, tier, riskScore, trustScore);
            } else {
                
                return String.format("PublishingDecision{publish: %s, tier: %s, risk: %.3f, IP threat: %.3f}",
                        shouldPublish, tier, riskScore,
                        ipThreatScore != null ? ipThreatScore : 0.0);
            }
        }
    }
}
