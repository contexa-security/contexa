package io.contexa.contexacore.autonomous.utils;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;

@Slf4j
@RequiredArgsConstructor
public class ThreatScoreUtil {

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${threat.score.initial:0.3}")
    private double initialThreatScore;

    public double getThreatScore(String userId) {
        if (userId == null || userId.isEmpty()) {
            return initialThreatScore;
        }
        try {
            String threatScoreKey = ZeroTrustRedisKeys.threatScore(userId);
            Object threatScoreObj = redisTemplate.opsForValue().get(threatScoreKey);

            if (threatScoreObj != null) {
                return Double.parseDouble(threatScoreObj.toString());
            }
        } catch (Exception e) {
            log.error("[ThreatScoreOrchestrator] Failed to retrieve threat score: userId={}", userId, e);
        }

        return initialThreatScore;
    }
}
