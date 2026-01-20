package io.contexa.contexacore.autonomous.orchestrator;

import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;


@Slf4j
@RequiredArgsConstructor
public class ThreatScoreOrchestrator {

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
