package io.contexa.contexacore.autonomous.event.sampling;

import io.contexa.contexacore.autonomous.event.decision.EventTier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Random;


@Slf4j
@RequiredArgsConstructor
public class AdaptiveSamplingEngine {

    private final @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate;

    
    private static final String KEY_SYSTEM_LOAD = "system:load:current";
    private static final String KEY_ATTACK_MODE = "system:attack:mode";

    
    private static final String ATTACK_MODE_NORMAL = "NORMAL";
    private static final String ATTACK_MODE_SUSPECTED = "SUSPECTED";
    private static final String ATTACK_MODE_CONFIRMED = "CONFIRMED";

    
    public boolean shouldSample(EventTier tier, String identifier) {
        
        if (tier.requiresImmediatePublishing()) {
            return true;
        }

        
        double samplingRate = calculateAdaptiveSamplingRate(tier);

        
        boolean shouldSample = identifierBasedSampling(identifier, samplingRate);

        log.debug("[AdaptiveSamplingEngine] Tier: {}, SamplingRate: {:.3f}, Decision: {}, Identifier: {}",
                tier, samplingRate, shouldSample, identifier);

        return shouldSample;
    }

    
    private double calculateAdaptiveSamplingRate(EventTier tier) {
        
        double baseRate = tier.getBaseSamplingRate();

        
        double systemLoadFactor = getSystemLoadFactor();

        
        double attackModeFactor = getAttackModeFactor();

        
        double adaptiveRate = baseRate * systemLoadFactor * attackModeFactor;

        
        return Math.max(0.0, Math.min(1.0, adaptiveRate));
    }

    
    private double getSystemLoadFactor() {
        try {
            Double systemLoad = (Double) redisTemplate.opsForValue().get(KEY_SYSTEM_LOAD);

            if (systemLoad == null) {
                return 1.0;  
            }

            
            if (systemLoad > 0.9) {
                return 0.5;  
            } else if (systemLoad > 0.75) {
                return 0.7;  
            } else if (systemLoad > 0.6) {
                return 0.9;  
            } else {
                return 1.0;  
            }

        } catch (Exception e) {
            log.warn("[AdaptiveSamplingEngine] Failed to get system load", e);
            return 1.0;
        }
    }

    
    private double getAttackModeFactor() {
        try {
            String attackMode = (String) redisTemplate.opsForValue().get(KEY_ATTACK_MODE);

            if (attackMode == null) {
                attackMode = ATTACK_MODE_NORMAL;
            }

            return switch (attackMode) {
                case ATTACK_MODE_CONFIRMED -> 3.0;  
                case ATTACK_MODE_SUSPECTED -> 2.0;  
                default -> 1.0;  
            };

        } catch (Exception e) {
            log.warn("[AdaptiveSamplingEngine] Failed to get attack mode", e);
            return 1.0;
        }
    }

    
    private boolean identifierBasedSampling(String identifier, double samplingRate) {
        if (identifier == null) {
            
            return Math.random() < samplingRate;
        }

        
        long seed = identifier.hashCode();
        Random random = new Random(seed);

        return random.nextDouble() < samplingRate;
    }
}
