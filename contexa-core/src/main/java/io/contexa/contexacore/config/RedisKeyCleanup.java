package io.contexa.contexacore.config;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Set;

@Slf4j
@RequiredArgsConstructor
@ConditionalOnProperty(name = "redis.cleanup.enabled", havingValue = "true", matchIfMissing = true)
public class RedisKeyCleanup {

    private final RedisTemplate<String, Object> redisTemplate;

    @PostConstruct
    public void cleanupConflictingKeys() {

        Set<String> keysToCheck = Set.of(
            "security:user:context:admin",
            "security:user:context:dev_lead",
            "security:user:context:dev_user",
            "security:user:context:finance_manager",
            "security:user:context:op_user"
        );

        for (String key : keysToCheck) {
            try {
                
                Boolean hasKey = redisTemplate.hasKey(key);
                if (Boolean.TRUE.equals(hasKey)) {
                    
                    try {
                        
                        redisTemplate.opsForHash().size(key);
                    } catch (Exception e) {
                        
                        log.warn("Deleting non-hash key: {} to prevent type conflict", key);
                        redisTemplate.delete(key);
                    }
                }
            } catch (Exception e) {
                log.warn("Error checking key {}: {}", key, e.getMessage());
            }
        }

            }
}