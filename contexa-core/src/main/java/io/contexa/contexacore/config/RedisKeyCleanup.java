package io.contexa.contexacore.config;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Redis Key Cleanup Component
 * Cleans up conflicting key types on startup
 */
@Slf4j
@RequiredArgsConstructor
@ConditionalOnProperty(name = "redis.cleanup.enabled", havingValue = "true", matchIfMissing = true)
public class RedisKeyCleanup {

    private final RedisTemplate<String, Object> redisTemplate;

    @PostConstruct
    public void cleanupConflictingKeys() {
        log.info("Starting Redis key cleanup for type conflicts...");

        // Clean up known conflicting keys
        Set<String> keysToCheck = Set.of(
            "security:user:context:admin",
            "security:user:context:dev_lead",
            "security:user:context:dev_user",
            "security:user:context:finance_manager",
            "security:user:context:op_user"
        );

        for (String key : keysToCheck) {
            try {
                // Check if key exists and its type
                Boolean hasKey = redisTemplate.hasKey(key);
                if (Boolean.TRUE.equals(hasKey)) {
                    // Try to determine the type and delete if it's not a hash
                    try {
                        // Try to access as hash
                        redisTemplate.opsForHash().size(key);
                    } catch (Exception e) {
                        // If it's not a hash, delete it
                        log.warn("Deleting non-hash key: {} to prevent type conflict", key);
                        redisTemplate.delete(key);
                    }
                }
            } catch (Exception e) {
                log.warn("Error checking key {}: {}", key, e.getMessage());
            }
        }

        log.info("Redis key cleanup completed");
    }
}