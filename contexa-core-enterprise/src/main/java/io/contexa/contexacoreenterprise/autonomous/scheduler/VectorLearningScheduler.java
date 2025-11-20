package io.contexa.contexacoreenterprise.autonomous.scheduler;

import io.contexa.contexacore.hcad.service.HCADVectorIntegrationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

@Slf4j
@ConditionalOnClass(name = "io.contexa.contexacore.repository.PolicyProposalRepository")
@Component
public class VectorLearningScheduler {

    private final HCADVectorIntegrationService hcadVectorService;
    private final RedisTemplate<String, Object> redisTemplate;

    private LocalDateTime lastColdToHotSyncRun = LocalDateTime.now();
    private LocalDateTime lastCacheCleanupRun = LocalDateTime.now();

    @Autowired
    public VectorLearningScheduler(@Autowired(required = false) HCADVectorIntegrationService hcadVectorService,
                                   @Autowired(required = false) RedisTemplate<String, Object> redisTemplate) {
        this.hcadVectorService = hcadVectorService;
        this.redisTemplate = redisTemplate;

        log.info("VectorLearningScheduler initialized");
        log.info("  - HCADVectorService: {}", hcadVectorService != null ? "Available" : "Not Available");
        log.info("  - RedisTemplate: {}", redisTemplate != null ? "Available" : "Not Available");
    }

    @Scheduled(fixedDelay = 900000)
    public void scheduledColdToHotPathSync() {
        if (hcadVectorService == null || redisTemplate == null) {
            log.debug("Cold→Hot path sync skipped - required services not available");
            return;
        }

        log.info("Starting scheduled Cold→Hot path synchronization...");
        lastColdToHotSyncRun = LocalDateTime.now();

        try {
            Set<String> feedbackKeys = redisTemplate.keys("layer3:feedback:*");

            if (feedbackKeys == null || feedbackKeys.isEmpty()) {
                log.debug("No Layer3 feedback found to sync");
                return;
            }

            int syncCount = 0;
            for (String key : feedbackKeys) {
                try {
                    Object feedbackObj = redisTemplate.opsForValue().get(key);
                    if (feedbackObj == null) continue;

                    java.util.Map<String, Object> feedback = (java.util.Map<String, Object>) feedbackObj;

                    String userId = (String) feedback.getOrDefault("userId", "unknown");
                    Double riskScore = (Double) feedback.get("riskScore");

                    if (riskScore != null && riskScore >= 8.0) {
                        CompletableFuture<Void> syncFuture = hcadVectorService.syncColdPathToHotPath(userId);
                        syncFuture.thenAccept(v -> log.debug("Cold→Hot sync completed for user: {}", userId))
                            .exceptionally(ex -> {
                                log.warn("Cold→Hot sync failed for user: {}", userId, ex);
                                return null;
                            });

                        syncCount++;
                    }

                } catch (Exception e) {
                    log.warn("Failed to process feedback key: {}", key, e);
                }
            }

            log.info("Cold→Hot path sync completed - Synced {} high-risk patterns", syncCount);

        } catch (Exception e) {
            log.error("Cold→Hot path sync failed", e);
        }
    }

    @Scheduled(cron = "0 0 3 * * *")
    public void scheduledEmbeddingCacheCleanup() {
        if (redisTemplate == null) {
            log.debug("Cache cleanup skipped - RedisTemplate not available");
            return;
        }

        log.info("Starting scheduled embedding cache cleanup...");
        lastCacheCleanupRun = LocalDateTime.now();

        try {
            long expiredCount = 0;
            long totalCount = 0;

            Set<String> cacheKeys = redisTemplate.keys("hcadEmbeddings::*");
            if (cacheKeys != null) {
                totalCount = cacheKeys.size();

                for (String key : cacheKeys) {
                    try {
                        Long ttl = redisTemplate.getExpire(key, java.util.concurrent.TimeUnit.SECONDS);

                        if (ttl != null && ttl < 0) {
                            redisTemplate.delete(key);
                            expiredCount++;
                        }
                        else if (ttl != null && ttl < 3600) {
                            redisTemplate.expire(key, java.time.Duration.ofHours(24));
                        }

                    } catch (Exception e) {
                        log.debug("Failed to process cache key: {}", key);
                    }
                }
            }

            Set<String> baselineKeys = redisTemplate.keys("hcad:baseline:*");
            if (baselineKeys != null) {
                totalCount += baselineKeys.size();

                for (String key : baselineKeys) {
                    try {
                        Long ttl = redisTemplate.getExpire(key, java.util.concurrent.TimeUnit.SECONDS);

                        if (ttl != null && ttl < 0) {
                            redisTemplate.delete(key);
                            expiredCount++;
                        }

                    } catch (Exception e) {
                        log.debug("Failed to process baseline key: {}", key);
                    }
                }
            }

            Set<String> oldFeedbackKeys = redisTemplate.keys("layer3:feedback:*");
            if (oldFeedbackKeys != null) {
                long cutoffTime = System.currentTimeMillis() - (7L * 24 * 60 * 60 * 1000);

                for (String key : oldFeedbackKeys) {
                    try {
                        Object feedbackObj = redisTemplate.opsForValue().get(key);
                        if (feedbackObj == null) continue;

                        java.util.Map<String, Object> feedback = (java.util.Map<String, Object>) feedbackObj;
                        Long timestamp = (Long) feedback.get("timestamp");

                        if (timestamp != null && timestamp < cutoffTime) {
                            redisTemplate.delete(key);
                            expiredCount++;
                        }

                    } catch (Exception e) {
                        log.debug("Failed to process feedback key: {}", key);
                    }
                }
            }

            log.info("Embedding cache cleanup completed - Total: {}, Cleaned: {}", totalCount, expiredCount);

        } catch (Exception e) {
            log.error("Embedding cache cleanup failed", e);
        }
    }

    public LocalDateTime getLastColdToHotSyncRun() {
        return lastColdToHotSyncRun;
    }

    public LocalDateTime getLastCacheCleanupRun() {
        return lastCacheCleanupRun;
    }
}