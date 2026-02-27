package io.contexa.contexacore.autonomous.blocking;

import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RTopic;
import org.redisson.api.RedissonClient;

import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory registry backed by Redisson RTopic for real-time cross-instance
 * propagation of BLOCK/UNBLOCK signals. Allows O(1) local lookup so that
 * BlockableServletOutputStream can abort in-flight responses immediately.
 */
@Slf4j
public class BlockingDecisionRegistry {

    private static final String TOPIC_NAME = "contexa:security:block-signal";
    private static final String BLOCK_PREFIX = "BLOCK:";
    private static final String UNBLOCK_PREFIX = "UNBLOCK:";

    private final ConcurrentHashMap<String, Boolean> blockedUsers = new ConcurrentHashMap<>();
    private final RTopic topic;

    public BlockingDecisionRegistry(RedissonClient redissonClient) {
        this.topic = redissonClient.getTopic(TOPIC_NAME);
        this.topic.addListener(String.class, (channel, message) -> {
            try {
                if (message.startsWith(BLOCK_PREFIX)) {
                    String userId = message.substring(BLOCK_PREFIX.length());
                    blockedUsers.put(userId, Boolean.TRUE);
                } else if (message.startsWith(UNBLOCK_PREFIX)) {
                    String userId = message.substring(UNBLOCK_PREFIX.length());
                    blockedUsers.remove(userId);
                }
            } catch (Exception e) {
                log.error("[BlockingDecisionRegistry] Failed to process RTopic message: {}", message, e);
            }
        });
    }

    /**
     * Register a BLOCK decision for the given user.
     * Updates local cache and publishes to all instances via RTopic.
     */
    public void registerBlock(String userId) {
        if (userId == null || userId.isBlank()) {
            return;
        }
        blockedUsers.put(userId, Boolean.TRUE);
        try {
            topic.publishAsync(BLOCK_PREFIX + userId);
        } catch (Exception e) {
            log.error("[BlockingDecisionRegistry] Failed to publish BLOCK signal: userId={}", userId, e);
        }
    }

    /**
     * Register an UNBLOCK decision for the given user.
     * Removes from local cache and publishes to all instances via RTopic.
     */
    public void registerUnblock(String userId) {
        if (userId == null || userId.isBlank()) {
            return;
        }
        blockedUsers.remove(userId);
        try {
            topic.publishAsync(UNBLOCK_PREFIX + userId);
        } catch (Exception e) {
            log.error("[BlockingDecisionRegistry] Failed to publish UNBLOCK signal: userId={}", userId, e);
        }
    }

    /**
     * O(1) local lookup to check if a user is currently blocked.
     */
    public boolean isBlocked(String userId) {
        if (userId == null || userId.isBlank()) {
            return false;
        }
        return blockedUsers.containsKey(userId);
    }
}
