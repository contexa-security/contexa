package io.contexa.contexacore.autonomous.blocking;

import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RTopic;
import org.redisson.api.RedissonClient;

import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory registry backed by Redisson RTopic for real-time cross-instance
 * propagation of BLOCK/UNBLOCK signals. Allows O(1) local lookup so that
 * BlockableServletOutputStream can abort in-flight responses immediately.
 *
 * Stores the action type (BLOCK, CHALLENGE, ESCALATE) along with the block signal
 * so the client can redirect to the appropriate page.
 */
@Slf4j
public class BlockingDecisionRegistry implements BlockingSignalBroadcaster {

    private static final String TOPIC_NAME = "contexa:security:block-signal";
    private static final String BLOCK_PREFIX = "BLOCK:";
    private static final String UNBLOCK_PREFIX = "UNBLOCK:";

    private final ConcurrentHashMap<String, String> blockedUsers = new ConcurrentHashMap<>();
    private final RTopic topic;

    public BlockingDecisionRegistry(RedissonClient redissonClient) {
        this.topic = redissonClient.getTopic(TOPIC_NAME);
        this.topic.addListener(String.class, (channel, message) -> {
            try {
                if (message.startsWith(BLOCK_PREFIX)) {
                    String payload = message.substring(BLOCK_PREFIX.length());
                    int sep = payload.lastIndexOf(':');
                    if (sep > 0) {
                        String userId = payload.substring(0, sep);
                        String action = payload.substring(sep + 1);
                        blockedUsers.put(userId, action);
                    } else {
                        blockedUsers.put(payload, "BLOCK");
                    }
                } else if (message.startsWith(UNBLOCK_PREFIX)) {
                    String userId = message.substring(UNBLOCK_PREFIX.length());
                    blockedUsers.remove(userId);
                }
            } catch (Exception e) {
                log.error("[BlockingDecisionRegistry] Failed to process RTopic message: {}", message, e);
            }
        });
    }

    @Override
    public void registerBlock(String userId, String action) {
        if (userId == null || userId.isBlank()) {
            return;
        }
        String effectiveAction = (action != null && !action.isBlank()) ? action : "BLOCK";
        blockedUsers.put(userId, effectiveAction);
        try {
            topic.publishAsync(BLOCK_PREFIX + userId + ":" + effectiveAction);
        } catch (Exception e) {
            log.error("[BlockingDecisionRegistry] Failed to publish BLOCK signal: userId={}", userId, e);
        }
    }

    @Override
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

    @Override
    public boolean isBlocked(String userId) {
        if (userId == null || userId.isBlank()) {
            return false;
        }
        return blockedUsers.containsKey(userId);
    }

    @Override
    public String getBlockAction(String userId) {
        if (userId == null || userId.isBlank()) {
            return null;
        }
        return blockedUsers.get(userId);
    }
}
