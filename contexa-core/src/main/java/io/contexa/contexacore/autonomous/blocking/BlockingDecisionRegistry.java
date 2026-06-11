/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.blocking;

import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RTopic;
import org.redisson.api.RedissonClient;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

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
    private static final int MAX_PUBLISH_RETRIES = 1;

    private final ConcurrentHashMap<String, String> blockedUsers = new ConcurrentHashMap<>();
    private final RTopic topic;
    private final AtomicLong publishRequestedCount = new AtomicLong(0);
    private final AtomicLong publishConfirmedCount = new AtomicLong(0);
    private final AtomicLong publishFailedCount = new AtomicLong(0);

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
        publishSignalAsync(BLOCK_PREFIX + userId + ":" + effectiveAction, "BLOCK", userId, 0);
    }

    @Override
    public void registerUnblock(String userId) {
        if (userId == null || userId.isBlank()) {
            return;
        }
        blockedUsers.remove(userId);
        publishSignalAsync(UNBLOCK_PREFIX + userId, "UNBLOCK", userId, 0);
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

    private void publishSignalAsync(String message, String signalType, String userId, int attempt) {
        try {
            publishRequestedCount.incrementAndGet();
            topic.publishAsync(message).whenComplete((listeners, throwable) -> {
                if (throwable == null) {
                    publishConfirmedCount.incrementAndGet();
                    return;
                }

                if (attempt < MAX_PUBLISH_RETRIES) {
                    log.warn("[BlockingDecisionRegistry] Retry publish {} signal: userId={}, attempt={}",
                            signalType, userId, attempt + 1, throwable);
                    publishSignalAsync(message, signalType, userId, attempt + 1);
                    return;
                }

                publishFailedCount.incrementAndGet();
                log.error("[BlockingDecisionRegistry] Failed to publish {} signal after retries: userId={}",
                        signalType, userId, throwable);
            });
        } catch (Exception e) {
            if (attempt < MAX_PUBLISH_RETRIES) {
                log.warn("[BlockingDecisionRegistry] Retry scheduling {} signal: userId={}, attempt={}",
                        signalType, userId, attempt + 1, e);
                publishSignalAsync(message, signalType, userId, attempt + 1);
                return;
            }
            publishFailedCount.incrementAndGet();
            log.error("[BlockingDecisionRegistry] Failed to schedule {} signal publish: userId={}", signalType, userId, e);
        }
    }
}
