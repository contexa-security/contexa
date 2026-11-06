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

import io.contexa.contexacommon.store.ApplicationNamespace;
import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RTopic;
import org.redisson.api.RedissonClient;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * In-memory registry backed by Redisson RTopic for real-time cross-instance
 * propagation of BLOCK/UNBLOCK signals. Allows O(1) local lookup so that
 * BlockableServletOutputStream can abort in-flight responses immediately.
 *
 * A signal keeps the moment this instance received it (see BlockSignals). Pub/sub does not deliver to a subscription
 * that dropped, so the probe also reads the decision in force from the shared decision store: a BLOCK this instance
 * did not hear still cuts its responses within one probe interval.
 */
@Slf4j
public class BlockingDecisionRegistry implements BlockingSignalBroadcaster {

    private static final String TOPIC_NAME = "contexa:security:block-signal";
    private static final String BLOCK_PREFIX = "BLOCK:";
    private static final String UNBLOCK_PREFIX = "UNBLOCK:";
    private static final int MAX_PUBLISH_RETRIES = 1;

    private final BlockSignals blockedUsers;
    private final RTopic topic;
    private final AtomicLong publishRequestedCount = new AtomicLong(0);
    private final AtomicLong publishConfirmedCount = new AtomicLong(0);
    private final AtomicLong publishFailedCount = new AtomicLong(0);

    public BlockingDecisionRegistry(RedissonClient redissonClient) {
        this(redissonClient, null, BlockSignals.DEFAULT_PROBE_INTERVAL);
    }

    public BlockingDecisionRegistry(RedissonClient redissonClient, BlockedStateProbe probe) {
        this(redissonClient, probe, BlockSignals.DEFAULT_PROBE_INTERVAL);
    }

    public BlockingDecisionRegistry(RedissonClient redissonClient, BlockedStateProbe probe,
                                    Duration probeInterval) {
        this(redissonClient, probe, probeInterval, System::nanoTime);
    }

    BlockingDecisionRegistry(RedissonClient redissonClient, BlockedStateProbe probe, Duration probeInterval,
                             LongSupplier clock) {
        this.blockedUsers = new BlockSignals(probe, probeInterval, clock);
        this.topic = redissonClient.getTopic(ApplicationNamespace.key(TOPIC_NAME));
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
    public void registerBlockAndAwait(String userId) {
        if (userId == null || userId.isBlank()) {
            throw new IllegalArgumentException("userId is required");
        }
        blockedUsers.put(userId, "BLOCK");
        publishRequestedCount.incrementAndGet();
        try {
            topic.publish(BLOCK_PREFIX + userId + ":BLOCK");
            publishConfirmedCount.incrementAndGet();
        } catch (RuntimeException exception) {
            publishFailedCount.incrementAndGet();
            log.error("[BlockingDecisionRegistry] Required block signal publication failed: userId={}", userId, exception);
            throw exception;
        }
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
        return blockedUsers.contains(userId);
    }

    @Override
    public String getBlockAction(String userId) {
        if (userId == null || userId.isBlank()) {
            return null;
        }
        return blockedUsers.action(userId);
    }

    @Override
    public boolean shouldCut(String userId, long responseStartNanos) {
        if (userId == null || userId.isBlank()) {
            return false;
        }
        return blockedUsers.cuts(userId, responseStartNanos);
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
