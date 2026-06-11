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
package io.contexa.contexacore.infra.redis;

import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RTopic;
import org.redisson.api.RedissonClient;

import java.util.UUID;

/**
 * Broadcasts policy reload signals across all application instances via Redisson RTopic.
 * When any instance modifies a policy, all instances invalidate their caches and rebuild
 * the authorization manager mappings. Uses an instance ID to skip self-sent messages.
 */
@Slf4j
public class PolicyReloadBroadcaster {

    private static final String TOPIC_NAME = "contexa:policy:reload-signal";
    private static final String MESSAGE_PREFIX = "POLICY_RELOAD:";

    private final RTopic topic;
    private final String instanceId = UUID.randomUUID().toString();

    public PolicyReloadBroadcaster(RedissonClient redissonClient, Runnable reloadCallback) {
        this.topic = redissonClient.getTopic(TOPIC_NAME);

        this.topic.addListener(String.class, (channel, message) -> {
            if (message != null && message.startsWith(MESSAGE_PREFIX)) {
                String senderId = message.substring(MESSAGE_PREFIX.length());
                if (instanceId.equals(senderId)) {
                    return;
                }
                try {
                    reloadCallback.run();
                } catch (Exception e) {
                    log.error("Failed to process policy reload signal from remote instance", e);
                }
            }
        });
    }

    /**
     * Broadcasts a policy reload signal to all other instances.
     * The local instance should have already reloaded before calling this.
     * Self-sent messages are ignored via instance ID comparison.
     */
    public void broadcastReload() {
        try {
            topic.publishAsync(MESSAGE_PREFIX + instanceId);
        } catch (Exception e) {
            log.error("Failed to publish policy reload signal", e);
        }
    }
}
