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
package io.contexa.contexacommon.config.redis;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.autoconfigure.data.redis.RedisConnectionDetails;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.lang.Nullable;

/**
 * Q-25: Contexa keeps a final decision with scripts and transactions over several keys that carry no hash tag, and a
 * Redis Cluster refuses those across slots, so this release supports a single server and Sentinel. An application on a
 * cluster is not stopped for it: the start says so once, at ERROR, and goes on.
 */
@Slf4j
final class RedisClusterNotice implements SmartInitializingSingleton {

    private final RedisConnectionFactory connectionFactory;
    @Nullable
    private final RedisConnectionDetails connectionDetails;

    RedisClusterNotice(RedisConnectionFactory connectionFactory, @Nullable RedisConnectionDetails connectionDetails) {
        this.connectionFactory = connectionFactory;
        this.connectionDetails = connectionDetails;
    }

    @Override
    public void afterSingletonsInstantiated() {
        if (cluster()) {
            log.error("[Contexa] Redis Cluster is not supported in this release: decisions are written with scripts over "
                    + "several keys, which a cluster can refuse, and a decision that is not stored is not enforced. Use a "
                    + "single Redis server or Sentinel. The application goes on starting.");
        }
    }

    private boolean cluster() {
        return (connectionDetails != null && connectionDetails.getCluster() != null)
                || (connectionFactory instanceof LettuceConnectionFactory lettuce && lettuce.isClusterAware());
    }
}
