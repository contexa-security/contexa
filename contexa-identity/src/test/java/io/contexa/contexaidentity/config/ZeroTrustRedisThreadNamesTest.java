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
package io.contexa.contexaidentity.config;

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.testsupport.TestStores;
import io.lettuce.core.resource.ClientResources;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * On a real Redis (CONTEXA_TEST_REDIS_PORT): the Lettuce client Contexa makes for an application without a Redis connection of its own
 * starts threads that say they are Contexa's. Lettuce names them "lettuce-nioEventLoop-4-1" by default, the names of an application's
 * own Lettuce client.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_REDIS_PORT", matches = ".+")
class ZeroTrustRedisThreadNamesTest {

    @Test
    void contexasOwnRedisClientStartsThreadsNamedForContexa() throws Exception {
        TestStores.Redis store = TestStores.redis();
        assertThat(store.port()).as("not the Redis a developer runs for themselves").isNotEqualTo(6379);
        RedisProperties redis = new RedisProperties();
        redis.setHost(store.host());
        redis.setPort(store.port());
        ZeroTrustRedisConfig config = new ZeroTrustRedisConfig(new SecurityZeroTrustProperties(), redis);

        Set<Thread> before = Collections.newSetFromMap(new IdentityHashMap<>());
        before.addAll(Thread.getAllStackTraces().keySet());
        ClientResources resources = config.clientResources();
        LettuceConnectionFactory connections =
                (LettuceConnectionFactory) config.redisConnectionFactory(config.lettuceClientConfiguration(resources));
        connections.afterPropertiesSet();
        try {
            try (RedisConnection connection = connections.getConnection()) {
                assertThat(connection.ping()).isEqualTo("PONG");
            }
            CompletableFuture<String> timer = new CompletableFuture<>();
            resources.timer().newTimeout(timeout -> timer.complete(Thread.currentThread().getName()), 1, TimeUnit.MILLISECONDS);
            String computation = resources.eventExecutorGroup().submit(() -> Thread.currentThread().getName()).get(10, TimeUnit.SECONDS);

            assertThat(timer.get(10, TimeUnit.SECONDS)).startsWith("contexa-lettuce-timer");
            assertThat(computation).startsWith("contexa-lettuce-eventExecutorLoop");
            List<String> started = Thread.getAllStackTraces().keySet().stream()
                    .filter(thread -> thread.isAlive() && !before.contains(thread))
                    .map(Thread::getName)
                    .toList();
            assertThat(started).as("the event loop that carried the ping").anyMatch(name -> name.matches("contexa-lettuce-\\w+EventLoop-.*"));
            assertThat(started).as("no thread under Lettuce's own names").noneMatch(name -> name.startsWith("lettuce-"));
        } finally {
            connections.destroy();
            resources.shutdown().get(10, TimeUnit.SECONDS);
        }
    }
}
