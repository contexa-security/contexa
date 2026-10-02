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
package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIf("io.contexa.contexacore.autonomous.repository.RedisZeroTrustActionRepositoryDecisionAuditPendingTest#isLocalRedisAvailable")
class RedisZeroTrustActionRepositoryDecisionAuditPendingTest {

    private static final String REDIS_HOST =
            System.getProperty("contexa.test.redis.host",
                    System.getenv().getOrDefault("CONTEXA_TEST_REDIS_HOST", "localhost"));
    private static final int REDIS_PORT = Integer.parseInt(
            System.getProperty("contexa.test.redis.port",
                    System.getenv().getOrDefault("CONTEXA_TEST_REDIS_PORT", "6379")));

    private static LettuceConnectionFactory connectionFactory;
    private static StringRedisTemplate stringRedisTemplate;
    private static ZeroTrustActionRedisRepository repository;

    static boolean isLocalRedisAvailable() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(REDIS_HOST, REDIS_PORT), 500);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    @BeforeAll
    static void connect() {
        connectionFactory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(REDIS_HOST, REDIS_PORT));
        connectionFactory.afterPropertiesSet();
        RedisTemplate<String, Object> redisTemplate = RedisTestTemplates.newProductionAlignedRedisTemplate(connectionFactory);
        stringRedisTemplate = RedisTestTemplates.newStringRedisTemplate(connectionFactory);
        repository = new ZeroTrustActionRedisRepository(redisTemplate, stringRedisTemplate);
    }

    @AfterAll
    static void disconnect() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @Test
    @DisplayName("decision audit pending marker is context scoped, bounded by its TTL and cleared explicitly")
    void markerIsContextScopedAndExpiring() {
        String userId = "audit-pending-" + UUID.randomUUID();

        repository.markDecisionAuditPending(userId, "context-a", Duration.ofSeconds(30));
        repository.markDecisionAuditPending(userId, null, Duration.ofSeconds(30));

        assertThat(repository.isDecisionAuditPending(userId, "context-a")).isTrue();
        assertThat(repository.isDecisionAuditPending(userId, "context-b")).isFalse();
        assertThat(repository.isDecisionAuditPending(userId, null)).isTrue();
        Long ttlMs = stringRedisTemplate.getExpire(
                ZeroTrustRedisKeys.autonomousDecisionAuditPending(userId), TimeUnit.MILLISECONDS);
        assertThat(ttlMs).isPositive().isLessThanOrEqualTo(30_000L);

        repository.clearDecisionAuditPending(userId, "context-a");

        assertThat(repository.isDecisionAuditPending(userId, "context-a")).isFalse();
        assertThat(repository.isDecisionAuditPending(userId, null)).isTrue();

        repository.removeAllUserData(userId);

        assertThat(repository.isDecisionAuditPending(userId, null)).isFalse();
    }

    @Test
    @DisplayName("expired decision audit pending entry no longer suspends analysis")
    void expiredMarkerEntryIsIgnored() {
        String userId = "audit-pending-" + UUID.randomUUID();
        stringRedisTemplate.opsForHash().put(
                ZeroTrustRedisKeys.autonomousDecisionAuditPending(userId),
                "context-a",
                Long.toString(System.currentTimeMillis() - 1L));

        assertThat(repository.isDecisionAuditPending(userId, "context-a")).isFalse();

        repository.removeAllUserData(userId);
    }
}
