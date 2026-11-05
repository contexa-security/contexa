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

import io.contexa.contexacommon.enums.ZeroTrustAction;
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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** Keys of their own in a shared Redis: nothing here flushes it. */
@EnabledIf("io.contexa.contexacore.autonomous.repository.RedisZeroTrustActionRepositoryUserKeyContractTest#isLocalRedisAvailable")
class RedisZeroTrustActionRepositoryUserKeyContractTest extends AbstractZeroTrustActionRepositoryUserKeyContractTest {

    private static final String REDIS_HOST =
            System.getProperty("contexa.test.redis.host",
                    System.getenv().getOrDefault("CONTEXA_TEST_REDIS_HOST", "localhost"));
    private static final int REDIS_PORT = Integer.parseInt(
            System.getProperty("contexa.test.redis.port",
                    System.getenv().getOrDefault("CONTEXA_TEST_REDIS_PORT", "6379")));

    private static LettuceConnectionFactory connectionFactory;
    private static RedisTemplate<String, Object> redisTemplate;
    private static StringRedisTemplate stringRedisTemplate;

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
        redisTemplate = RedisTestTemplates.newProductionAlignedRedisTemplate(connectionFactory);
        stringRedisTemplate = RedisTestTemplates.newStringRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void disconnect() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @Override
    protected ZeroTrustActionRepository createRepository() {
        return new ZeroTrustActionRedisRepository(redisTemplate, stringRedisTemplate);
    }

    /** A BLOCK has no TTL: one stored under the name as typed by an earlier version must not lapse with the upgrade. */
    @Test
    @DisplayName("a BLOCK an earlier version stored under the name as typed stays in force, and its release lifts it")
    void aBlockOfAnEarlierVersionStays() {
        String typed = "Upgrade-" + UUID.randomUUID();
        String earlierKey = "security:blocked:users:" + typed;
        stringRedisTemplate.opsForValue().set(earlierKey, "true");
        try {
            assertThat(repository.getCurrentAction(typed, "context-1")).isEqualTo(ZeroTrustAction.BLOCK);

            repository.removeBlockedFlag(typed);

            assertThat(repository.getCurrentAction(typed, "context-1")).isNotEqualTo(ZeroTrustAction.BLOCK);
            assertThat(stringRedisTemplate.hasKey(earlierKey)).isFalse();
        } finally {
            stringRedisTemplate.delete(earlierKey);
        }
    }

    @Test
    @DisplayName("an administrator's override lifts such a BLOCK too")
    void anOverrideLiftsABlockOfAnEarlierVersion() {
        String typed = "Upgrade-" + UUID.randomUUID();
        String earlierKey = "security:blocked:users:" + typed;
        stringRedisTemplate.opsForValue().set(earlierKey, "true");
        try {
            repository.approveOverrideAtomically(typed, ZeroTrustAction.ALLOW);

            assertThat(repository.getCurrentAction(typed, "context-1")).isNotEqualTo(ZeroTrustAction.BLOCK);
        } finally {
            stringRedisTemplate.delete(earlierKey);
        }
    }
}
