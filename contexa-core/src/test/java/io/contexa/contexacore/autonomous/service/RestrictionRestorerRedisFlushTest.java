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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import io.contexa.contexacore.testsupport.TestStores;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The restorer on a real Redis that is emptied while it runs: the blocks the record holds in force are written again, a
 * block that was released is not, and a user that was never blocked gets no flag. The Redis of this test is emptied, so it
 * is one of the test's own (never the usual port of a developer's Redis).
 */
class RestrictionRestorerRedisFlushTest {

    private static final String CONTEXT = "context-1";
    private static final Duration LOOK = Duration.ofMillis(80);

    private static LettuceConnectionFactory connectionFactory;
    private static RedisTemplate<String, Object> redis;
    private static StringRedisTemplate strings;

    private final String blocked = "blocked-" + UUID.randomUUID();
    private final String released = "released-" + UUID.randomUUID();
    private final String bystander = "bystander-" + UUID.randomUUID();
    private final Set<String> inForce = new CopyOnWriteArraySet<>();
    private final ZeroTrustActionRedisRepository actions = new ZeroTrustActionRedisRepository(redis, strings);
    private RestrictionRestorer restorer;

    @BeforeAll
    static void connect() {
        TestStores.Redis server = TestStores.disposableRedis();
        connectionFactory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(server.host(), server.port()));
        connectionFactory.afterPropertiesSet();
        redis = RedisTestTemplates.newProductionAlignedRedisTemplate(connectionFactory);
        strings = RedisTestTemplates.newStringRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void disconnect() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @AfterEach
    void stop() {
        if (restorer != null) {
            restorer.stop();
        }
        flushAll();
    }

    private static void flushAll() {
        try (RedisConnection connection = connectionFactory.getConnection()) {
            connection.serverCommands().flushAll();
        }
    }

    /** The record of an application's database: the blocks it holds in force, as an administrator's release changes them. */
    private IBlockedUserRecorder database() {
        return new IBlockedUserRecorder() {
            @Override
            public void recordBlock(String requestId, String userId, String username, String action, String reasoning,
                                    String sourceIp, String userAgent) {
            }

            @Override
            public void resolveBlock(String userId, String adminId, String resolvedAction, String reason) {
            }

            @Override
            public List<String> blocksInForce() {
                return List.copyOf(inForce);
            }
        };
    }

    private void start() {
        IBlockedUserRecorder recorder = database();
        restorer = new RestrictionRestorer(() -> actions, () -> recorder, () -> mock(SecurityContextDataStore.class),
                Duration.ofSeconds(10), List.of(Duration.ofMillis(50)), LOOK);
        restorer.start();
    }

    private ZeroTrustAction actionOf(String user) {
        return actions.getCurrentAction(user, CONTEXT);
    }

    @Test
    @DisplayName("a Redis emptied while the application runs gets its blocks back from the record, and nobody else is blocked")
    void aFlushedRedisGetsItsBlocksBack() {
        inForce.add(blocked);
        start();
        assertThat(actionOf(blocked)).isEqualTo(ZeroTrustAction.BLOCK);

        flushAll();
        assertThat(actionOf(blocked)).as("the Redis was emptied").isNotEqualTo(ZeroTrustAction.BLOCK);

        Awaitility.await().atMost(Duration.ofSeconds(10))
                .untilAsserted(() -> assertThat(actionOf(blocked)).isEqualTo(ZeroTrustAction.BLOCK));
        assertThat(actionOf(released)).isNotEqualTo(ZeroTrustAction.BLOCK);
        assertThat(actionOf(bystander)).isNotEqualTo(ZeroTrustAction.BLOCK);
        assertThat(strings.getExpire("security:blocked:users:" + blocked, TimeUnit.SECONDS)).as("a BLOCK has no expiry")
                .isEqualTo(-1L);
    }

    @Test
    @DisplayName("a block that was released before the flush is not written back, whatever the Redis lost")
    void aReleasedBlockIsNotWrittenBack() throws InterruptedException {
        inForce.addAll(List.of(blocked, released));
        start();
        assertThat(actionOf(released)).isEqualTo(ZeroTrustAction.BLOCK);

        // The release: the record first, the flag after.
        inForce.remove(released);
        actions.removeBlockedFlag(released);
        flushAll();

        Awaitility.await().atMost(Duration.ofSeconds(10))
                .untilAsserted(() -> assertThat(actionOf(blocked)).isEqualTo(ZeroTrustAction.BLOCK));
        Thread.sleep(500);
        assertThat(actionOf(released)).isNotEqualTo(ZeroTrustAction.BLOCK);
        assertThat(strings.hasKey("security:blocked:users:" + released)).isFalse();
    }

    @Test
    @DisplayName("a flag the Redis still has is not written again: its value stays and nothing is written for it")
    void aFlagTheRedisHasIsLeftAlone() throws InterruptedException {
        inForce.add(blocked);
        start();
        strings.opsForValue().set("security:blocked:users:" + blocked, "true");

        Thread.sleep(600);

        assertThat(strings.opsForValue().get("security:blocked:users:" + blocked)).isEqualTo("true");
        assertThat(strings.getExpire("security:blocked:users:" + blocked, TimeUnit.SECONDS)).isEqualTo(-1L);
    }
}
