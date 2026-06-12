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

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import java.net.InetSocketAddress;
import java.net.Socket;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;

@EnabledIf("io.contexa.contexacore.autonomous.repository.RedisZeroTrustActionRepositorySaveActionWithPreviousTest#isLocalRedisAvailable")
class RedisZeroTrustActionRepositorySaveActionWithPreviousTest {

    private static final String REDIS_HOST =
            System.getProperty("contexa.test.redis.host",
                    System.getenv().getOrDefault("CONTEXA_TEST_REDIS_HOST", "localhost"));
    private static final int REDIS_PORT = Integer.parseInt(
            System.getProperty("contexa.test.redis.port",
                    System.getenv().getOrDefault("CONTEXA_TEST_REDIS_PORT", "6379")));

    private static LettuceConnectionFactory connectionFactory;
    private static RedisTemplate<String, Object> redisTemplate;
    private static StringRedisTemplate stringRedisTemplate;
    private ZeroTrustActionRedisRepository repository;

    static boolean isLocalRedisAvailable() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(REDIS_HOST, REDIS_PORT), 500);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    @BeforeAll
    static void startRedis() {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(REDIS_HOST, REDIS_PORT);
        connectionFactory = new LettuceConnectionFactory(config);
        connectionFactory.afterPropertiesSet();
        redisTemplate = RedisTestTemplates.newProductionAlignedRedisTemplate(connectionFactory);
        stringRedisTemplate = RedisTestTemplates.newStringRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void stopRedis() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @BeforeEach
    void flushRedis() {
        stringRedisTemplate.execute((RedisCallback<Void>) connection -> {
            connection.serverCommands().flushDb();
            return null;
        });
        repository = new ZeroTrustActionRedisRepository(redisTemplate, stringRedisTemplate);
    }

    @Test
    @DisplayName("First saveActionWithPrevious records previousAction as PENDING_ANALYSIS and action as the new value")
    void firstCall_recordsPendingAsPrevious() {
        repository.saveActionWithPrevious("user-first", ZeroTrustAction.ALLOW);

        String analysisKey = ZeroTrustRedisKeys.hcadAnalysis("user-first");
        Object previous = redisTemplate.opsForHash().get(analysisKey, "previousAction");
        Object current = redisTemplate.opsForHash().get(analysisKey, "action");

        assertThat(String.valueOf(previous)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS.name());
        assertThat(String.valueOf(current)).isEqualTo(ZeroTrustAction.ALLOW.name());
    }

    @Test
    @DisplayName("Second saveActionWithPrevious rotates the previous action atomically")
    void secondCall_rotatesPreviousAtomically() {
        repository.saveActionWithPrevious("user-rotate", ZeroTrustAction.ALLOW);
        repository.saveActionWithPrevious("user-rotate", ZeroTrustAction.CHALLENGE);

        String analysisKey = ZeroTrustRedisKeys.hcadAnalysis("user-rotate");
        Object previous = redisTemplate.opsForHash().get(analysisKey, "previousAction");
        Object current = redisTemplate.opsForHash().get(analysisKey, "action");

        assertThat(String.valueOf(previous)).isEqualTo(ZeroTrustAction.ALLOW.name());
        assertThat(String.valueOf(current)).isEqualTo(ZeroTrustAction.CHALLENGE.name());
    }
}
