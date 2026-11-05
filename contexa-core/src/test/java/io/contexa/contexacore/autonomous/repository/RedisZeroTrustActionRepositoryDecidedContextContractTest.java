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
import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
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
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** Keys of their own in a shared Redis: nothing here flushes it. */
@EnabledIf("io.contexa.contexacore.autonomous.repository.RedisZeroTrustActionRepositoryDecidedContextContractTest#isLocalRedisAvailable")
class RedisZeroTrustActionRepositoryDecidedContextContractTest
        extends AbstractZeroTrustActionRepositoryDecidedContextContractTest {

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

    @AfterEach
    void removeTheUser() {
        repository.removeAllAgentData(user);
        repository.removeAllUserData(user);
    }

    @Override
    protected ZeroTrustActionRepository createRepository() {
        return new ZeroTrustActionRedisRepository(redisTemplate, stringRedisTemplate);
    }

    /** As a key past its TTL, for the user and for an agent acting for the user. */
    @Override
    protected void theAnalysisLapses() {
        stringRedisTemplate.delete(List.of(ZeroTrustRedisKeys.autonomousActionAnalysis(user),
                ZeroTrustRedisKeys.autonomousActionAnalysis(LearningSubject.agentKey(user, "agent-1"))));
    }

    @Override
    protected void theLastVerifiedRecordsLapse() {
        stringRedisTemplate.delete(List.of(ZeroTrustRedisKeys.autonomousLastVerifiedAction(user),
                ZeroTrustRedisKeys.autonomousLastVerifiedActionContext(user)));
    }

    @Test
    @DisplayName("the record lasts 24 hours, as the last verified action does")
    void theRecordLasts24Hours() {
        repository.saveFinalAction(user, ZeroTrustAction.ALLOW, Map.of("observationId", "observation-1",
                "processingGeneration", "1", "contextBindingHash", "context-home"));

        Long remaining = stringRedisTemplate.getExpire(ZeroTrustRedisKeys.autonomousLastVerifiedActionContext(user),
                TimeUnit.HOURS);

        assertThat(remaining).isBetween(23L, 24L);
    }
}
