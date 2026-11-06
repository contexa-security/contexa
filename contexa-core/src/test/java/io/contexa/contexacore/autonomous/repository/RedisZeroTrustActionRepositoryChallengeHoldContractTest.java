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
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import io.contexa.contexacore.testsupport.TestStores;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** Keys of their own in a shared Redis: nothing here flushes it. */
class RedisZeroTrustActionRepositoryChallengeHoldContractTest
        extends AbstractZeroTrustActionRepositoryChallengeHoldContractTest {

    private static LettuceConnectionFactory connectionFactory;
    private static RedisTemplate<String, Object> redisTemplate;
    private static StringRedisTemplate stringRedisTemplate;

    @BeforeAll
    static void connect() {
        TestStores.Redis server = TestStores.redis();
        connectionFactory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(server.host(), server.port()));
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
        repository.removeAllUserData(user);
    }

    @Override
    protected ZeroTrustActionRepository createRepository() {
        return new ZeroTrustActionRedisRepository(redisTemplate, stringRedisTemplate);
    }

    @Test
    @DisplayName("it lapses when the CHALLENGE would have, and no later")
    void itLapsesWithTheChallenge() {
        challenge();
        String analysis = ZeroTrustRedisKeys.autonomousActionAnalysis(user);
        stringRedisTemplate.expire(analysis, Duration.ofSeconds(100));

        repository.holdChallengeForOtherSessions(user, "context-victim");

        Long remaining = stringRedisTemplate.getExpire(ZeroTrustRedisKeys.autonomousChallengeHold(user), TimeUnit.SECONDS);
        assertThat(remaining).isBetween(90L, 100L);
    }

    @Test
    @DisplayName("a second answer does not extend it")
    void aSecondAnswerDoesNotExtendIt() {
        challenge();
        repository.holdChallengeForOtherSessions(user, "context-victim");
        repository.saveActionWithPrevious(user, ZeroTrustAction.ALLOW, "context-victim");
        String hold = ZeroTrustRedisKeys.autonomousChallengeHold(user);
        stringRedisTemplate.expire(hold, Duration.ofSeconds(100));

        repository.holdChallengeForOtherSessions(user, "context-second-device");

        assertThat(stringRedisTemplate.getExpire(hold, TimeUnit.SECONDS)).isBetween(90L, 100L);
    }

    @Test
    @DisplayName("a held user is read for a request as for a context, without a request as without one")
    void aStoreThatFailsAnswersPending() {
        challenge();
        repository.holdChallengeForOtherSessions(user, "context-victim");
        repository.saveActionWithPrevious(user, ZeroTrustAction.ALLOW, "context-victim");

        assertThat(repository.getCurrentAction(user)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }
}
