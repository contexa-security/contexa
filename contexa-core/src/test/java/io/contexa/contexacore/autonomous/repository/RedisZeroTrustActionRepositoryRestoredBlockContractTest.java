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

import io.contexa.contexacommon.store.ApplicationNamespace;
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
class RedisZeroTrustActionRepositoryRestoredBlockContractTest extends AbstractZeroTrustActionRepositoryRestoredBlockContractTest {

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
    void removeWhatWasWritten() {
        repository.removeBlockedFlag(user);
        repository.removeBlockedFlag(user.toUpperCase());
        repository.removeBlockedFlag("console::" + user);
    }

    @Override
    protected ZeroTrustActionRepository createRepository() {
        return new ZeroTrustActionRedisRepository(redisTemplate, stringRedisTemplate);
    }

    @Test
    @DisplayName("a BLOCK that is there keeps its value and its time: the write is only for an absent key")
    void aBlockThatIsThereKeepsItsTime() {
        String key = ZeroTrustRedisKeys.userBlocked(user);
        stringRedisTemplate.opsForValue().set(key, "true", Duration.ofMinutes(10));

        assertThat(repository.restoreBlockedFlag(user)).isFalse();

        assertThat(stringRedisTemplate.opsForValue().get(key)).isEqualTo("true");
        assertThat(stringRedisTemplate.getExpire(key, TimeUnit.SECONDS)).isBetween(1L, 600L);
    }

    @Test
    @DisplayName("a restored BLOCK is the key a BLOCK always was: no expiry, under the application's prefix when it has a name")
    void aRestoredBlockHasNoExpiry() {
        repository.restoreBlockedFlag(user);

        String key = ZeroTrustRedisKeys.userBlocked(user);
        assertThat(stringRedisTemplate.opsForValue().get(key)).isEqualTo("true");
        assertThat(stringRedisTemplate.getExpire(key, TimeUnit.SECONDS)).isEqualTo(-1L);
        assertThat(key).isEqualTo(ApplicationNamespace.key("security:blocked:users:" + user));
    }
}
