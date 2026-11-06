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
package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.RedisSecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import io.contexa.contexacore.testsupport.TestStores;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.mockito.Mockito.mock;

class RedisZeroTrustSessionServiceContractTest extends AbstractZeroTrustSessionServiceContractTest {

    private static LettuceConnectionFactory connectionFactory;
    private static RedisTemplate<String, Object> redis;

    @BeforeAll
    static void connect() {
        TestStores.Redis server = TestStores.redis();
        connectionFactory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(server.host(), server.port()));
        connectionFactory.afterPropertiesSet();
        redis = RedisTestTemplates.newProductionAlignedRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void disconnect() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @AfterEach
    void removeWrittenKeys() {
        for (String id : ids) {
            Set<String> keys = redis.keys("*" + id + "*");
            if (keys != null && !keys.isEmpty()) {
                redis.delete(keys);
            }
        }
    }

    @Override
    protected AbstractZeroTrustSecurityService createService(SecurityZeroTrustProperties properties) {
        return new RedisZeroTrustSecurityService(redis, mock(ThreatScoreUtil.class), properties,
                new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock), clock);
    }

    @Override
    protected SecurityContextDataStore contextStore() {
        return new RedisSecurityContextDataStore(redis);
    }

    /** The clock moves on, and every key of this test's ids with a TTL loses as much of it, as Redis lets it expire. */
    @Override
    protected void elapse(Duration elapsed) {
        clock.advance(elapsed);
        Set<String> keys = new HashSet<>();
        for (String id : ids) {
            Set<String> keysOfId = redis.keys("*" + id + "*");
            if (keysOfId != null) {
                keys.addAll(keysOfId);
            }
        }
        for (String key : keys) {
            Long remainingMs = redis.getExpire(key, TimeUnit.MILLISECONDS);
            if (remainingMs == null || remainingMs < 0) {
                continue;
            }
            if (remainingMs <= elapsed.toMillis()) {
                redis.delete(key);
            } else {
                redis.expire(key, remainingMs - elapsed.toMillis(), TimeUnit.MILLISECONDS);
            }
        }
    }
}
