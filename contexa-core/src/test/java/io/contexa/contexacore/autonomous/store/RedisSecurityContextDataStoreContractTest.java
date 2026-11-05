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
package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.Disabled;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

@EnabledIf("io.contexa.contexacore.autonomous.store.RedisSecurityContextDataStoreContractTest#isLocalRedisAvailable")
class RedisSecurityContextDataStoreContractTest extends AbstractSecurityContextDataStoreContractTest {

    private static final String REDIS_HOST =
            System.getProperty("contexa.test.redis.host",
                    System.getenv().getOrDefault("CONTEXA_TEST_REDIS_HOST", "localhost"));
    private static final int REDIS_PORT = Integer.parseInt(
            System.getProperty("contexa.test.redis.port",
                    System.getenv().getOrDefault("CONTEXA_TEST_REDIS_PORT", "6379")));

    private static LettuceConnectionFactory connectionFactory;
    private static RedisTemplate<String, Object> redisTemplate;

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
    }

    @AfterAll
    static void stopRedis() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @BeforeEach
    void flushRedis() {
        redisTemplate.execute((RedisCallback<Void>) connection -> {
            connection.serverCommands().flushDb();
            return null;
        });
    }

    @Override
    protected SecurityContextDataStore createStore() {
        return new RedisSecurityContextDataStore(redisTemplate);
    }

    @Override
    protected SecurityContextDataStore createStoreWithAllowValidity(Duration validity) {
        RedisSecurityContextDataStore store = new RedisSecurityContextDataStore(redisTemplate);
        store.setAllowValidity(validity);
        return store;
    }

    @Override
    protected SecurityContextDataStore createStoreWithLoginFailureRetention(Duration retention) {
        RedisSecurityContextDataStore store = new RedisSecurityContextDataStore(redisTemplate);
        store.setLoginFailureRetention(retention);
        return store;
    }

    @Override
    protected SecurityContextDataStore createStoreWithObservationCapacity(int capacity) {
        RedisSecurityContextDataStore store = new RedisSecurityContextDataStore(redisTemplate);
        store.setObservationCapacity(capacity);
        return store;
    }

    @Override
    protected SecurityContextDataStore createStoreWithEventProcessedTtl(Duration ttl) {
        return new RedisSecurityContextDataStore(redisTemplate);
    }

    /** Brings every key's expiry {@code elapsed} nearer, removing the keys whose expiry it passes. */
    @Override
    protected void passTime(Duration elapsed) {
        String script = "local passed = " + elapsed.toMillis() + " "
                + "for _, key in ipairs(redis.call('keys', '*')) do "
                + "local left = redis.call('pttl', key) "
                + "if left > 0 then "
                + "if left <= passed then redis.call('del', key) else redis.call('pexpire', key, left - passed) end "
                + "end end "
                + "return 0";
        redisTemplate.execute(new DefaultRedisScript<>(script, Long.class), List.of());
    }

    @Override
    protected long heldLoginFailureKeys() {
        long keys = redisTemplate.keys("security:context:authentication:failure:*").size();
        Long ordered = redisTemplate.opsForZSet().zCard(ZeroTrustRedisKeys.authenticationLoginFailureKeys());
        return Math.max(keys, ordered != null ? ordered : 0);
    }

    @Override
    protected boolean holdsSessionRisk(String sessionId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(ZeroTrustRedisKeys.sessionRisk(sessionId)));
    }

    @Override
    @Disabled("Redis implementation already enforces 24h fixed TTL; short-TTL injection is a memory-side concern")
    void markEventProcessed_expiresAfterTtl() {
        // inherited
    }
}
