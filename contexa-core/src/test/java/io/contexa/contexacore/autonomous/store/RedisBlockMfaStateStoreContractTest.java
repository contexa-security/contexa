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

import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import io.contexa.contexacore.testsupport.TestStores;
import java.time.Duration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

class RedisBlockMfaStateStoreContractTest extends AbstractBlockMfaStateStoreContractTest {

    private static LettuceConnectionFactory connectionFactory;
    private static StringRedisTemplate stringRedisTemplate;

    @BeforeAll
    static void startRedis() {
        TestStores.Redis server = TestStores.disposableRedis();
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(server.host(), server.port());
        connectionFactory = new LettuceConnectionFactory(config);
        connectionFactory.afterPropertiesSet();

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
    }

    @Override
    protected ZeroTrustActionRepository createActionRepository() {
        return new ZeroTrustActionRedisRepository(
                RedisTestTemplates.newProductionAlignedRedisTemplate(connectionFactory), stringRedisTemplate);
    }

    @Override
    protected BlockMfaStateStore createStore(ZeroTrustActionRepository actionRepository) {
        return new RedisBlockMfaStateStore(stringRedisTemplate, actionRepository);
    }

    @Override
    protected BlockMfaStateStore createStoreWithVerifiedTtl(ZeroTrustActionRepository actionRepository,
                                                            Duration verifiedTtl) {
        return new RedisBlockMfaStateStore(stringRedisTemplate, actionRepository, verifiedTtl);
    }
}
