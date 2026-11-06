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
package io.contexa.contexacore.autonomous.baseline.store;

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import io.contexa.contexacore.testsupport.TestStores;
import java.time.Duration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;

class RedisBaselineDataStoreContractTest extends AbstractBaselineDataStoreContractTest {

    private static LettuceConnectionFactory connectionFactory;
    private static RedisTemplate<String, Object> redisTemplate;

    @BeforeAll
    static void startRedis() {
        TestStores.Redis server = TestStores.disposableRedis();
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(server.host(), server.port());
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
    protected BaselineDataStore createStore() {
        return new RedisBaselineDataStore(redisTemplate);
    }

    /** BR-C11 (DD-52): the retention is a setting, so the expiry is tested with a short one as the memory store is. */
    @Override
    protected BaselineDataStore createStoreWithTtl(Duration ttl) {
        return new RedisBaselineDataStore(redisTemplate, ttl);
    }

    /**
     * QF-23: a user whose baseline hash expired is not counted; its index entry is removed when the users are counted,
     * as an organization's is when the organizations are listed.
     */
    @Test
    @DisplayName("countUserBaselines leaves out and forgets a user whose baseline expired")
    void count_leavesOutAndForgetsExpiredBaselines() {
        store.saveUserBaseline("u-live", BaselineVector.builder().userId("u-live").updateCount(5L).build());
        store.saveUserBaseline("u-gone", BaselineVector.builder().userId("u-gone").updateCount(5L).build());
        // The hash's time to live ran out; the index set has no time to live of its own.
        redisTemplate.delete("security:autonomous:baseline:u-gone");

        assertThat(store.countUserBaselines()).isEqualTo(1L);
        assertThat(redisTemplate.opsForSet().members("security:autonomous:baseline:user:index"))
                .containsExactly("u-live");
    }
}
