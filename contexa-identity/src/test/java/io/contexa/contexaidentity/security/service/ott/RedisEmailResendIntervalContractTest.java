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
package io.contexa.contexaidentity.security.service.ott;

import io.contexa.contexacore.testsupport.TestStores;
import io.contexa.contexaidentity.security.zerotrust.stepup.RedisStepUpOptionsStore;
import io.contexa.contexaidentity.security.zerotrust.stepup.StepUpOptionsStore;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.List;

/** Runs only against a Redis named for it: it never falls back to the Redis of the machine. */
class RedisEmailResendIntervalContractTest extends AbstractEmailResendIntervalContractTest {

    private static LettuceConnectionFactory connections;
    private static StringRedisTemplate redis;

    @BeforeAll
    static void connect() {
        TestStores.Redis server = TestStores.redis();
        connections = new LettuceConnectionFactory(new RedisStandaloneConfiguration(server.host(), server.port()));
        connections.afterPropertiesSet();
        redis = new StringRedisTemplate(connections);
    }

    @AfterAll
    static void disconnect() {
        if (connections != null) {
            connections.destroy();
        }
    }

    @Override
    protected StepUpOptionsStore store() {
        return new RedisStepUpOptionsStore(redis);
    }

    @RepeatedTest(25)
    @DisplayName("two nodes share the interval: requests at once on both mail once")
    void twoNodesShareTheInterval() throws Exception {
        assertOneMailOutOf(askAtOnce(List.of(service(120, true), service(120, true))));
    }
}
