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
package io.contexa.contexacore.testsupport;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;
import org.opentest4j.TestAbortedException;

class TestStoresTest {

    private final Map<String, String> environment = new HashMap<>();

    @Test
    @DisplayName("without a port the Redis test is skipped, and the reason names the variables")
    void withoutAPortTheRedisTestIsSkipped() {
        environment.put(TestStores.REDIS_HOST, "127.0.0.1");

        assertThatThrownBy(() -> TestStores.redis(environment::get))
                .isInstanceOf(TestAbortedException.class)
                .hasMessageContaining(TestStores.REDIS_PORT)
                .hasMessageContaining(TestStores.REDIS_HOST);
        assertThatThrownBy(() -> TestStores.disposableRedis(environment::get)).isInstanceOf(TestAbortedException.class);
        assertThat(TestStores.findRedis(environment::get)).isEmpty();
    }

    @Test
    @DisplayName("a blank port counts as none")
    void aBlankPortCountsAsNone() {
        environment.put(TestStores.REDIS_PORT, "  ");

        assertThatThrownBy(() -> TestStores.redis(environment::get)).isInstanceOf(TestAbortedException.class);
    }

    @Test
    @DisplayName("the variables name the Redis; without a host it is the loopback address")
    void theVariablesNameTheRedis() {
        environment.put(TestStores.REDIS_PORT, "57013");

        assertThat(TestStores.redis(environment::get)).isEqualTo(new TestStores.Redis("127.0.0.1", 57013));

        environment.put(TestStores.REDIS_HOST, "redis.test");
        TestStores.Redis redis = TestStores.disposableRedis(environment::get);
        assertThat(redis).isEqualTo(new TestStores.Redis("redis.test", 57013));
        assertThat(redis.uri()).isEqualTo("redis://redis.test:57013");
        assertThat(TestStores.findRedis(environment::get)).contains(redis);
    }

    @Test
    @DisplayName("a test that empties its Redis fails on 6379, the usual port of a developer's own Redis, even when set")
    void aTestThatEmptiesItsRedisFailsOnTheUsualPortOfADeveloperRedis() {
        environment.put(TestStores.REDIS_HOST, "127.0.0.1");
        environment.put(TestStores.REDIS_PORT, "6379");

        assertThatThrownBy(() -> TestStores.disposableRedis(environment::get))
                .isInstanceOf(AssertionFailedError.class)
                .hasMessageContaining("6379")
                .hasMessageContaining("FLUSHDB");
        assertThat(TestStores.redis(environment::get)).as("a test that only writes keys of its own may use it")
                .isEqualTo(new TestStores.Redis("127.0.0.1", 6379));
    }

    @Test
    @DisplayName("a port that is not a number fails instead of being skipped")
    void aPortThatIsNotANumberFails() {
        environment.put(TestStores.REDIS_PORT, "redis");

        assertThatThrownBy(() -> TestStores.redis(environment::get))
                .isInstanceOf(AssertionFailedError.class)
                .hasMessageContaining(TestStores.REDIS_PORT);
    }

    @Test
    @DisplayName("without a URL the database test is skipped, and the reason names the variables")
    void withoutAUrlTheDatabaseTestIsSkipped() {
        environment.put(TestStores.DB_USERNAME, "contexa_test");
        environment.put(TestStores.DB_PASSWORD, "secret");

        assertThatThrownBy(() -> TestStores.database(environment::get))
                .isInstanceOf(TestAbortedException.class)
                .hasMessageContaining(TestStores.DB_URL)
                .hasMessageNotContaining("secret");
    }

    @Test
    @DisplayName("the variables name the database; a name or password left out stays out")
    void theVariablesNameTheDatabase() {
        environment.put(TestStores.DB_URL, " jdbc:postgresql://127.0.0.1:55440/contexa_test ");

        assertThat(TestStores.database(environment::get))
                .isEqualTo(new TestStores.Database("jdbc:postgresql://127.0.0.1:55440/contexa_test", null, null));

        environment.put(TestStores.DB_USERNAME, "contexa_test");
        environment.put(TestStores.DB_PASSWORD, "secret");
        assertThat(TestStores.database(environment::get))
                .isEqualTo(new TestStores.Database("jdbc:postgresql://127.0.0.1:55440/contexa_test", "contexa_test", "secret"));
    }
}
