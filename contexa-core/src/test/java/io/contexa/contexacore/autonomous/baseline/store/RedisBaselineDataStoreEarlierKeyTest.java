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

import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacommon.store.ApplicationNamespace;
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

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Learning is not thrown away by giving an application a name: a baseline kept under the key the application had before
 * is copied under its new key the first time it is read, and from then on only the new key counts. Keys of their own in a
 * shared Redis: nothing here flushes it.
 */
class RedisBaselineDataStoreEarlierKeyTest {

    private static final String APPLICATION = "shop";
    private static final String EARLIER_PREFIX = "security:autonomous:baseline:";
    private static final String INDEX_PREFIX = "security:autonomous:baseline-index:";

    private static LettuceConnectionFactory connectionFactory;
    private static RedisTemplate<String, Object> redis;

    private final String user = "earlier-" + UUID.randomUUID();
    private final String organization = "earlier-org-" + UUID.randomUUID();
    private final RedisBaselineDataStore store = new RedisBaselineDataStore(redis, Duration.ofDays(30));

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
    void clean() {
        redis.delete(EARLIER_PREFIX + user);
        redis.delete(EARLIER_PREFIX + "org:" + organization);
        redis.delete(ApplicationNamespace.PREFIX + APPLICATION + ":" + EARLIER_PREFIX + user);
        redis.delete(ApplicationNamespace.PREFIX + APPLICATION + ":" + EARLIER_PREFIX + "org:" + organization);
        redis.opsForZSet().remove(INDEX_PREFIX + "user", user);
        redis.opsForZSet().remove(ApplicationNamespace.PREFIX + APPLICATION + ":" + INDEX_PREFIX + "user", user);
        redis.opsForZSet().remove(INDEX_PREFIX + "org", organization);
        redis.opsForZSet().remove(ApplicationNamespace.PREFIX + APPLICATION + ":" + INDEX_PREFIX + "org", organization);
    }

    @Test
    @DisplayName("a named application finds the baseline of the earlier key, copies it under its own, and leaves the earlier one")
    void copiesTheEarlierBaselineOnce() {
        savedBeforeTheApplicationHadAName(user, 5L);

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(APPLICATION)) {
            BaselineVector first = store.getUserBaseline(user);
            assertThat(first).isNotNull();
            assertThat(first.getUpdateCount()).isEqualTo(5L);
            assertThat(redis.hasKey(ApplicationNamespace.key(EARLIER_PREFIX + user))).as("its own key now holds it").isTrue();
            assertThat(redis.hasKey(EARLIER_PREFIX + user)).as("the earlier key stays").isTrue();
            assertThat(redis.opsForZSet().score(ApplicationNamespace.key(INDEX_PREFIX + "user"), user))
                    .as("and its own index lists the user").isNotNull();

            // From then on only its own key is read: a change to the earlier key is not seen.
            savedBeforeTheApplicationHadAName(user, 99L);
            assertThat(store.getUserBaseline(user).getUpdateCount()).isEqualTo(5L);
            assertThat(store.readUserBaseline(user).baseline().getUpdateCount()).isEqualTo(5L);
        }
    }

    @Test
    @DisplayName("an organization's baseline is carried over the same way")
    void copiesTheEarlierOrganizationBaseline() {
        withoutAName(() -> store.saveOrganizationBaseline(organization,
                BaselineVector.builder().userId(organization).updateCount(12L).avgTrustScore(0.85).build()));

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(APPLICATION)) {
            assertThat(store.getOrganizationBaseline(organization).getUpdateCount()).isEqualTo(12L);
            assertThat(redis.hasKey(ApplicationNamespace.key(EARLIER_PREFIX + "org:" + organization))).isTrue();
            assertThat(redis.opsForZSet().score(ApplicationNamespace.key(INDEX_PREFIX + "org"), organization))
                    .isNotNull();
        }
    }

    @Test
    @DisplayName("the copy lasts no longer than the earlier baseline had left, and a baseline that never expired gets the retention")
    void keepsTheTimeTheEarlierBaselineHadLeft() {
        savedBeforeTheApplicationHadAName(user, 5L);
        redis.expire(EARLIER_PREFIX + user, Duration.ofSeconds(120));

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(APPLICATION)) {
            assertThat(store.getUserBaseline(user)).isNotNull();
            Long left = redis.getExpire(ApplicationNamespace.key(EARLIER_PREFIX + user), TimeUnit.SECONDS);
            assertThat(left).isPositive().isLessThanOrEqualTo(120L);
        }

        savedBeforeTheApplicationHadAName(user, 6L);
        redis.persist(EARLIER_PREFIX + user);
        redis.delete(ApplicationNamespace.PREFIX + APPLICATION + ":" + EARLIER_PREFIX + user);
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(APPLICATION)) {
            assertThat(store.getUserBaseline(user)).isNotNull();
            Long left = redis.getExpire(ApplicationNamespace.key(EARLIER_PREFIX + user), TimeUnit.SECONDS);
            assertThat(left).isGreaterThan(Duration.ofDays(29).toSeconds());
        }
    }

    @Test
    @DisplayName("a baseline the application has under its own key is the one it reads, and the earlier one is not looked at")
    void itsOwnBaselineWins() {
        savedBeforeTheApplicationHadAName(user, 5L);
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(APPLICATION)) {
            store.saveUserBaseline(user, BaselineVector.builder().userId(user).updateCount(8L).build());
            assertThat(store.getUserBaseline(user).getUpdateCount()).isEqualTo(8L);
        }
    }

    @Test
    @DisplayName("an application without a name reads and writes only the key it always had")
    void anApplicationWithoutANameIsAsItWas() {
        withoutAName(() -> assertThat(store.getUserBaseline(user)).isNull());
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(APPLICATION)) {
            store.saveUserBaseline(user, BaselineVector.builder().userId(user).updateCount(3L).build());
        }

        withoutAName(() -> {
            assertThat(store.getUserBaseline(user)).as("not the named application's").isNull();
            assertThat(redis.hasKey(EARLIER_PREFIX + user)).isFalse();
        });
    }

    @Test
    @DisplayName("deleting a user's baseline takes the earlier copy too, so that it is not copied back")
    void aDeletionTakesTheEarlierCopy() {
        savedBeforeTheApplicationHadAName(user, 5L);
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(APPLICATION)) {
            assertThat(store.getUserBaseline(user)).isNotNull();

            store.deleteUserBaseline(user);

            assertThat(redis.hasKey(EARLIER_PREFIX + user)).isFalse();
            assertThat(store.getUserBaseline(user)).isNull();
        }
    }

    @Test
    @DisplayName("a user whose baseline was never read still has the earlier one removed with the account")
    void aDeletionTakesAnEarlierBaselineThatWasNeverCopied() {
        savedBeforeTheApplicationHadAName(user, 5L);
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(APPLICATION)) {
            store.deleteUserBaseline(user);

            assertThat(store.getUserBaseline(user)).isNull();
        }
    }

    private void savedBeforeTheApplicationHadAName(String id, long updateCount) {
        withoutAName(() -> store.saveUserBaseline(id,
                BaselineVector.builder().userId(id).updateCount(updateCount).avgTrustScore(0.9).build()));
    }

    private static void withoutAName(Runnable action) {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            action.run();
        }
    }
}
