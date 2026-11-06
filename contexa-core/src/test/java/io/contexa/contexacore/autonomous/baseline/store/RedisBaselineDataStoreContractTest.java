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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexacommon.store.ApplicationNamespace;
import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import io.contexa.contexacore.testsupport.TestStores;
import java.time.Duration;
import java.util.Set;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;

class RedisBaselineDataStoreContractTest extends AbstractBaselineDataStoreContractTest {

    /** The indexes of the baselines still stored, scored by when each expires; and the sets the earlier versions kept. */
    private static final String USER_INDEX = "security:autonomous:baseline-index:user";
    private static final String ORG_INDEX = "security:autonomous:baseline-index:org";
    private static final String EARLIER_USER_INDEX = "security:autonomous:baseline:user:index";
    private static final String EARLIER_ORG_INDEX = "security:autonomous:baseline:org:index";

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
     * QF-23: a user whose baseline expired is not counted, and the index does not list the user either.
     */
    @Test
    @DisplayName("countUserBaselines counts only the baselines still stored, and the index lists no one else")
    void count_leavesOutExpiredBaselines() throws InterruptedException {
        BaselineDataStore shortLived = createStoreWithTtl(Duration.ofMillis(300));
        shortLived.saveUserBaseline("u-gone", baseline("u-gone"));
        store.saveUserBaseline("u-live", baseline("u-live"));
        Thread.sleep(500);

        assertThat(store.countUserBaselines()).isEqualTo(1L);
        assertThat(indexed(USER_INDEX)).containsExactly("u-live");
    }

    /**
     * The index of the people with a baseline is kept as small as the baselines are: the next save drops those whose
     * baseline expired, with no one counting.
     */
    @Test
    @DisplayName("a save drops from the user index the people whose baseline expired, so the index does not outgrow the baselines")
    void userIndex_dropsExpiredPeopleAtTheNextSave() throws InterruptedException {
        BaselineDataStore shortLived = createStoreWithTtl(Duration.ofMillis(300));
        for (int person = 0; person < 40; person++) {
            shortLived.saveUserBaseline("p-" + person, baseline("p-" + person));
        }
        Thread.sleep(500);
        shortLived.saveUserBaseline("p-new", baseline("p-new"));

        assertThat(indexed(USER_INDEX)).containsExactly("p-new");
        assertThat(redisTemplate.hasKey(ApplicationNamespace.key(EARLIER_USER_INDEX)))
                .as("no set that is added to and never trimmed").isFalse();
    }

    @Test
    @DisplayName("a save drops from the organization index the organizations whose baseline expired")
    void orgIndex_dropsExpiredOrganizationsAtTheNextSave() throws InterruptedException {
        BaselineDataStore shortLived = createStoreWithTtl(Duration.ofMillis(300));
        for (int organization = 0; organization < 20; organization++) {
            shortLived.saveOrganizationBaseline("o-" + organization, baseline("o-" + organization));
        }
        Thread.sleep(500);
        shortLived.saveOrganizationBaseline("o-new", baseline("o-new"));

        assertThat(indexed(ORG_INDEX)).containsExactly("o-new");
        assertThat(redisTemplate.hasKey(ApplicationNamespace.key(EARLIER_ORG_INDEX))).isFalse();
    }

    @Test
    @DisplayName("listOrganizationBaselines leaves out the organizations whose baseline expired, and the index forgets them")
    void list_leavesOutExpiredOrganizations() throws InterruptedException {
        BaselineDataStore shortLived = createStoreWithTtl(Duration.ofMillis(300));
        shortLived.saveOrganizationBaseline("o-gone", baseline("o-gone"));
        store.saveOrganizationBaseline("o-live", baseline("o-live"));
        Thread.sleep(500);

        assertThat(store.listOrganizationBaselines()).hasSize(1);
        assertThat(indexed(ORG_INDEX)).containsExactly("o-live");
    }

    @Test
    @DisplayName("a person is in the index until the baseline expires: the score is the time it expires")
    void userIndex_isScoredByWhenTheBaselineExpires() {
        BaselineDataStore aMinute = createStoreWithTtl(Duration.ofSeconds(60));
        long before = System.currentTimeMillis();
        aMinute.saveUserBaseline("u-minute", baseline("u-minute"));
        long after = System.currentTimeMillis();

        Double expiresAt = redisTemplate.opsForZSet().score(ApplicationNamespace.key(USER_INDEX), "u-minute");
        assertThat(expiresAt).isNotNull().isBetween((double) before + 60_000, (double) after + 60_000);
    }

    @Test
    @DisplayName("deleting a user's baseline takes the user out of the index")
    void deleteUserBaseline_takesThePersonOutOfTheIndex() {
        store.saveUserBaseline("erin", baseline("erin"));
        store.saveUserBaseline("frank", baseline("frank"));
        assertThat(indexed(USER_INDEX)).containsExactlyInAnyOrder("erin", "frank");

        store.deleteUserBaseline("erin");

        assertThat(indexed(USER_INDEX)).containsExactly("frank");
        assertThat(store.countUserBaselines()).isEqualTo(1L);
    }

    @Test
    @DisplayName("a user named like the index of the earlier version is stored and found: no index key is a baseline's key")
    void aUserNamedLikeTheEarlierIndexIsStored() {
        Logger logger = (Logger) LoggerFactory.getLogger(RedisBaselineDataStore.class);
        ListAppender<ILoggingEvent> logged = new ListAppender<>();
        logged.start();
        logger.addAppender(logged);
        try {
            assertThat(store.saveUserBaselineChecked("user:index", baseline("user:index"))).isTrue();

            assertThat(store.getUserBaseline("user:index")).isNotNull();
            assertThat(store.countUserBaselines()).isEqualTo(1L);
            assertThat(createStore().countUserBaselines()).as("a process that starts after it").isEqualTo(1L);
            assertThat(logged.list).as("the baseline is not taken for an index to move, and nothing is warned of")
                    .noneMatch(event -> event.getLevel().isGreaterOrEqual(Level.WARN));
        } finally {
            logger.detachAppender(logged);
        }
    }

    /**
     * Servers of the earlier version kept the index as a set that nothing trimmed. The first server of this version that
     * counts or saves moves what is still stored into the index scored by expiry, and the set goes.
     */
    @Test
    @DisplayName("the user index of the earlier version is moved: stored baselines kept with the time they have left, the set gone")
    void earlierUserIndexIsMoved() {
        store.saveUserBaseline("u-live", baseline("u-live"));
        store.saveUserBaseline("u-short", baseline("u-short"));
        redisTemplate.expire(ApplicationNamespace.key("security:autonomous:baseline:u-short"), Duration.ofSeconds(120));
        // The state the earlier version left: a set with the live people and one whose baseline is gone, and no new index.
        redisTemplate.delete(ApplicationNamespace.key(USER_INDEX));
        redisTemplate.opsForSet().add(ApplicationNamespace.key(EARLIER_USER_INDEX), "u-live", "u-short", "u-gone");

        long before = System.currentTimeMillis();
        assertThat(createStore().countUserBaselines()).isEqualTo(2L);
        long after = System.currentTimeMillis();

        assertThat(redisTemplate.hasKey(ApplicationNamespace.key(EARLIER_USER_INDEX))).as("the earlier set is gone").isFalse();
        assertThat(indexed(USER_INDEX)).containsExactlyInAnyOrder("u-live", "u-short");
        assertThat(scoreOf(USER_INDEX, "u-short")).isBetween((double) before + 100_000, (double) after + 120_000);
        assertThat(scoreOf(USER_INDEX, "u-live")).isGreaterThan((double) before + Duration.ofDays(29).toMillis());
        assertThat(scoreOf(USER_INDEX, "u-live")).isLessThanOrEqualTo((double) after + Duration.ofDays(30).toMillis());
    }

    @Test
    @DisplayName("the organization index of the earlier version is moved the same way")
    void earlierOrganizationIndexIsMoved() {
        store.saveOrganizationBaseline("o-live", baseline("o-live"));
        redisTemplate.delete(ApplicationNamespace.key(ORG_INDEX));
        redisTemplate.opsForSet().add(ApplicationNamespace.key(EARLIER_ORG_INDEX), "o-live", "o-gone");

        assertThat(createStore().listOrganizationBaselines()).hasSize(1);

        assertThat(redisTemplate.hasKey(ApplicationNamespace.key(EARLIER_ORG_INDEX))).isFalse();
        assertThat(indexed(ORG_INDEX)).containsExactly("o-live");
    }

    @Test
    @DisplayName("another server that moves the earlier index after the first one finds nothing, and changes nothing")
    void movingTheEarlierIndexTwiceChangesNothing() {
        store.saveUserBaseline("u-live", baseline("u-live"));
        redisTemplate.opsForSet().add(ApplicationNamespace.key(EARLIER_USER_INDEX), "u-live");
        // A newer score, as a save by this version gives: the move must not put an older one over it.
        Double newer = scoreOf(USER_INDEX, "u-live") + 5_000;
        redisTemplate.opsForZSet().add(ApplicationNamespace.key(USER_INDEX), "u-live", newer);

        assertThat(createStore().countUserBaselines()).isEqualTo(1L);
        assertThat(createStore().countUserBaselines()).isEqualTo(1L);

        assertThat(scoreOf(USER_INDEX, "u-live")).isEqualTo(newer);
        assertThat(redisTemplate.hasKey(ApplicationNamespace.key(EARLIER_USER_INDEX))).isFalse();
    }

    private static BaselineVector baseline(String id) {
        return BaselineVector.builder().userId(id).updateCount(5L).build();
    }

    private static Set<Object> indexed(String index) {
        Set<Object> members = redisTemplate.opsForZSet().range(ApplicationNamespace.key(index), 0, -1);
        return members != null ? members : Set.of();
    }

    private static Double scoreOf(String index, String member) {
        return redisTemplate.opsForZSet().score(ApplicationNamespace.key(index), member);
    }
}
