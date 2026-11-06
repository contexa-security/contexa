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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.store.RedisSecurityContextDataStore;
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
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The blocks the database holds in force, on a real Redis: after the upgrade of an application to a name what was blocked
 * before stays blocked, and in an application with or without a name a block the store lost is in force again. What was
 * released does not come back, and another application sharing the Redis is not blocked by it. Keys of their own in a
 * shared Redis: nothing here flushes it.
 */
class NamespaceRestrictionRestorerRedisTest {

    private static final String CONTEXT = "context-1";
    private static final String EARLIER_QUARANTINE = "security:autonomous:learning:quarantine";

    private static LettuceConnectionFactory connectionFactory;
    private static RedisTemplate<String, Object> redis;
    private static StringRedisTemplate strings;

    private final String blocked = "blocked-" + UUID.randomUUID();
    private final String released = "released-" + UUID.randomUUID();
    private final String agent = "agent:upgrade-" + UUID.randomUUID();
    private final ZeroTrustActionRedisRepository actions = new ZeroTrustActionRedisRepository(redis, strings);
    private final RedisSecurityContextDataStore context = new RedisSecurityContextDataStore(redis);

    @BeforeAll
    static void connect() {
        TestStores.Redis server = TestStores.redis();
        connectionFactory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(server.host(), server.port()));
        connectionFactory.afterPropertiesSet();
        redis = RedisTestTemplates.newProductionAlignedRedisTemplate(connectionFactory);
        strings = RedisTestTemplates.newStringRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void disconnect() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @AfterEach
    void clean() {
        for (String application : new String[]{"", "shop", "clinic"}) {
            try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(application)) {
                actions.removeBlockedFlag(blocked);
                actions.removeBlockedFlag(released);
                context.setLearningQuarantined(agent, false);
                strings.delete(ApplicationNamespace.key(EARLIER_QUARANTINE + ":carried"));
            }
        }
    }

    /** The record of an application's database: the blocks it holds in force. */
    private static IBlockedUserRecorder database(String... inForce) {
        return new IBlockedUserRecorder() {
            @Override
            public void recordBlock(String requestId, String userId, String username, String action, String reasoning,
                                    String sourceIp, String userAgent) {
            }

            @Override
            public void resolveBlock(String userId, String adminId, String resolvedAction, String reason) {
            }

            @Override
            public List<String> blocksInForce() {
                return List.of(inForce);
            }
        };
    }

    private void start(String application, IBlockedUserRecorder recorder) {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(application)) {
            NamespaceRestrictionRestorer restorer = new NamespaceRestrictionRestorer(() -> actions, () -> recorder,
                    () -> context, Duration.ofSeconds(10), List.of(Duration.ofMillis(50)));
            restorer.start();
            restorer.stop();
        }
    }

    private ZeroTrustAction actionIn(String application, String user) {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(application)) {
            return actions.getCurrentAction(user, CONTEXT);
        }
    }

    @Test
    @DisplayName("a block the old keys held is in force again after the application is given a name, and a released one is not")
    void aBlockSurvivesTheUpgrade() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            actions.setBlockedFlag(blocked);
            actions.setBlockedFlag(released);
        }
        assertThat(actionIn("", blocked)).as("before the upgrade").isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(actionIn("shop", blocked)).as("under the new keys the block is not there").isNotEqualTo(ZeroTrustAction.BLOCK);

        start("shop", database(blocked));

        assertThat(actionIn("shop", blocked)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(actionIn("shop", released)).as("the database holds it resolved").isNotEqualTo(ZeroTrustAction.BLOCK);
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            String key = "ctxa:shop:security:blocked:users:" + blocked;
            assertThat(strings.opsForValue().get(key)).isEqualTo("true");
            assertThat(strings.getExpire(key, TimeUnit.SECONDS)).as("a BLOCK has no expiry").isEqualTo(-1L);
        }
        assertThat(strings.hasKey("security:blocked:users:" + blocked)).as("the old key is left as it was").isTrue();
    }

    @Test
    @DisplayName("another application sharing the Redis is not blocked by it: only the application's own database says what is restored")
    void anotherApplicationIsNotBlocked() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            actions.setBlockedFlag(blocked);
        }

        start("shop", database(blocked));
        start("clinic", database());

        assertThat(actionIn("shop", blocked)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(actionIn("clinic", blocked)).isNotEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("an application without a name finds a block its store lost in force again, and a released one is not written")
    void anUnnamedApplicationRestoresABlockTheStoreLost() {
        // A Redis that was emptied or replaced: the database holds the block and the store has no flag.
        assertThat(actionIn("", blocked)).as("before the start").isNotEqualTo(ZeroTrustAction.BLOCK);

        start("", database(blocked));

        assertThat(actionIn("", blocked)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(actionIn("", released)).as("the database holds it resolved").isNotEqualTo(ZeroTrustAction.BLOCK);
        assertThat(strings.opsForValue().get("security:blocked:users:" + blocked)).isEqualTo("true");
        assertThat(strings.getExpire("security:blocked:users:" + blocked, TimeUnit.SECONDS)).as("a BLOCK has no expiry")
                .isEqualTo(-1L);
        assertThat(strings.hasKey("security:blocked:users:" + released)).isFalse();
    }

    @Test
    @DisplayName("a flag the store still has is left as it is by an application without a name, and no quarantine is carried")
    void anUnnamedApplicationLeavesAnExistingFlagAsItIs() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            actions.setBlockedFlag(blocked);
        }
        redis.opsForSet().add(EARLIER_QUARANTINE, agent);
        try {
            start("", database(blocked));

            assertThat(actionIn("", blocked)).isEqualTo(ZeroTrustAction.BLOCK);
            assertThat(strings.getExpire("security:blocked:users:" + blocked, TimeUnit.SECONDS)).isEqualTo(-1L);
            assertThat(strings.hasKey(EARLIER_QUARANTINE + ":carried")).as("there is no earlier key to carry").isFalse();
        } finally {
            redis.opsForSet().remove(EARLIER_QUARANTINE, agent);
        }
    }

    @Test
    @DisplayName("an application without a name does not write a block another record no longer holds, on a second start")
    void anUnnamedApplicationDoesNotWriteAReleasedBlockOnASecondStart() {
        start("", database(blocked));
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            actions.removeBlockedFlag(blocked);
        }

        start("", database());

        assertThat(actionIn("", blocked)).isNotEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("a second start changes nothing: a block an administrator released since is not written again by a record that no longer holds it")
    void aSecondStartChangesNothing() {
        start("shop", database(blocked));
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            actions.removeBlockedFlag(blocked);
        }

        start("shop", database());

        assertThat(actionIn("shop", blocked)).isNotEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("the quarantine of the old key is carried with the blocks")
    void theQuarantineIsCarriedToo() {
        redis.opsForSet().add(EARLIER_QUARANTINE, agent);
        try {
            start("shop", database());

            try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
                assertThat(context.learningQuarantined(agent)).isTrue();
            }
            try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("clinic")) {
                assertThat(context.learningQuarantined(agent)).as("not before its own start").isFalse();
            }
        } finally {
            redis.opsForSet().remove(EARLIER_QUARANTINE, agent);
        }
    }
}
