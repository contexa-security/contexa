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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.testsupport.AdjustableClock;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Q-28 (PR-92): an ALLOW lasts the production time unless a setting says otherwise, and a setting that could keep it
 * for ever reads as the default. Both repositories answer alike: every scenario runs on the in-memory repository and
 * on a real Redis (set CONTEXA_BACKLOG_REDIS_PORT), under keys of their own.
 */
class AllowValidityStoreTest {

    private static final String REDIS_PORT = "CONTEXA_BACKLOG_REDIS_PORT";
    private static final String CONTEXT = "context-hash-a";
    private static final String OTHER_CONTEXT = "context-hash-b";
    private static final Duration PRODUCTION = Duration.ofMinutes(15);
    /** Not a time any default has, so that only the setting can give it. */
    private static final Duration SHORT = Duration.ofSeconds(40);

    private static LettuceConnectionFactory factory;
    private static StringRedisTemplate strings;

    @BeforeAll
    static void connect() {
        String port = System.getenv(REDIS_PORT);
        if (port == null || !port.matches("[0-9]+")) {
            return;
        }
        factory = new LettuceConnectionFactory("127.0.0.1", Integer.parseInt(port));
        factory.afterPropertiesSet();
        strings = RedisTestTemplates.newStringRedisTemplate(factory);
    }

    @AfterAll
    static void close() {
        if (factory != null) {
            factory.destroy();
        }
    }

    private interface Store {
        ZeroTrustActionRepository repository();

        void set(Duration validity);

        /** The action of the user is in force a little before the time and gone a little after it. */
        void assertLasts(String user, Duration time);
    }

    private static Store inMemory() {
        AdjustableClock clock = new AdjustableClock();
        InMemoryZeroTrustActionRepository repository = new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);
        return new Store() {
            @Override
            public ZeroTrustActionRepository repository() {
                return repository;
            }

            @Override
            public void set(Duration validity) {
                repository.setAllowValidity(validity);
            }

            @Override
            public void assertLasts(String user, Duration time) {
                clock.advance(time.minusSeconds(5));
                assertThat(repository.getActionFromHash(user)).as("before its time").isNotNull();
                clock.advance(Duration.ofSeconds(6));
                assertThat(repository.getActionFromHash(user)).as("after its time").isNull();
                assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
            }
        };
    }

    private static Store redis() {
        ZeroTrustActionRedisRepository repository = new ZeroTrustActionRedisRepository(
                RedisTestTemplates.newProductionAlignedRedisTemplate(factory), strings);
        return new Store() {
            @Override
            public ZeroTrustActionRepository repository() {
                return repository;
            }

            @Override
            public void set(Duration validity) {
                repository.setAllowValidity(validity);
            }

            @Override
            public void assertLasts(String user, Duration time) {
                Long left = strings.getExpire(ZeroTrustRedisKeys.autonomousActionAnalysis(user), TimeUnit.MILLISECONDS);
                assertThat(left).isBetween(time.minusSeconds(5).toMillis(), time.toMillis());
            }
        };
    }

    private static String user() {
        return "allow-validity-" + UUID.randomUUID();
    }

    private static Map<String, Object> bound() {
        return Map.of("contextBindingHash", CONTEXT);
    }

    private void withoutASettingAnAllowLastsTheProductionTime(Store store) {
        String user = user();
        store.repository().saveAction(user, ZeroTrustAction.ALLOW, bound());
        store.assertLasts(user, PRODUCTION);
    }

    private void aSettingDecidesHowLongAnAllowLasts(Store store) {
        store.set(SHORT);
        String user = user();
        store.repository().saveAction(user, ZeroTrustAction.ALLOW, bound());
        store.assertLasts(user, SHORT);
    }

    private void theAllowAPassedStepUpWritesLastsTheSame(Store store) {
        store.set(SHORT);
        String user = user();
        store.repository().saveAction(user, ZeroTrustAction.CHALLENGE, bound());
        store.repository().saveActionWithPrevious(user, ZeroTrustAction.ALLOW, CONTEXT);
        store.assertLasts(user, SHORT);
    }

    private void aSettingThatCouldKeepAnAllowForEverReadsAsTheDefault(Store store) {
        for (Duration invalid : new Duration[] {Duration.ZERO, Duration.ofSeconds(-1), null}) {
            store.set(invalid);
            String user = user();
            store.repository().saveAction(user, ZeroTrustAction.ALLOW, bound());
            store.assertLasts(user, PRODUCTION);
        }
    }

    private void theSettingTouchesNoOtherAction(Store store) {
        store.set(SHORT);
        String user = user();
        store.repository().saveAction(user, ZeroTrustAction.CHALLENGE, bound());
        store.assertLasts(user, ZeroTrustAction.CHALLENGE.getDefaultTtl());
    }

    private void anAllowInForceAnswersNoOtherContext(Store store) {
        String user = user();
        store.repository().saveAction(user, ZeroTrustAction.ALLOW, bound());

        assertThat(store.repository().getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(store.repository().getCurrentAction(user, OTHER_CONTEXT))
                .isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    void inMemoryWithoutASetting() {
        withoutASettingAnAllowLastsTheProductionTime(inMemory());
    }

    @Test
    void inMemoryUnderASetting() {
        aSettingDecidesHowLongAnAllowLasts(inMemory());
    }

    @Test
    void inMemoryAfterAStepUp() {
        theAllowAPassedStepUpWritesLastsTheSame(inMemory());
    }

    @Test
    void inMemoryUnderAnInvalidSetting() {
        aSettingThatCouldKeepAnAllowForEverReadsAsTheDefault(inMemory());
    }

    @Test
    void inMemoryOtherActions() {
        theSettingTouchesNoOtherAction(inMemory());
    }

    @Test
    void inMemoryOtherContext() {
        anAllowInForceAnswersNoOtherContext(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisWithoutASetting() {
        withoutASettingAnAllowLastsTheProductionTime(redis());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisUnderASetting() {
        aSettingDecidesHowLongAnAllowLasts(redis());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAfterAStepUp() {
        theAllowAPassedStepUpWritesLastsTheSame(redis());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisUnderAnInvalidSetting() {
        aSettingThatCouldKeepAnAllowForEverReadsAsTheDefault(redis());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisOtherActions() {
        theSettingTouchesNoOtherAction(redis());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisOtherContext() {
        anAllowInForceAnswersNoOtherContext(redis());
    }
}
