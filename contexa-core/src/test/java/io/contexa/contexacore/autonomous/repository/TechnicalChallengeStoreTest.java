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
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository.FinalActionWrite;
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
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Q-5 (PR-50): a CHALLENGE no model decided lasts a short time, gives way to what the model decides and never shortens
 * a restriction the model decided. Both repositories answer alike: every scenario runs on the in-memory repository and
 * on a real Redis (set CONTEXA_BACKLOG_REDIS_PORT), under keys of their own.
 */
class TechnicalChallengeStoreTest {

    private static final String REDIS_PORT = "CONTEXA_BACKLOG_REDIS_PORT";
    private static final String CONTEXT = "context-hash-a";

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
            public void assertLasts(String user, Duration time) {
                Long left = strings.getExpire(ZeroTrustRedisKeys.autonomousActionAnalysis(user), TimeUnit.MILLISECONDS);
                assertThat(left).isBetween(time.minusSeconds(5).toMillis(), time.toMillis());
            }
        };
    }

    private static String user() {
        return "q5-" + UUID.randomUUID();
    }

    private static Map<String, Object> modelDecided() {
        Map<String, Object> fields = new HashMap<>();
        fields.put("observationId", "observation-" + UUID.randomUUID());
        fields.put("processingGeneration", "generation-" + UUID.randomUUID());
        fields.put("contextBindingHash", CONTEXT);
        fields.put("llmDecisionPresent", true);
        return fields;
    }

    private static Map<String, Object> noModel() {
        Map<String, Object> fields = modelDecided();
        fields.put("llmDecisionPresent", false);
        return fields;
    }

    private static Map<String, Object> technical() {
        Map<String, Object> fields = noModel();
        fields.put(ZeroTrustActionRepository.TECHNICAL_CHALLENGE, true);
        return fields;
    }

    private static void assertWrite(ZeroTrustActionRepository repository, String user, ZeroTrustAction action,
                                    Map<String, Object> fields, FinalActionWrite expected) {
        assertThat(repository.writeFinalAction(user, action, fields)).as(action.name()).isEqualTo(expected);
    }

    // ----- it is short and it is marked -----

    private static void assertShortAndMarked(Store store) {
        String user = user();
        assertWrite(store.repository(), user, ZeroTrustAction.CHALLENGE, technical(), FinalActionWrite.APPLIED);

        assertThat(store.repository().getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(store.repository().isTechnicalChallenge(user)).isTrue();
        store.assertLasts(user, ZeroTrustActionRepository.TECHNICAL_CHALLENGE_TTL);
    }

    @Test
    void inMemoryItIsShortAndMarked() {
        assertShortAndMarked(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisItIsShortAndMarked() {
        assertShortAndMarked(redis());
    }

    private static void assertTheModelsChallengeKeepsItsOwnTime(Store store) {
        String user = user();
        assertWrite(store.repository(), user, ZeroTrustAction.CHALLENGE, modelDecided(), FinalActionWrite.APPLIED);

        assertThat(store.repository().isTechnicalChallenge(user)).isFalse();
        store.assertLasts(user, ZeroTrustAction.CHALLENGE.getDefaultTtl());
    }

    @Test
    void inMemoryTheModelsChallengeKeepsItsOwnTime() {
        assertTheModelsChallengeKeepsItsOwnTime(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisTheModelsChallengeKeepsItsOwnTime() {
        assertTheModelsChallengeKeepsItsOwnTime(redis());
    }

    // ----- it gives way to what the model decides -----

    private static void assertAnAllowOfTheModelReplacesIt(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        assertWrite(repository, user, ZeroTrustAction.CHALLENGE, technical(), FinalActionWrite.APPLIED);

        assertWrite(repository, user, ZeroTrustAction.ALLOW, modelDecided(), FinalActionWrite.APPLIED);

        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(repository.isTechnicalChallenge(user)).isFalse();
        store.assertLasts(user, ZeroTrustAction.ALLOW.getDefaultTtl());
    }

    @Test
    void inMemoryAnAllowOfTheModelReplacesIt() {
        assertAnAllowOfTheModelReplacesIt(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAnAllowOfTheModelReplacesIt() {
        assertAnAllowOfTheModelReplacesIt(redis());
    }

    private static void assertWhatNoModelReachedDoesNotLiftIt(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        assertWrite(repository, user, ZeroTrustAction.CHALLENGE, technical(), FinalActionWrite.APPLIED);

        assertWrite(repository, user, ZeroTrustAction.ALLOW, noModel(), FinalActionWrite.KEPT_STRICTER);
        Map<String, Object> unstated = modelDecided();
        unstated.remove("llmDecisionPresent");
        assertWrite(repository, user, ZeroTrustAction.ALLOW, unstated, FinalActionWrite.KEPT_STRICTER);
        assertWrite(repository, user, ZeroTrustAction.PENDING_ANALYSIS, noModel(), FinalActionWrite.KEPT_STRICTER);

        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.isTechnicalChallenge(user)).isTrue();
        repository.removeAllUserData(user);
    }

    @Test
    void inMemoryWhatNoModelReachedDoesNotLiftIt() {
        assertWhatNoModelReachedDoesNotLiftIt(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisWhatNoModelReachedDoesNotLiftIt() {
        assertWhatNoModelReachedDoesNotLiftIt(redis());
    }

    private static void assertAChallengeOfTheModelReplacesItWithItsOwnTime(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        assertWrite(repository, user, ZeroTrustAction.CHALLENGE, technical(), FinalActionWrite.APPLIED);

        assertWrite(repository, user, ZeroTrustAction.CHALLENGE, modelDecided(), FinalActionWrite.APPLIED);

        assertThat(repository.isTechnicalChallenge(user)).isFalse();
        store.assertLasts(user, ZeroTrustAction.CHALLENGE.getDefaultTtl());
    }

    @Test
    void inMemoryAChallengeOfTheModelReplacesItWithItsOwnTime() {
        assertAChallengeOfTheModelReplacesItWithItsOwnTime(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAChallengeOfTheModelReplacesItWithItsOwnTime() {
        assertAChallengeOfTheModelReplacesItWithItsOwnTime(redis());
    }

    private static void assertABlockReplacesIt(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        assertWrite(repository, user, ZeroTrustAction.CHALLENGE, technical(), FinalActionWrite.APPLIED);

        assertWrite(repository, user, ZeroTrustAction.BLOCK, modelDecided(), FinalActionWrite.APPLIED);

        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.isTechnicalChallenge(user)).isFalse();
        repository.removeAllUserData(user);
    }

    @Test
    void inMemoryABlockReplacesIt() {
        assertABlockReplacesIt(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisABlockReplacesIt() {
        assertABlockReplacesIt(redis());
    }

    // ----- a restriction the model decided is never lowered by it -----

    private static void assertItNeverShortensTheModelsChallenge(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        assertWrite(repository, user, ZeroTrustAction.CHALLENGE, modelDecided(), FinalActionWrite.APPLIED);

        assertWrite(repository, user, ZeroTrustAction.CHALLENGE, technical(), FinalActionWrite.KEPT_STRICTER);

        assertThat(repository.isTechnicalChallenge(user)).isFalse();
        store.assertLasts(user, ZeroTrustAction.CHALLENGE.getDefaultTtl());
    }

    @Test
    void inMemoryItNeverShortensTheModelsChallenge() {
        assertItNeverShortensTheModelsChallenge(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisItNeverShortensTheModelsChallenge() {
        assertItNeverShortensTheModelsChallenge(redis());
    }

    private static void assertItNeverReplacesABlockOrAnEscalate(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        for (ZeroTrustAction stricter : new ZeroTrustAction[] {ZeroTrustAction.BLOCK, ZeroTrustAction.ESCALATE}) {
            String user = user();
            assertWrite(repository, user, stricter, modelDecided(), FinalActionWrite.APPLIED);

            assertWrite(repository, user, ZeroTrustAction.CHALLENGE, technical(), FinalActionWrite.KEPT_STRICTER);

            assertThat(repository.getActionFromHash(user)).isEqualTo(stricter);
            repository.removeAllUserData(user);
        }
    }

    @Test
    void inMemoryItNeverReplacesABlockOrAnEscalate() {
        assertItNeverReplacesABlockOrAnEscalate(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisItNeverReplacesABlockOrAnEscalate() {
        assertItNeverReplacesABlockOrAnEscalate(redis());
    }

    private static void assertTheBlockFlagKeepsItOut(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        repository.setBlockedFlag(user);

        assertWrite(repository, user, ZeroTrustAction.CHALLENGE, technical(), FinalActionWrite.KEPT_STRICTER);

        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
        repository.removeAllUserData(user);
    }

    @Test
    void inMemoryTheBlockFlagKeepsItOut() {
        assertTheBlockFlagKeepsItOut(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisTheBlockFlagKeepsItOut() {
        assertTheBlockFlagKeepsItOut(redis());
    }

    private static void assertTheNextFailureRenewsIt(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        assertWrite(repository, user, ZeroTrustAction.CHALLENGE, technical(), FinalActionWrite.APPLIED);

        assertWrite(repository, user, ZeroTrustAction.CHALLENGE, technical(), FinalActionWrite.APPLIED);

        assertThat(repository.isTechnicalChallenge(user)).isTrue();
        store.assertLasts(user, ZeroTrustActionRepository.TECHNICAL_CHALLENGE_TTL);
    }

    @Test
    void inMemoryTheNextFailureRenewsIt() {
        assertTheNextFailureRenewsIt(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisTheNextFailureRenewsIt() {
        assertTheNextFailureRenewsIt(redis());
    }

    // ----- a passed step-up -----

    private static void assertAPassedStepUpTakesTheMarkWithIt(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        assertWrite(repository, user, ZeroTrustAction.CHALLENGE, technical(), FinalActionWrite.APPLIED);

        repository.saveActionWithPrevious(user, ZeroTrustAction.ALLOW, CONTEXT);

        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(repository.isTechnicalChallenge(user)).isFalse();
        // What the ALLOW left behind must not make a later CHALLENGE of the model give way.
        repository.saveActionWithPrevious(user, ZeroTrustAction.CHALLENGE, CONTEXT);
        assertThat(repository.isTechnicalChallenge(user)).isFalse();
        assertWrite(repository, user, ZeroTrustAction.ALLOW, modelDecided(), FinalActionWrite.KEPT_STRICTER);
        repository.removeAllUserData(user);
    }

    @Test
    void inMemoryAPassedStepUpTakesTheMarkWithIt() {
        assertAPassedStepUpTakesTheMarkWithIt(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAPassedStepUpTakesTheMarkWithIt() {
        assertAPassedStepUpTakesTheMarkWithIt(redis());
    }

    private static void assertAnApprovedOverrideTakesTheMarkWithIt(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        assertWrite(repository, user, ZeroTrustAction.CHALLENGE, technical(), FinalActionWrite.APPLIED);

        repository.approveOverrideAtomically(user, ZeroTrustAction.CHALLENGE);

        assertThat(repository.isTechnicalChallenge(user)).isFalse();
        store.assertLasts(user, ZeroTrustAction.CHALLENGE.getDefaultTtl());
    }

    @Test
    void inMemoryAnApprovedOverrideTakesTheMarkWithIt() {
        assertAnApprovedOverrideTakesTheMarkWithIt(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAnApprovedOverrideTakesTheMarkWithIt() {
        assertAnApprovedOverrideTakesTheMarkWithIt(redis());
    }
}
