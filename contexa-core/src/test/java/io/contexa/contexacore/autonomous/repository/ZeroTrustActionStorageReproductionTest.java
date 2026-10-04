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
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Storage of the final decision in both repository implementations. The decision is stored per
 * user while analysis runs per user session. CHALLENGE and ESCALATE restrict the user like BLOCK:
 * the analysis of another session, a re-analysis or the logout of one session cannot lift them.
 * MFA success, an approved override, a stricter decision or the TTL still replace them. ALLOW stays
 * bound to the analysed context and lapses after its 15 second TTL.
 */
class ZeroTrustActionStorageReproductionTest {

    private static final String REDIS_PORT = "CONTEXA_BACKLOG_REDIS_PORT";
    private static final String SESSION_A = "context-hash-session-a";
    private static final String SESSION_B = "context-hash-session-b";

    private static LettuceConnectionFactory factory;
    private static StringRedisTemplate strings;
    private static ZeroTrustActionRedisRepository redis;

    @BeforeAll
    static void connect() {
        String port = System.getenv(REDIS_PORT);
        if (port == null || !port.matches("[0-9]+")) {
            return;
        }
        factory = new LettuceConnectionFactory("127.0.0.1", Integer.parseInt(port));
        factory.afterPropertiesSet();
        strings = RedisTestTemplates.newStringRedisTemplate(factory);
        redis = new ZeroTrustActionRedisRepository(
                RedisTestTemplates.newProductionAlignedRedisTemplate(factory), strings);
    }

    @AfterAll
    static void close() {
        if (factory != null) {
            factory.destroy();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"CHALLENGE", "ESCALATE"})
    void inMemoryAnotherSessionCannotLiftRestriction(String restriction) {
        assertAnotherSessionCannotLift(new InMemoryZeroTrustActionRepository(), ZeroTrustAction.valueOf(restriction));
    }

    @ParameterizedTest
    @ValueSource(strings = {"CHALLENGE", "ESCALATE"})
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAnotherSessionCannotLiftRestriction(String restriction) {
        assertAnotherSessionCannotLift(redis, ZeroTrustAction.valueOf(restriction));
    }

    @Test
    void inMemoryConcurrentLessStrictWritesCannotLiftRestriction() throws Exception {
        assertConcurrentLessStrictWritesCannotLift(new InMemoryZeroTrustActionRepository());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisConcurrentLessStrictWritesCannotLiftRestriction() throws Exception {
        assertConcurrentLessStrictWritesCannotLift(redis);
    }

    @Test
    void inMemoryEscalateIsNotReplacedByChallenge() {
        assertEscalateIsNotReplacedByChallenge(new InMemoryZeroTrustActionRepository());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisEscalateIsNotReplacedByChallenge() {
        assertEscalateIsNotReplacedByChallenge(redis);
    }

    @Test
    void inMemoryStricterDecisionReplacesRestriction() {
        assertStricterDecisionReplaces(new InMemoryZeroTrustActionRepository());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisStricterDecisionReplacesRestriction() {
        assertStricterDecisionReplaces(redis);
    }

    @Test
    void inMemoryAllowStaysBoundToItsContext() {
        assertAllowStaysBoundToItsContext(new InMemoryZeroTrustActionRepository());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAllowStaysBoundToItsContext() {
        assertAllowStaysBoundToItsContext(redis);
    }

    @Test
    void inMemoryAllowLapsesToPendingAfterAnalysisTtl() {
        ZeroTrustActionRepository repository = new InMemoryZeroTrustActionRepository();
        String user = user();
        assertThat(repository.saveFinalAction(user, ZeroTrustAction.ALLOW, fields(SESSION_A))).isTrue();
        assertThat(repository.getCurrentAction(user, SESSION_A)).isEqualTo(ZeroTrustAction.ALLOW);
        Awaitility.await().atMost(Duration.ofSeconds(20)).pollInterval(Duration.ofMillis(250)).untilAsserted(() -> {
            assertThat(repository.getCurrentAction(user, SESSION_A)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
            assertThat(repository.getCurrentAction(user)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        });
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAllowLapsesToPendingAfterAnalysisTtl() {
        String user = user();
        assertThat(redis.saveFinalAction(user, ZeroTrustAction.ALLOW, fields(SESSION_A))).isTrue();
        assertThat(redis.getCurrentAction(user, SESSION_A)).isEqualTo(ZeroTrustAction.ALLOW);
        Awaitility.await().atMost(Duration.ofSeconds(20)).pollInterval(Duration.ofMillis(250)).untilAsserted(() -> {
            assertThat(redis.getAnalysisData(user).action()).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS.name());
            assertThat(redis.getCurrentAction(user, SESSION_A)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        });
    }

    @Test
    void inMemoryMfaSuccessReleasesChallenge() {
        assertMfaSuccessReleasesChallenge(new InMemoryZeroTrustActionRepository());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisMfaSuccessReleasesChallenge() {
        assertMfaSuccessReleasesChallenge(redis);
    }

    @ParameterizedTest
    @ValueSource(strings = {"CHALLENGE", "ESCALATE"})
    void inMemoryApprovedOverrideReleasesRestriction(String restriction) {
        assertApprovedOverrideReleases(new InMemoryZeroTrustActionRepository(), ZeroTrustAction.valueOf(restriction));
    }

    @ParameterizedTest
    @ValueSource(strings = {"CHALLENGE", "ESCALATE"})
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisApprovedOverrideReleasesRestriction(String restriction) {
        assertApprovedOverrideReleases(redis, ZeroTrustAction.valueOf(restriction));
    }

    @Test
    void inMemoryEscalatePromotionToBlockStillApplies() {
        assertEscalatePromotionToBlockStillApplies(new InMemoryZeroTrustActionRepository());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisEscalatePromotionToBlockStillApplies() {
        assertEscalatePromotionToBlockStillApplies(redis);
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisExpiredRestrictionNoLongerApplies() {
        String user = user();
        assertThat(redis.saveFinalAction(user, ZeroTrustAction.CHALLENGE, fields(SESSION_A))).isTrue();
        strings.expire(ZeroTrustRedisKeys.autonomousActionAnalysis(user), Duration.ofMillis(300));
        Awaitility.await().atMost(Duration.ofSeconds(5)).untilAsserted(() ->
                assertThat(redis.getCurrentAction(user, SESSION_B)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS));
        assertThat(redis.saveFinalAction(user, ZeroTrustAction.ALLOW, fields(SESSION_B))).isTrue();
        assertThat(redis.getCurrentAction(user, SESSION_B)).isEqualTo(ZeroTrustAction.ALLOW);
    }

    @ParameterizedTest
    @ValueSource(strings = {"CHALLENGE", "ESCALATE"})
    void inMemoryLogoutKeepsRestriction(String restriction) {
        assertLogoutKeepsRestriction(new InMemoryZeroTrustActionRepository(), ZeroTrustAction.valueOf(restriction));
    }

    @ParameterizedTest
    @ValueSource(strings = {"CHALLENGE", "ESCALATE"})
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisLogoutKeepsRestriction(String restriction) {
        assertLogoutKeepsRestriction(redis, ZeroTrustAction.valueOf(restriction));
    }

    private static void assertAnotherSessionCannotLift(
            ZeroTrustActionRepository repository, ZeroTrustAction restriction) {
        String user = user();
        assertThat(repository.saveFinalAction(user, restriction, fields(SESSION_A))).isTrue();
        assertThat(repository.getCurrentAction(user, SESSION_B)).isEqualTo(restriction);

        assertThat(repository.saveFinalAction(user, ZeroTrustAction.ALLOW, fields(SESSION_B))).isTrue();
        assertThat(repository.saveFinalAction(user, ZeroTrustAction.PENDING_ANALYSIS, fields(SESSION_B))).isTrue();
        assertThat(repository.saveFinalAction(user, ZeroTrustAction.ALLOW, fields(SESSION_A))).isTrue();

        assertThat(repository.getCurrentAction(user, SESSION_A)).isEqualTo(restriction);
        assertThat(repository.getCurrentAction(user, SESSION_B)).isEqualTo(restriction);
        assertThat(repository.getCurrentAction(user)).isEqualTo(restriction);
        assertThat(repository.getActionFromHash(user)).isEqualTo(restriction);
        assertThat(repository.getAnalysisData(user).contextBindingHash()).isEqualTo(SESSION_A);
    }

    /**
     * Writers of other contexts keep storing ALLOW while one writer stores CHALLENGE in the middle of
     * its own ALLOW stream. Every ALLOW that was not overwritten by the CHALLENGE must be refused.
     */
    private static void assertConcurrentLessStrictWritesCannotLift(ZeroTrustActionRepository repository)
            throws Exception {
        int writers = 8;
        int writesPerWriter = 20;
        ExecutorService pool = Executors.newFixedThreadPool(writers + 1);
        try {
            for (int round = 0; round < 20; round++) {
                String user = user();
                CyclicBarrier start = new CyclicBarrier(writers + 1);
                List<Future<?>> allowWriters = new ArrayList<>();
                for (int writer = 0; writer < writers; writer++) {
                    String context = "context-hash-writer-" + writer;
                    allowWriters.add(pool.submit(() -> {
                        start.await();
                        for (int write = 0; write < writesPerWriter; write++) {
                            repository.saveFinalAction(user, ZeroTrustAction.ALLOW, fields(context));
                        }
                        return null;
                    }));
                }
                Future<Boolean> challengeWriter = pool.submit(() -> {
                    start.await();
                    for (int write = 0; write < writesPerWriter / 2; write++) {
                        repository.saveFinalAction(user, ZeroTrustAction.ALLOW, fields(SESSION_A));
                    }
                    boolean saved = repository.saveFinalAction(user, ZeroTrustAction.CHALLENGE, fields(SESSION_A));
                    for (int write = 0; write < writesPerWriter / 2; write++) {
                        repository.saveFinalAction(user, ZeroTrustAction.ALLOW, fields(SESSION_A));
                    }
                    return saved;
                });

                assertThat(challengeWriter.get(30, TimeUnit.SECONDS)).isTrue();
                for (Future<?> allowWriter : allowWriters) {
                    allowWriter.get(30, TimeUnit.SECONDS);
                }

                assertThat(repository.getActionFromHash(user)).as("round %d", round).isEqualTo(ZeroTrustAction.CHALLENGE);
                assertThat(repository.getCurrentAction(user, "context-hash-writer-0")).isEqualTo(ZeroTrustAction.CHALLENGE);
                assertThat(repository.getCurrentAction(user, SESSION_B)).isEqualTo(ZeroTrustAction.CHALLENGE);
                assertThat(repository.getLastVerifiedAction(user)).isEqualTo(ZeroTrustAction.CHALLENGE);
                assertThat(repository.getAnalysisData(user).contextBindingHash()).isEqualTo(SESSION_A);
                repository.removeAllUserData(user);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private static void assertEscalateIsNotReplacedByChallenge(ZeroTrustActionRepository repository) {
        String user = user();
        assertThat(repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields(SESSION_A))).isTrue();
        assertThat(repository.saveFinalAction(user, ZeroTrustAction.CHALLENGE, fields(SESSION_B))).isTrue();
        assertThat(repository.getCurrentAction(user, SESSION_B)).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(repository.getActionFromHash(user)).isEqualTo(ZeroTrustAction.ESCALATE);
    }

    private static void assertStricterDecisionReplaces(ZeroTrustActionRepository repository) {
        String user = user();
        assertThat(repository.saveFinalAction(user, ZeroTrustAction.CHALLENGE, fields(SESSION_A))).isTrue();
        assertThat(repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields(SESSION_B))).isTrue();
        assertThat(repository.getCurrentAction(user, SESSION_A)).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(repository.saveFinalAction(user, ZeroTrustAction.BLOCK, fields(SESSION_A))).isTrue();
        assertThat(repository.getCurrentAction(user, SESSION_B)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.getActionFromHash(user)).isEqualTo(ZeroTrustAction.BLOCK);
        repository.removeAllUserData(user);
    }

    private static void assertAllowStaysBoundToItsContext(ZeroTrustActionRepository repository) {
        String user = user();
        assertThat(repository.saveFinalAction(user, ZeroTrustAction.ALLOW, fields(SESSION_A))).isTrue();
        assertThat(repository.getCurrentAction(user, SESSION_A)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(repository.getCurrentAction(user, SESSION_B)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(repository.saveFinalAction(user, ZeroTrustAction.ALLOW, fields(SESSION_B))).isTrue();
        assertThat(repository.getCurrentAction(user, SESSION_B)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(repository.getCurrentAction(user, SESSION_A)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    private static void assertMfaSuccessReleasesChallenge(ZeroTrustActionRepository repository) {
        String user = user();
        assertThat(repository.saveFinalAction(user, ZeroTrustAction.CHALLENGE, fields(SESSION_A))).isTrue();
        assertThat(repository.getActionFromHash(user)).isEqualTo(ZeroTrustAction.CHALLENGE);

        repository.saveActionWithPrevious(user, ZeroTrustAction.ALLOW, SESSION_B);

        assertThat(repository.getCurrentAction(user, SESSION_B)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(repository.getCurrentAction(user, SESSION_A)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(repository.saveFinalAction(user, ZeroTrustAction.ALLOW, fields(SESSION_A))).isTrue();
        assertThat(repository.getCurrentAction(user, SESSION_A)).isEqualTo(ZeroTrustAction.ALLOW);
    }

    private static void assertApprovedOverrideReleases(
            ZeroTrustActionRepository repository, ZeroTrustAction restriction) {
        String user = user();
        assertThat(repository.saveFinalAction(user, restriction, fields(SESSION_A))).isTrue();

        repository.approveOverrideAtomically(user, ZeroTrustAction.ALLOW);

        assertThat(repository.getCurrentAction(user, SESSION_A)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(repository.saveFinalAction(user, ZeroTrustAction.ALLOW, fields(SESSION_B))).isTrue();
        assertThat(repository.getCurrentAction(user, SESSION_B)).isEqualTo(ZeroTrustAction.ALLOW);
    }

    private static void assertEscalatePromotionToBlockStillApplies(ZeroTrustActionRepository repository) {
        String user = user();
        assertThat(repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields(SESSION_A))).isTrue();

        repository.saveAction(user, ZeroTrustAction.BLOCK, Map.of(
                "promotedFrom", "ESCALATE", "contextBindingHash", SESSION_B));
        repository.setBlockedFlag(user);

        assertThat(repository.getCurrentAction(user, SESSION_A)).isEqualTo(ZeroTrustAction.BLOCK);
        repository.removeAllUserData(user);
    }

    private static void assertLogoutKeepsRestriction(
            ZeroTrustActionRepository repository, ZeroTrustAction restriction) {
        String user = user();
        assertThat(repository.saveFinalAction(user, restriction, fields(SESSION_A))).isTrue();

        repository.removeLogoutData(user);

        assertThat(repository.getCurrentAction(user, SESSION_A)).isEqualTo(restriction);
        assertThat(repository.getCurrentAction(user, SESSION_B)).isEqualTo(restriction);
        repository.removeAllUserData(user);
        assertThat(repository.getCurrentAction(user, SESSION_A)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    private static String user() {
        return "repro-" + UUID.randomUUID();
    }

    private static Map<String, Object> fields(String contextBindingHash) {
        return Map.of(
                "contextBindingHash", contextBindingHash,
                "observationId", UUID.randomUUID().toString(),
                "processingGeneration", UUID.randomUUID().toString());
    }
}
