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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PR-83: with allow-escalate-final-action off an ESCALATE is internal to the analysis, so one left in the store, by an
 * earlier version or setting, ends as the terminal action when it is read. It never reaches the access filter's
 * promotion to BLOCK. Both repositories answer alike: the keys are written as the earlier version wrote them, then read
 * with the terminal action set.
 */
class StoredEscalateTerminalActionTest {

    private static final String REDIS_PORT = "CONTEXA_BACKLOG_REDIS_PORT";
    private static final String CONTEXT = "context-hash-a";
    private static final String OTHER_CONTEXT = "context-hash-b";

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

    /** A store and how time passes for it: a clock moves, a Redis key is left with what is said to remain of it. */
    private interface Store {
        ZeroTrustActionRepository repository();

        /** The analysis of the user passes its TTL. */
        void expireAnalysis(String user);
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
            public void expireAnalysis(String user) {
                ZeroTrustAction action = repository.getActionFromHash(user);
                clock.advance(action.getDefaultTtl().plusSeconds(1));
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
            public void expireAnalysis(String user) {
                strings.expire(ZeroTrustRedisKeys.autonomousActionAnalysis(user), Duration.ofMillis(200));
                Awaitility.await().atMost(Duration.ofSeconds(5)).until(() ->
                        !Boolean.TRUE.equals(strings.hasKey(ZeroTrustRedisKeys.autonomousActionAnalysis(user))));
            }
        };
    }

    private static String user() {
        return "pr83-" + UUID.randomUUID();
    }

    private static Map<String, Object> fields(String context, String requestId) {
        Map<String, Object> fields = new HashMap<>();
        fields.put("observationId", "observation-" + UUID.randomUUID());
        fields.put("processingGeneration", "generation-" + UUID.randomUUID());
        fields.put("contextBindingHash", context);
        fields.put("requestId", requestId);
        fields.put("reasoning", "Layer 2 LLM call failed");
        fields.put("riskScore", 0.4);
        return fields;
    }

    // ----- an ESCALATE whose analysis is in its TTL -----

    @Test
    void inMemoryALiveEscalateEndsAsTheTerminalActionForEveryReader() {
        assertLiveEscalateEnds(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisALiveEscalateEndsAsTheTerminalActionForEveryReader() {
        assertLiveEscalateEnds(redis());
    }

    private static void assertLiveEscalateEnds(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        assertThat(repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields(CONTEXT, "request-1"))).isTrue();

        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);

        assertThat(repository.getCurrentAction(user, OTHER_CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getCurrentAction(user)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getActionFromHash(user)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getLastVerifiedAction(user)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getPreviousActionFromHash(user)).isEqualTo(ZeroTrustAction.ESCALATE);
        // The analysis stays with it: a step-up learns the request the challenge stopped from its id.
        ZeroTrustActionRepository.ZeroTrustAnalysisData analysis = repository.getAnalysisData(user);
        assertThat(analysis.action()).isEqualTo("CHALLENGE");
        assertThat(analysis.requestId()).isEqualTo("request-1");
        assertThat(analysis.reasoning()).isEqualTo("Layer 2 LLM call failed");
        assertThat(analysis.contextBindingHash()).isEqualTo(CONTEXT);
        assertThat(analysis.riskScore()).isEqualTo(0.4);
        repository.removeAllUserData(user);
    }

    /** The first read may be any of them: a sign-in reads the analysis data, a release the hash. */
    @Test
    void inMemoryEachReadEndsAnEscalateByItself() {
        assertEachReadEnds(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisEachReadEndsAnEscalateByItself() {
        assertEachReadEnds(redis());
    }

    private static void assertEachReadEnds(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        repository.setEscalateTerminalAction(null);
        String first = user();
        String second = user();
        repository.saveFinalAction(first, ZeroTrustAction.ESCALATE, fields(CONTEXT, "request-1"));
        repository.saveFinalAction(second, ZeroTrustAction.ESCALATE, fields(CONTEXT, "request-2"));
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);

        assertThat(repository.getAnalysisData(first).action()).isEqualTo("CHALLENGE");
        assertThat(repository.getActionFromHash(second)).isEqualTo(ZeroTrustAction.CHALLENGE);
        repository.removeAllUserData(first);
        repository.removeAllUserData(second);
    }

    // ----- an ESCALATE whose analysis passed its TTL: what the access filter promoted to BLOCK -----

    @Test
    void inMemoryAnEscalatePastItsTtlEndsAsTheTerminalActionAndThenLapsesAsOne() {
        assertExpiredEscalateEnds(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAnEscalatePastItsTtlEndsAsTheTerminalActionAndThenLapsesAsOne() {
        assertExpiredEscalateEnds(redis());
    }

    private static void assertExpiredEscalateEnds(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields(CONTEXT, "request-1"));
        store.expireAnalysis(user);
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);

        assertThat(repository.getCurrentAction(user, OTHER_CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getCurrentAction(user)).isEqualTo(ZeroTrustAction.CHALLENGE);
        // A real CHALLENGE now, so that the MFA its challenge starts finds and releases it.
        assertThat(repository.getActionFromHash(user)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getLastVerifiedAction(user)).isEqualTo(ZeroTrustAction.CHALLENGE);

        store.expireAnalysis(user);

        assertThat(repository.getCurrentAction(user, OTHER_CONTEXT)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(repository.getCurrentAction(user)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        repository.removeAllUserData(user);
    }

    @Test
    void inMemoryTheEndedActionKeepsItsOwnTtl() {
        AdjustableClock clock = new AdjustableClock();
        InMemoryZeroTrustActionRepository repository = new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);
        String user = user();
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields(CONTEXT, "request-1"));
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);

        clock.advance(ZeroTrustAction.CHALLENGE.getDefaultTtl().minusSeconds(10));
        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);

        clock.advance(Duration.ofSeconds(11));
        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisTheEndedActionKeepsItsOwnTtl() {
        ZeroTrustActionRepository repository = redis().repository();
        String user = user();
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields(CONTEXT, "request-1"));
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);

        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);

        Long ttl = strings.getExpire(ZeroTrustRedisKeys.autonomousActionAnalysis(user), TimeUnit.SECONDS);
        assertThat(ttl).isBetween(ZeroTrustAction.CHALLENGE.getDefaultTtl().toSeconds() - 30,
                ZeroTrustAction.CHALLENGE.getDefaultTtl().toSeconds());
        repository.removeAllUserData(user);
    }

    /** Keys an earlier version left: the plain string form of the hash, as the legacy reader of the repository reads. */
    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAnEscalateInTheLegacyPlainFormEndsToo() {
        ZeroTrustActionRepository repository = redis().repository();
        String user = user();
        strings.opsForHash().put(ZeroTrustRedisKeys.autonomousActionAnalysis(user), "action", "ESCALATE");
        strings.opsForHash().put(ZeroTrustRedisKeys.autonomousActionAnalysis(user), "requestId", "request-1");
        strings.opsForValue().set(ZeroTrustRedisKeys.autonomousLastVerifiedAction(user), "ESCALATE");
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);

        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getActionFromHash(user)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getLastVerifiedAction(user)).isEqualTo(ZeroTrustAction.CHALLENGE);
        repository.removeAllUserData(user);
    }

    // ----- the ended action behaves as the action it is -----

    @Test
    void inMemoryTheStepUpReleasesTheEndedAction() {
        assertStepUpReleases(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisTheStepUpReleasesTheEndedAction() {
        assertStepUpReleases(redis());
    }

    private static void assertStepUpReleases(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields(CONTEXT, "request-1"));
        store.expireAnalysis(user);
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);

        repository.saveActionWithPrevious(user, ZeroTrustAction.ALLOW, CONTEXT);

        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(repository.getPreviousActionFromHash(user)).isEqualTo(ZeroTrustAction.CHALLENGE);
        repository.removeAllUserData(user);
    }

    @Test
    void inMemoryAStricterDecisionReplacesTheEndedActionAndALessStrictOneDoesNot() {
        assertPrecedenceOfTheEndedAction(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAStricterDecisionReplacesTheEndedActionAndALessStrictOneDoesNot() {
        assertPrecedenceOfTheEndedAction(redis());
    }

    private static void assertPrecedenceOfTheEndedAction(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields(CONTEXT, "request-1"));
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);

        assertThat(repository.writeFinalAction(user, ZeroTrustAction.ALLOW, fields(CONTEXT, "request-2")))
                .isEqualTo(FinalActionWrite.KEPT_STRICTER);
        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);

        assertThat(repository.writeFinalAction(user, ZeroTrustAction.BLOCK, fields(CONTEXT, "request-3")))
                .isEqualTo(FinalActionWrite.APPLIED);
        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
        repository.removeAllUserData(user);
    }

    @Test
    void inMemoryAStandingBlockIsNeitherReplacedNorRead() {
        assertStandingBlockStays(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAStandingBlockIsNeitherReplacedNorRead() {
        assertStandingBlockStays(redis());
    }

    private static void assertStandingBlockStays(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields(CONTEXT, "request-1"));
        repository.setBlockedFlag(user);
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);

        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.getActionFromHash(user)).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
        repository.removeAllUserData(user);
    }

    @Test
    void inMemoryALogoutKeepsTheEndedAction() {
        assertLogoutKeeps(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisALogoutKeepsTheEndedAction() {
        assertLogoutKeeps(redis());
    }

    private static void assertLogoutKeeps(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields(CONTEXT, "request-1"));
        store.expireAnalysis(user);
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);

        repository.removeLogoutData(user);

        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);
        repository.removeAllUserData(user);
    }

    /** docs/agent A5-1: an agent's ESCALATE ends under the agent's own key; the person's state is not touched. */
    @Test
    void inMemoryAnAgentsEscalateEndsUnderItsOwnKey() {
        assertAgentKey(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAnAgentsEscalateEndsUnderItsOwnKey() {
        assertAgentKey(redis());
    }

    private static void assertAgentKey(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        String person = user();
        String agentKey = person + "::agent::report-agent";
        repository.saveFinalAction(agentKey, ZeroTrustAction.ESCALATE, fields(CONTEXT, "request-1"));
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);

        assertThat(repository.getCurrentAction(agentKey, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);

        assertThat(repository.getCurrentAction(person, CONTEXT)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(repository.getActionFromHash(person)).isNull();
        repository.removeAllUserData(agentKey);
    }

    // ----- what stays as it was -----

    @ParameterizedTest
    @ValueSource(strings = {"ALLOW", "CHALLENGE", "BLOCK"})
    void inMemoryNoOtherActionIsTouched(String action) {
        assertOtherActionsStay(inMemory(), ZeroTrustAction.valueOf(action));
    }

    @ParameterizedTest
    @ValueSource(strings = {"ALLOW", "CHALLENGE", "BLOCK"})
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisNoOtherActionIsTouched(String action) {
        assertOtherActionsStay(redis(), ZeroTrustAction.valueOf(action));
    }

    private static void assertOtherActionsStay(Store store, ZeroTrustAction action) {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);
        repository.saveFinalAction(user, action, fields(CONTEXT, "request-1"));

        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(action);
        assertThat(repository.getActionFromHash(user)).isEqualTo(action);
        assertThat(repository.getPreviousActionFromHash(user)).isNull();
        repository.removeAllUserData(user);
    }

    /** allow-escalate-final-action on: no terminal action, the ESCALATE stays and the filter's promotion applies. */
    @Test
    void inMemoryWithoutATerminalActionAnEscalateStays() {
        assertEscalateStays(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisWithoutATerminalActionAnEscalateStays() {
        assertEscalateStays(redis());
    }

    private static void assertEscalateStays(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        repository.setEscalateTerminalAction(null);
        String user = user();
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields(CONTEXT, "request-1"));

        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(repository.getActionFromHash(user)).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(repository.getAnalysisData(user).action()).isEqualTo("ESCALATE");

        store.expireAnalysis(user);

        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(repository.getCurrentAction(user)).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(repository.getActionFromHash(user)).isNull();
        repository.removeAllUserData(user);
    }

    /** A terminal BLOCK needs its flag and its record: the ESCALATE stays for the access filter, which writes them. */
    @Test
    void inMemoryATerminalBlockIsLeftToTheAccessFilter() {
        assertTerminalBlockLeftToTheFilter(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisATerminalBlockIsLeftToTheAccessFilter() {
        assertTerminalBlockLeftToTheFilter(redis());
    }

    private static void assertTerminalBlockLeftToTheFilter(Store store) {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields(CONTEXT, "request-1"));
        repository.setEscalateTerminalAction(ZeroTrustAction.BLOCK);

        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(repository.getActionFromHash(user)).isEqualTo(ZeroTrustAction.ESCALATE);
        repository.removeAllUserData(user);
    }

    // ----- several at once -----

    @Test
    void inMemoryConcurrentReadersEndAnEscalateOnce() throws Exception {
        assertConcurrentReaders(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisConcurrentReadersEndAnEscalateOnce() throws Exception {
        assertConcurrentReaders(redis());
    }

    private static void assertConcurrentReaders(Store store) throws Exception {
        ZeroTrustActionRepository repository = store.repository();
        String user = user();
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields(CONTEXT, "request-1"));
        store.expireAnalysis(user);
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);

        List<Callable<ZeroTrustAction>> readers = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            readers.add(() -> repository.getCurrentAction(user, CONTEXT));
        }

        assertThat(runTogether(readers)).containsOnly(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getActionFromHash(user)).isEqualTo(ZeroTrustAction.CHALLENGE);
        repository.removeAllUserData(user);
    }

    /** The replacement checks what is stored as it writes: a decision that lands first is never overwritten. */
    @Test
    void inMemoryAConcurrentBlockIsNeverOverwritten() throws Exception {
        assertConcurrentBlock(inMemory());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAConcurrentBlockIsNeverOverwritten() throws Exception {
        assertConcurrentBlock(redis());
    }

    private static void assertConcurrentBlock(Store store) throws Exception {
        ZeroTrustActionRepository repository = store.repository();
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);
        for (int round = 0; round < 30; round++) {
            String user = user();
            repository.setEscalateTerminalAction(null);
            repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields(CONTEXT, "request-1"));
            repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);

            runTogether(List.of(
                    () -> repository.getCurrentAction(user, CONTEXT),
                    () -> repository.getCurrentAction(user, CONTEXT),
                    () -> {
                        repository.saveFinalAction(user, ZeroTrustAction.BLOCK, fields(CONTEXT, "request-2"));
                        return ZeroTrustAction.BLOCK;
                    }));

            assertThat(repository.getActionFromHash(user)).isEqualTo(ZeroTrustAction.BLOCK);
            assertThat(repository.getLastVerifiedAction(user)).isEqualTo(ZeroTrustAction.BLOCK);
            repository.removeAllUserData(user);
        }
    }

    private static List<ZeroTrustAction> runTogether(List<Callable<ZeroTrustAction>> tasks) throws Exception {
        CyclicBarrier barrier = new CyclicBarrier(tasks.size());
        ExecutorService executor = Executors.newFixedThreadPool(tasks.size());
        try {
            List<Future<ZeroTrustAction>> futures = new ArrayList<>();
            for (Callable<ZeroTrustAction> task : tasks) {
                futures.add(executor.submit(() -> {
                    barrier.await(5, TimeUnit.SECONDS);
                    return task.call();
                }));
            }
            List<ZeroTrustAction> answers = new ArrayList<>();
            for (Future<ZeroTrustAction> future : futures) {
                answers.add(future.get(10, TimeUnit.SECONDS));
            }
            return answers;
        } finally {
            executor.shutdownNow();
        }
    }
}
