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
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository.ZeroTrustAnalysisData;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.testsupport.AdjustableClock;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * QF-47, QF-48 (DD-66): the in-memory decision store answers every read as ZeroTrustActionRedisRepository answers it
 * for the same state. Both repositories receive the same writes; time passes for both alike (the in-memory clock moves
 * and every Redis key with a TTL loses as much of it, as Redis lets it expire). An analysis past its TTL is then absent
 * in both, as its Redis key is gone.
 *
 * <p>Z-16 (1-a): outside a request too, a decision past its TTL lapses in both, as {@link ZeroTrustActionPrecedence}
 * and ZeroTrustActionStorageReproductionTest describe (an ALLOW or CHALLENGE lapses with its TTL; only an unresolved
 * ESCALATE stays). Inside a request both answer through the request's context binding.</p>
 */
@EnabledIf("io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepositoryRedisReadContractTest#isLocalRedisAvailable")
class InMemoryZeroTrustActionRepositoryRedisReadContractTest {

    private static final String REDIS_HOST =
            System.getProperty("contexa.test.redis.host",
                    System.getenv().getOrDefault("CONTEXA_TEST_REDIS_HOST", "localhost"));
    private static final int REDIS_PORT = Integer.parseInt(
            System.getProperty("contexa.test.redis.port",
                    System.getenv().getOrDefault("CONTEXA_TEST_REDIS_PORT", "6379")));
    private static final Duration FAIL_COUNT_TTL = Duration.ofSeconds(2);

    private static LettuceConnectionFactory connectionFactory;
    private static RedisTemplate<String, Object> redisTemplate;
    private static StringRedisTemplate strings;

    private final AdjustableClock clock = new AdjustableClock();
    private final String contextA = contextOf(newRequest("session-a"));
    private final String contextB = contextOf(newRequest("session-b"));
    private InMemoryZeroTrustActionRepository memory;
    private ZeroTrustActionRedisRepository redis;

    static boolean isLocalRedisAvailable() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(REDIS_HOST, REDIS_PORT), 500);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    @BeforeAll
    static void connect() {
        connectionFactory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(REDIS_HOST, REDIS_PORT));
        connectionFactory.afterPropertiesSet();
        redisTemplate = RedisTestTemplates.newProductionAlignedRedisTemplate(connectionFactory);
        strings = RedisTestTemplates.newStringRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void close() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @BeforeEach
    void setUp() {
        strings.execute((RedisCallback<Void>) connection -> {
            connection.serverCommands().flushDb();
            return null;
        });
        memory = new InMemoryZeroTrustActionRepository(FAIL_COUNT_TTL, clock);
        redis = new ZeroTrustActionRedisRepository(redisTemplate, strings, FAIL_COUNT_TTL);
    }

    @AfterEach
    void leaveRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void aUserWithoutStateReadsTheSame() {
        assertSameReads("nobody");
    }

    @ParameterizedTest
    @ValueSource(strings = {"ALLOW", "CHALLENGE", "ESCALATE", "BLOCK", "PENDING_ANALYSIS"})
    void aDecisionInItsTtlReadsTheSame(String action) {
        both(repository -> repository.saveFinalAction("alice", ZeroTrustAction.valueOf(action), fields(contextA)));

        assertSameReads("alice");
    }

    @Test
    void aBlockWithItsFlagReadsTheSameBeforeAndAfterItsLastVerifiedDay() {
        both(repository -> {
            repository.saveFinalAction("alice", ZeroTrustAction.BLOCK, fields(contextA));
            repository.setBlockedFlag("alice");
        });
        assertSameReads("alice");

        elapse(Duration.ofHours(25));

        assertSameReads("alice");
    }

    @Test
    void anAllowPastItsTtlReadsTheSame() {
        both(repository -> repository.saveFinalAction("alice", ZeroTrustAction.ALLOW, fields(contextA)));

        elapse(Duration.ofSeconds(20));

        assertSameReads("alice");
    }

    @Test
    void aChallengePastItsTtlReadsTheSame() {
        both(repository -> repository.saveFinalAction("alice", ZeroTrustAction.CHALLENGE, fields(contextA)));

        elapse(Duration.ofMinutes(31));

        assertSameReads("alice");
    }

    @Test
    void anEscalatePastItsTtlStillReadsAsEscalateAlike() {
        both(repository -> repository.saveFinalAction("alice", ZeroTrustAction.ESCALATE, fields(contextA)));

        elapse(Duration.ofMinutes(6));

        assertSameReads("alice");
    }

    @Test
    void aDecisionPastItsLastVerifiedDayReadsTheSame() {
        both(repository -> repository.saveFinalAction("alice", ZeroTrustAction.CHALLENGE, fields(contextA)));

        elapse(Duration.ofHours(25));

        assertSameReads("alice");
    }

    @Test
    void aDecisionWrittenAfterAnExpiredOneCarriesNoPreviousAction() {
        both(repository -> repository.saveFinalAction("alice", ZeroTrustAction.CHALLENGE, fields(contextA)));
        elapse(Duration.ofMinutes(31));

        both(repository -> repository.saveFinalAction("alice", ZeroTrustAction.ALLOW, fields(contextB)));

        assertSameReads("alice");
    }

    @Test
    void aReleaseWithoutContextKeepsEveryFieldOfTheLiveAnalysis() {
        both(repository -> {
            repository.saveFinalAction("alice", ZeroTrustAction.CHALLENGE, fields(contextA));
            repository.saveActionWithPrevious("alice", ZeroTrustAction.ALLOW);
        });

        assertSameReads("alice");
    }

    @Test
    void aReleaseInAContextKeepsTheOtherFieldsOfTheLiveAnalysis() {
        both(repository -> {
            repository.saveFinalAction("alice", ZeroTrustAction.CHALLENGE, fields(contextA));
            repository.saveActionWithPrevious("alice", ZeroTrustAction.ALLOW, contextB);
        });

        assertSameReads("alice");
    }

    @Test
    void aReleaseWithANullContextKeepsTheContextOfTheLiveAnalysis() {
        both(repository -> {
            repository.saveFinalAction("alice", ZeroTrustAction.CHALLENGE, fields(contextA));
            repository.saveActionWithPrevious("alice", ZeroTrustAction.ALLOW, null);
        });

        assertSameReads("alice");
    }

    @Test
    void aFirstReleaseRecordsPendingAnalysisAsThePreviousAction() {
        both(repository -> repository.saveActionWithPrevious("alice", ZeroTrustAction.ALLOW));

        assertSameReads("alice");
    }

    @Test
    void aReleaseAfterAnExpiredDecisionInheritsNothingOfIt() {
        both(repository -> repository.saveFinalAction("alice", ZeroTrustAction.CHALLENGE, fields(contextA)));
        elapse(Duration.ofMinutes(31));

        both(repository -> repository.saveActionWithPrevious("alice", ZeroTrustAction.ALLOW, contextB));

        assertSameReads("alice");
    }

    @Test
    void anApprovedOverrideKeepsThePreviousActionAndTheFieldsOfTheLiveAnalysis() {
        both(repository -> {
            repository.saveFinalAction("alice", ZeroTrustAction.ESCALATE, fields(contextA));
            repository.saveFinalAction("alice", ZeroTrustAction.BLOCK, fields(contextA));
            repository.setBlockedFlag("alice");
            repository.approveOverrideAtomically("alice", ZeroTrustAction.ALLOW);
        });

        assertSameReads("alice");
    }

    @Test
    void aLogoutOfAnUnrestrictedUserLeavesTheRetryAndAuditMarkers() {
        both(repository -> {
            repository.saveFinalAction("alice", ZeroTrustAction.ALLOW, fields(contextA));
            repository.markDecisionAuditPending("alice", contextA, Duration.ofMinutes(1));
            repository.setEscalateRetry("alice", Duration.ofMinutes(1));
            repository.incrementBlockMfaFailCount("alice");
            repository.removeLogoutData("alice");
        });

        assertSameReads("alice");
    }

    /** Z-16 (1-b): an ESCALATE whose analysis expired unresolved still reads as ESCALATE, so a logout keeps it. */
    @Test
    void aLogoutKeepsAnUnresolvedEscalateAlike() {
        both(repository -> repository.saveFinalAction("alice", ZeroTrustAction.ESCALATE, fields(contextA)));
        elapse(Duration.ofMinutes(6));

        both(repository -> repository.removeLogoutData("alice"));

        assertSameReads("alice");
        assertThat(redis.getCurrentAction("alice", contextB)).isEqualTo(ZeroTrustAction.ESCALATE);
    }

    @ParameterizedTest
    @ValueSource(strings = {"CHALLENGE", "ESCALATE", "BLOCK"})
    void aLogoutKeepsALiveRestriction(String action) {
        both(repository -> {
            repository.saveFinalAction("alice", ZeroTrustAction.valueOf(action), fields(contextA));
            repository.setBlockMfaPending("alice");
            repository.removeLogoutData("alice");
        });

        assertSameReads("alice");
    }

    @Test
    void aFailCountKeepsCountingWhileFailuresContinue() {
        both(repository -> repository.incrementBlockMfaFailCount("alice"));
        elapse(Duration.ofMillis(1_500));
        both(repository -> repository.incrementBlockMfaFailCount("alice"));
        elapse(Duration.ofMillis(1_000));

        assertSameReads("alice");
    }

    @Test
    void anExpiredEscalateRetryIsSetAgain() throws InterruptedException {
        both(repository -> repository.setEscalateRetry("alice", Duration.ofMillis(200)));
        Thread.sleep(400);

        both(repository -> repository.setEscalateRetry("alice", Duration.ofMinutes(5)));

        assertSameReads("alice");
    }

    @Test
    void aBlankUserIdIsNeitherStoredNorRead() {
        both(repository -> {
            repository.saveFinalAction(" ", ZeroTrustAction.CHALLENGE, fields(contextA));
            repository.saveActionWithPrevious(" ", ZeroTrustAction.ALLOW);
            repository.setBlockedFlag(" ");
            repository.setBlockMfaPending(" ");
            repository.incrementBlockMfaFailCount(" ");
            repository.setEscalateRetry(" ", Duration.ofMinutes(1));
            repository.markDecisionAuditPending(" ", contextA, Duration.ofMinutes(1));
        });

        assertSameReads(" ");
    }

    private void both(Consumer<ZeroTrustActionRepository> step) {
        step.accept(memory);
        step.accept(redis);
    }

    /** Time passes for both: the in-memory clock moves on, and every Redis key with a TTL loses as much of it. */
    private void elapse(Duration elapsed) {
        clock.advance(elapsed);
        for (String key : strings.keys("*")) {
            Long remainingMs = strings.getExpire(key, TimeUnit.MILLISECONDS);
            if (remainingMs == null || remainingMs < 0) {
                continue;
            }
            if (remainingMs <= elapsed.toMillis()) {
                strings.delete(key);
            } else {
                strings.expire(key, remainingMs - elapsed.toMillis(), TimeUnit.MILLISECONDS);
            }
        }
    }

    private void assertSameReads(String user) {
        assertThat(reads(memory, user))
                .as("in-memory reads of %s, Redis reads on the right", user)
                .isEqualTo(reads(redis, user));
    }

    private Map<String, Object> reads(ZeroTrustActionRepository repository, String user) {
        Map<String, Object> reads = new LinkedHashMap<>();
        reads.put("getCurrentAction(user, contextA)", repository.getCurrentAction(user, contextA));
        reads.put("getCurrentAction(user, contextB)", repository.getCurrentAction(user, contextB));
        reads.put("getCurrentAction(user, null)", repository.getCurrentAction(user, null));
        reads.put("getCurrentAction(user) in a request of contextA",
                inRequest("session-a", () -> repository.getCurrentAction(user)));
        reads.put("getCurrentAction(user) in a request of contextB",
                inRequest("session-b", () -> repository.getCurrentAction(user)));
        reads.put("getCurrentAction(user) outside a request", repository.getCurrentAction(user));
        reads.put("getAnalysisData", analysisView(repository.getAnalysisData(user)));
        reads.put("getActionFromHash", repository.getActionFromHash(user));
        reads.put("getPreviousActionFromHash", repository.getPreviousActionFromHash(user));
        reads.put("getLastVerifiedAction", repository.getLastVerifiedAction(user));
        reads.put("isStale(user, 1 h)", repository.isStale(user, Duration.ofHours(1).toMillis()));
        reads.put("getBlockMfaFailCount", repository.getBlockMfaFailCount(user));
        reads.put("isBlockMfaPending", repository.isBlockMfaPending(user));
        reads.put("hasEscalateRetry", repository.hasEscalateRetry(user));
        reads.put("isDecisionAuditPending(user, contextA)", repository.isDecisionAuditPending(user, contextA));
        return reads;
    }

    /** The analysis as read; the time it was written is compared by its presence, each store stamps its own. */
    private static Map<String, Object> analysisView(ZeroTrustAnalysisData data) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("action", data.action());
        view.put("riskScore", data.riskScore());
        view.put("confidence", data.confidence());
        view.put("threatEvidence", data.threatEvidence());
        view.put("analysisDepth", data.analysisDepth());
        view.put("updatedAt present", data.updatedAt() != null);
        view.put("reasoning", data.reasoning());
        view.put("reasoningSummary", data.reasoningSummary());
        view.put("requestId", data.requestId());
        view.put("contextBindingHash", data.contextBindingHash());
        view.put("llmProposedAction", data.llmProposedAction());
        return view;
    }

    private static <T> T inRequest(String session, Supplier<T> read) {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(newRequest(session)));
        try {
            return read.get();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    private static MockHttpServletRequest newRequest(String session) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/orders");
        request.setRequestedSessionId(session);
        request.setRemoteAddr("10.0.0.7");
        request.addHeader("User-Agent", "contract-test");
        return request;
    }

    private static String contextOf(MockHttpServletRequest request) {
        return SessionFingerprintUtil.generateContextBindingHash(request);
    }

    private static Map<String, Object> fields(String contextBindingHash) {
        Map<String, Object> fields = new HashMap<>();
        fields.put("contextBindingHash", contextBindingHash);
        fields.put("observationId", UUID.randomUUID().toString());
        fields.put("processingGeneration", UUID.randomUUID().toString());
        fields.put("riskScore", 0.42d);
        fields.put("confidence", 0.9d);
        fields.put("threatEvidence", "new device");
        fields.put("analysisDepth", 2);
        fields.put("reasoning", "the request came from a new device");
        fields.put("reasoningSummary", "new device");
        fields.put("requestId", "request-1");
        fields.put("llmProposedAction", "CHALLENGE");
        return fields;
    }
}
