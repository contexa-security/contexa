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

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.SecurityEventProcessor;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.audit.AgentDecisionRecord;
import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.handler.handler.SecurityDecisionEnforcementHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService.SyncDecisionResult;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.RedisSecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter.PersistedFinalDecision;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * PR-86: the answer of a request decided in place, through the real agent, enforcement and store, in memory and on the
 * real Redis ({@code CONTEXA_BACKLOG_REDIS_PORT}, unique keys). A restriction stored for the user while a request was
 * decided answers that request, whichever session it came from; what is not stricter changes nothing.
 */
class StoredRestrictionAnswersDecidedRequestTest {

    private static final String REDIS_PORT = "CONTEXA_BACKLOG_REDIS_PORT";
    private static final String SLOW_SESSION = "session-slow";
    private static final String QUICK_SESSION = "session-quick";
    private static final String CLIENT_IP = "203.0.113.10";
    private static final String USER_AGENT = "JUnit";
    private static final int ROUNDS = 100;

    private static LettuceConnectionFactory factory;
    private static RedisTemplate<String, Object> objects;
    private static StringRedisTemplate strings;

    /** Where the decisions are stored. */
    enum Store {
        MEMORY, REDIS
    }

    static List<Store> stores() {
        String port = System.getenv(REDIS_PORT);
        return port != null && port.matches("[0-9]+") ? List.of(Store.MEMORY, Store.REDIS) : List.of(Store.MEMORY);
    }

    @BeforeAll
    static void connect() {
        String port = System.getenv(REDIS_PORT);
        if (port == null || !port.matches("[0-9]+")) {
            return;
        }
        factory = new LettuceConnectionFactory("127.0.0.1", Integer.parseInt(port));
        factory.afterPropertiesSet();
        objects = RedisTestTemplates.newProductionAlignedRedisTemplate(factory);
        strings = RedisTestTemplates.newStringRedisTemplate(factory);
    }

    @AfterAll
    static void close() {
        if (factory != null) {
            factory.destroy();
        }
    }

    @AfterEach
    void forgetTheRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    @ParameterizedTest
    @MethodSource("stores")
    @DisplayName("PR-86: a slow ALLOW is answered by the CHALLENGE stored while it was decided, and the CHALLENGE stands")
    void aSlowAllowIsAnsweredByTheChallengeStoredWhileItWasDecided(Store store) {
        Pipeline pipeline = new Pipeline(store);
        String user = user();
        String quick = pipeline.decision("CHALLENGE");
        String slow = pipeline.decision("ALLOW", () -> pipeline.analyze(user, QUICK_SESSION, quick));

        SyncDecisionResult answer = pipeline.analyze(user, SLOW_SESSION, slow);

        assertThat(answer.action()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(pipeline.outcome(slow)).isEqualTo(AgentDecisionRecord.KEPT_STRICTER);
        assertThat(pipeline.actions.getCurrentAction(user, context(SLOW_SESSION))).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(pipeline.actions.getCurrentAction(user, context(QUICK_SESSION))).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(answer.analysisData().action()).as("what the answer reports is the decision in force")
                .isEqualTo(ZeroTrustAction.CHALLENGE.name());
        pipeline.actions.removeAllUserData(user);
    }

    @ParameterizedTest
    @MethodSource("stores")
    @DisplayName("PR-86: an ESCALATE or a BLOCK stored while a request was decided answers its ALLOW")
    void aStrongerRestrictionStoredWhileItWasDecidedAnswersToo(Store store) {
        for (ZeroTrustAction restriction : List.of(ZeroTrustAction.ESCALATE, ZeroTrustAction.BLOCK)) {
            Pipeline pipeline = new Pipeline(store);
            String user = user();
            String quick = pipeline.decision(restriction.name());
            String slow = pipeline.decision("ALLOW", () -> pipeline.analyze(user, QUICK_SESSION, quick));

            assertThat(pipeline.analyze(user, SLOW_SESSION, slow).action()).isEqualTo(restriction);

            pipeline.actions.removeAllUserData(user);
        }
    }

    @ParameterizedTest
    @MethodSource("stores")
    @DisplayName("PR-86: of two restrictions the stricter stored one answers, a request's own stricter one stays")
    void ofTwoRestrictionsTheStricterAnswers(Store store) {
        Pipeline pipeline = new Pipeline(store);
        String keptOut = user();
        String block = pipeline.decision("BLOCK");
        String challenge = pipeline.decision("CHALLENGE", () -> pipeline.analyze(keptOut, QUICK_SESSION, block));
        assertThat(pipeline.analyze(keptOut, SLOW_SESSION, challenge).action()).isEqualTo(ZeroTrustAction.BLOCK);
        pipeline.actions.removeAllUserData(keptOut);

        String stricterOwn = user();
        String quickChallenge = pipeline.decision("CHALLENGE");
        String ownBlock = pipeline.decision("BLOCK", () -> pipeline.analyze(stricterOwn, QUICK_SESSION, quickChallenge));
        assertThat(pipeline.analyze(stricterOwn, SLOW_SESSION, ownBlock).action()).isEqualTo(ZeroTrustAction.BLOCK);
        pipeline.actions.removeAllUserData(stricterOwn);
    }

    @ParameterizedTest
    @MethodSource("stores")
    @DisplayName("PR-86: a restriction stored right after a request's ALLOW was written answers it before it is released")
    void aRestrictionStoredAfterTheWriteAnswersBeforeTheRelease(Store store) {
        Pipeline pipeline = new Pipeline(store);
        String user = user();
        String quick = pipeline.decision("CHALLENGE");
        String slow = pipeline.decision("ALLOW");
        pipeline.afterEnforcement.put(slow, () -> pipeline.analyze(user, QUICK_SESSION, quick));

        assertThat(pipeline.analyze(user, SLOW_SESSION, slow).action()).isEqualTo(ZeroTrustAction.CHALLENGE);

        pipeline.actions.removeAllUserData(user);
    }

    @ParameterizedTest
    @MethodSource("stores")
    @DisplayName("PR-86: the two calls at the same moment, many times over: the one that ends last never passes")
    void theCallThatEndsAfterTheRestrictionNeverPasses(Store store) throws Exception {
        Pipeline pipeline = new Pipeline(store);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            for (int round = 0; round < ROUNDS; round++) {
                String user = user();
                CountDownLatch stored = new CountDownLatch(1);
                String quick = pipeline.decision("CHALLENGE");
                String slow = pipeline.decision("ALLOW", () -> await(stored));
                Future<SyncDecisionResult> slowCall = pool.submit(() -> pipeline.analyze(user, SLOW_SESSION, slow));
                Future<SyncDecisionResult> quickCall = pool.submit(() -> {
                    SyncDecisionResult answer = pipeline.analyze(user, QUICK_SESSION, quick);
                    stored.countDown();
                    return answer;
                });

                assertThat(quickCall.get(30, TimeUnit.SECONDS).action()).as("round %d", round)
                        .isEqualTo(ZeroTrustAction.CHALLENGE);
                assertThat(slowCall.get(30, TimeUnit.SECONDS).action()).as("round %d", round)
                        .isEqualTo(ZeroTrustAction.CHALLENGE);
                pipeline.actions.removeAllUserData(user);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @ParameterizedTest
    @MethodSource("stores")
    @DisplayName("PR-86: with nothing stored, or the ALLOW of another session stored, an ALLOW stays an ALLOW")
    void whatIsNotStricterChangesNothing(Store store) {
        Pipeline pipeline = new Pipeline(store);
        String nothingStored = user();
        assertThat(pipeline.analyze(nothingStored, SLOW_SESSION, pipeline.decision("ALLOW")).action())
                .isEqualTo(ZeroTrustAction.ALLOW);
        pipeline.actions.removeAllUserData(nothingStored);

        String otherSession = user();
        String quick = pipeline.decision("ALLOW");
        String slow = pipeline.decision("ALLOW", () -> pipeline.analyze(otherSession, QUICK_SESSION, quick));
        assertThat(pipeline.analyze(otherSession, SLOW_SESSION, slow).action()).isEqualTo(ZeroTrustAction.ALLOW);
        pipeline.actions.removeAllUserData(otherSession);

        String ownChallenge = user();
        assertThat(pipeline.analyze(ownChallenge, SLOW_SESSION, pipeline.decision("CHALLENGE")).action())
                .isEqualTo(ZeroTrustAction.CHALLENGE);
        pipeline.actions.removeAllUserData(ownChallenge);
    }

    @ParameterizedTest
    @MethodSource("stores")
    @DisplayName("PR-86: a CHALLENGE the step-up released before the decision landed is no restriction any more")
    void aReleasedChallengeDoesNotAnswer(Store store) {
        Pipeline pipeline = new Pipeline(store);
        String user = user();
        String quick = pipeline.decision("CHALLENGE");
        String slow = pipeline.decision("ALLOW", () -> {
            pipeline.analyze(user, QUICK_SESSION, quick);
            pipeline.actions.saveActionWithPrevious(user, ZeroTrustAction.ALLOW, context(SLOW_SESSION));
        });

        assertThat(pipeline.analyze(user, SLOW_SESSION, slow).action()).isEqualTo(ZeroTrustAction.ALLOW);

        pipeline.actions.removeAllUserData(user);
    }

    @ParameterizedTest
    @MethodSource("stores")
    @DisplayName("PR-86: inside a shadow boundary the analysed request is answered as allowed, whatever is stored")
    void aShadowBoundaryEnforcesNothing(Store store) {
        Pipeline pipeline = new Pipeline(store);
        String user = user();
        pipeline.analyze(user, QUICK_SESSION, pipeline.decision("CHALLENGE"));

        SyncDecisionResult answer = pipeline.analyze(event(user, SLOW_SESSION, pipeline.decision("CHALLENGE"),
                Map.of("decisionBoundaryMode", "SHADOW")));

        assertThat(answer.action()).isEqualTo(ZeroTrustAction.ALLOW);
        pipeline.actions.removeAllUserData(user);
    }

    @ParameterizedTest
    @MethodSource("stores")
    @DisplayName("PR-86: a failed analysis decides nothing: the request stays undecided, or is answered by what is stored")
    void aFailedAnalysisKeepsTheAnswerOfTheStore(Store store) {
        Pipeline pipeline = new Pipeline(store);
        String user = user();
        String failed = pipeline.failedDecision();

        assertThat(pipeline.analyze(user, SLOW_SESSION, failed).action()).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);

        pipeline.analyze(user, QUICK_SESSION, pipeline.decision("CHALLENGE"));
        assertThat(pipeline.analyze(user, SLOW_SESSION, pipeline.failedDecision()).action())
                .isEqualTo(ZeroTrustAction.CHALLENGE);
        pipeline.actions.removeAllUserData(user);
    }

    @ParameterizedTest
    @MethodSource("stores")
    @DisplayName("docs/agent A5-2: a confirmed request of an agent answers the CHALLENGE in force, not an ESCALATE or a BLOCK")
    void aConfirmedAgentRequestAnswersOnlyTheChallenge(Store store) {
        confirmTheRequest();
        for (ZeroTrustAction stored : List.of(ZeroTrustAction.CHALLENGE, ZeroTrustAction.ESCALATE, ZeroTrustAction.BLOCK)) {
            Pipeline pipeline = new Pipeline(store);
            String user = user();
            String quick = pipeline.decision(stored.name());
            String slow = pipeline.decision("ALLOW",
                    () -> pipeline.analyze(event(user, QUICK_SESSION, quick, agent("report-agent"))));

            ZeroTrustAction answer = pipeline.analyze(event(user, SLOW_SESSION, slow, agent("report-agent"))).action();

            assertThat(answer).as("confirmed under a stored %s", stored)
                    .isEqualTo(stored == ZeroTrustAction.CHALLENGE ? ZeroTrustAction.ALLOW : stored);
            pipeline.actions.removeAllUserData(LearningSubject.agentKey(user, "report-agent"));
        }
    }

    @ParameterizedTest
    @MethodSource("stores")
    @DisplayName("docs/agent A5-1: an agent is answered by its own restriction and the person's BLOCK, not by the person's CHALLENGE")
    void anAgentAndItsPersonKeepTheirOwnDecisions(Store store) {
        Pipeline pipeline = new Pipeline(store);
        String user = user();
        String personChallenge = pipeline.decision("CHALLENGE");
        String agentAllow = pipeline.decision("ALLOW", () -> pipeline.analyze(user, QUICK_SESSION, personChallenge));
        assertThat(pipeline.analyze(event(user, SLOW_SESSION, agentAllow, agent("report-agent"))).action())
                .as("the person's CHALLENGE stops the person, not the agent acting for them")
                .isEqualTo(ZeroTrustAction.ALLOW);
        pipeline.actions.removeAllUserData(user);
        pipeline.actions.removeAllUserData(LearningSubject.agentKey(user, "report-agent"));

        String blocked = user();
        String personBlock = pipeline.decision("BLOCK");
        String blockedAgentAllow = pipeline.decision("ALLOW", () -> pipeline.analyze(blocked, QUICK_SESSION, personBlock));
        assertThat(pipeline.analyze(event(blocked, SLOW_SESSION, blockedAgentAllow, agent("report-agent"))).action())
                .as("a blocked person's delegation stops with the account")
                .isEqualTo(ZeroTrustAction.BLOCK);
        pipeline.actions.removeAllUserData(blocked);
        pipeline.actions.removeAllUserData(LearningSubject.agentKey(blocked, "report-agent"));
    }

    @ParameterizedTest
    @MethodSource("stores")
    @DisplayName("PR-86: a retry that restores a persisted ALLOW is answered by the restriction in force, as before")
    void aRestoredAllowIsAnsweredByTheRestrictionInForce(Store store) {
        Pipeline pipeline = new Pipeline(store);
        String user = user();
        pipeline.analyze(user, QUICK_SESSION, pipeline.decision("CHALLENGE"));
        String restored = pipeline.decision("ALLOW");
        pipeline.persisted.put(user, new PersistedFinalDecision(UUID.randomUUID().toString(), null, user, "ALLOW",
                context(SLOW_SESSION), UUID.randomUUID().toString(), UUID.randomUUID().toString(), null, null, "persisted"));

        assertThat(pipeline.analyze(user, SLOW_SESSION, restored).action()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(pipeline.analysed).as("the retry restored the decision instead of asking again").doesNotContain(restored);
        pipeline.actions.removeAllUserData(user);
    }

    private static void await(CountDownLatch latch) {
        try {
            assertThat(latch.await(30, TimeUnit.SECONDS)).isTrue();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(interrupted);
        }
    }

    private static void confirmTheRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setAttribute(BridgeRequestAttributes.AGENT_CONFIRMATION, "confirmation-1");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    private static String user() {
        return "restriction-" + UUID.randomUUID();
    }

    private static String context(String session) {
        return SessionFingerprintUtil.generateContextBindingHash(session, CLIENT_IP, USER_AGENT);
    }

    private static Map<String, Object> agent(String agentId) {
        return Map.of("executionSubjectKind", "DELEGATED_AGENT", "agentId", agentId);
    }

    /** The request {@code decision} names, by a user in a session; {@code facts} are what the publisher adds. */
    private static ZeroTrustSpringEvent event(String user, String session, String decision, Map<String, Object> facts) {
        Map<String, Object> payload = new LinkedHashMap<>(facts);
        payload.put("httpMethod", "GET");
        payload.put("decisionName", decision);
        return ZeroTrustSpringEvent.builder(StoredRestrictionAnswersDecidedRequestTest.class)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId(user)
                .sessionId(session)
                .clientIp(CLIENT_IP)
                .userAgent(USER_AGENT)
                .resource("/orders/" + decision)
                .payload(payload)
                .build();
    }

    /** A controlled analysis in front of the real enforcement, agent, service and store. */
    private static final class Pipeline {

        final ZeroTrustActionRepository actions;
        final Map<String, ProcessingResult> resultOf = new ConcurrentHashMap<>();
        final Map<String, Runnable> whileDecided = new ConcurrentHashMap<>();
        final Map<String, Runnable> afterEnforcement = new ConcurrentHashMap<>();
        final Map<String, PersistedFinalDecision> persisted = new ConcurrentHashMap<>();
        final Map<String, String> outcomes = new ConcurrentHashMap<>();
        final List<String> analysed = new ArrayList<>();
        final SynchronousProtectableDecisionService service;

        Pipeline(Store store) {
            actions = store == Store.MEMORY ? new InMemoryZeroTrustActionRepository()
                    : new ZeroTrustActionRedisRepository(objects, strings);
            SecurityContextDataStore data = store == Store.MEMORY ? new InMemorySecurityContextDataStore()
                    : new RedisSecurityContextDataStore(objects);
            SecurityZeroTrustProperties mode = new SecurityZeroTrustProperties();
            mode.setMode(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
            AiSecurityDecisionObservationWriter writer = mock(AiSecurityDecisionObservationWriter.class);
            when(writer.recordDecision(any(), any(), any())).thenAnswer(call -> UUID.randomUUID().toString());
            when(writer.findFinalDecision(anyString())).thenAnswer(call -> persisted.values().stream().findFirst().orElse(null));
            SecurityDecisionEnforcementHandler enforcement = new SecurityDecisionEnforcementHandler(actions, null,
                    mock(IBlockedUserRecorder.class), new InMemoryBlockingSignalBroadcaster(), mode, Runnable::run,
                    () -> writer, data);
            SecurityPlaneProperties properties = new SecurityPlaneProperties();
            properties.getAgent().setAutoStart(false);
            SecurityPlaneAgent agent = new SecurityPlaneAgent(mock(SecurityMonitoringService.class), data, null,
                    new SecurityEventProcessor(List.of(analysis(), enforcement, closing()), "restriction-test"),
                    properties, Runnable::run);
            agent.setZeroTrustActionRepository(actions);
            agent.setAiSecurityDecisionObservationWriterSupplier(() -> writer);
            agent.setDecisionEnforcementHandlerSupplier(() -> enforcement);
            ZeroTrustEventListener listener = mock(ZeroTrustEventListener.class);
            when(listener.generateAuthorizationContextBindingHash(any())).thenAnswer(call -> {
                ZeroTrustSpringEvent event = call.getArgument(0);
                return context(event.getSessionId());
            });
            when(listener.shouldPublishSynchronousAuthorizationEvent(any())).thenReturn(true);
            service = new SynchronousProtectableDecisionService(mock(ZeroTrustEventPublisher.class), listener, agent, actions);
        }

        private SecurityEventHandler analysis() {
            SecurityEventHandler analysis = mock(SecurityEventHandler.class);
            when(analysis.getOrder()).thenReturn(0);
            when(analysis.getName()).thenReturn("ControlledAnalysis");
            when(analysis.canHandle(any())).thenReturn(true);
            when(analysis.handle(any())).thenAnswer(call -> {
                SecurityEventContext context = call.getArgument(0);
                String decision = name(context.getSecurityEvent());
                synchronized (analysed) {
                    analysed.add(decision);
                }
                whileDecided.getOrDefault(decision, () -> { }).run();
                context.addMetadata("processingResult", resultOf.get(decision));
                return true;
            });
            return analysis;
        }

        private SecurityEventHandler closing() {
            SecurityEventHandler closing = mock(SecurityEventHandler.class);
            when(closing.getOrder()).thenReturn(100);
            when(closing.getName()).thenReturn("AfterEnforcement");
            when(closing.canHandle(any())).thenReturn(true);
            when(closing.handle(any())).thenAnswer(call -> {
                SecurityEventContext context = call.getArgument(0);
                SecurityEvent event = context.getSecurityEvent();
                Object outcome = event.getMetadata().get(AgentDecisionRecord.ENFORCEMENT_OUTCOME);
                if (outcome != null) {
                    outcomes.put(name(event), outcome.toString());
                }
                afterEnforcement.getOrDefault(name(event), () -> { }).run();
                return true;
            });
            return closing;
        }

        private static String name(SecurityEvent event) {
            return event.getMetadata().get("decisionName").toString();
        }

        String decision(String action) {
            return decision(action, () -> { });
        }

        /** Names a decision of this action; {@code during} runs while it is decided. */
        String decision(String action, Runnable during) {
            String name = "decision-" + UUID.randomUUID();
            resultOf.put(name, ProcessingResult.builder().success(true).action(action).reasoning("Controlled").build());
            whileDecided.put(name, during);
            return name;
        }

        String failedDecision() {
            String name = "decision-" + UUID.randomUUID();
            resultOf.put(name, ProcessingResult.failure(ProcessingResult.ProcessingPath.COLD_PATH, "AI analysis failed"));
            return name;
        }

        String outcome(String decision) {
            return outcomes.get(decision);
        }

        SyncDecisionResult analyze(String user, String session, String decision) {
            return analyze(event(user, session, decision, new HashMap<>()));
        }

        SyncDecisionResult analyze(ZeroTrustSpringEvent event) {
            return service.analyze(event);
        }
    }
}
