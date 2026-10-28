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
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.agent.AgentAllowReuse;
import io.contexa.contexacore.autonomous.agent.AgentDecisionFlights;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.execution.ZeroTrustAccessDeniedException;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService.AsyncProtectableGate;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService.SyncDecisionResult;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * RL-12 at the service: one agent's requests that come in numbers, through the real flights and the real allow-reuse
 * anchors, with a scripted analysis and a stored state that the analysis writes the way the engine's enforcement does.
 * What is checked is structure: analyses started, analyses running at once, the answer of each request, and how the
 * requests answered without an analysis are recorded.
 */
class AgentFlightsServiceTest {

    private static final String USER = "agent-key";
    private static final String CONTEXT = "ctx-hash";

    private final ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
    private final ZeroTrustEventListener listener = mock(ZeroTrustEventListener.class);
    private final SecurityPlaneAgent agent = mock(SecurityPlaneAgent.class);
    private final ZeroTrustActionRepository repository = mock(ZeroTrustActionRepository.class);
    private final UnanalysedRequestRecorder recorder = mock(UnanalysedRequestRecorder.class);
    private final MethodInvocation invocation = mock(MethodInvocation.class);
    private final UsernamePasswordAuthenticationToken authentication =
            new UsernamePasswordAuthenticationToken("alice", "n/a", List.of());

    /** The decision stored for the agent, as the engine's enforcement leaves it. */
    private final AtomicReference<ZeroTrustAction> stored = new AtomicReference<>(ZeroTrustAction.PENDING_ANALYSIS);
    /** The request the calling thread makes. */
    private final ThreadLocal<Map<String, Object>> current = new ThreadLocal<>();
    private final AtomicInteger started = new AtomicInteger();
    private final AtomicInteger running = new AtomicInteger();
    private final AtomicInteger mostAtOnce = new AtomicInteger();
    private volatile long analysisMillis = 60;
    private volatile Function<Integer, ZeroTrustAction> verdict = order -> ZeroTrustAction.ALLOW;
    private volatile Runnable beforeAnswer = () -> { };

    private SynchronousProtectableDecisionService service(boolean flightsOn, int inFlight, int queue, long waitMillis,
                                                          int passBudget) {
        SynchronousProtectableDecisionService service =
                new SynchronousProtectableDecisionService(publisher, listener, agent, repository);
        service.setUnanalysedRequestRecorder(recorder);
        service.setAgentAllowReuse(new AgentAllowReuse(10, 3, 1, null));
        service.setAgentDecisionFlights(new AgentDecisionFlights(new AgentDecisionFlights.Settings(flightsOn,
                inFlight, queue, Duration.ofMillis(waitMillis), passBudget, Set.of(ActionFamily.READ))));
        when(publisher.buildMethodAuthorizationEvent(any(MethodInvocation.class), any(), eq(true), isNull()))
                .thenAnswer(call -> event(current.get()));
        when(listener.generateAuthorizationContextBindingHash(any())).thenReturn(CONTEXT);
        // a restriction in force answers without an analysis, as the listener decides
        when(listener.shouldPublishSynchronousAuthorizationEvent(any())).thenAnswer(call -> !restriction(stored.get()));
        when(repository.getCurrentAction(eq(USER), eq(CONTEXT))).thenAnswer(call -> stored.get());
        when(repository.getAnalysisData(USER)).thenReturn(ZeroTrustActionRepository.ZeroTrustAnalysisData.pending());
        when(agent.processSecurityEvent(any(SecurityEvent.class))).thenAnswer(call -> {
            int order = started.incrementAndGet();
            int now = running.incrementAndGet();
            mostAtOnce.accumulateAndGet(now, Math::max);
            try {
                Thread.sleep(analysisMillis);
                ZeroTrustAction action = verdict.apply(order);
                beforeAnswer.run();
                // The enforcement writes the final decision unless a restriction in force is stricter.
                stored.updateAndGet(old -> restriction(old) && !restriction(action) ? old : action);
                SecurityEventContext context = mock(SecurityEventContext.class);
                when(context.getMetadata()).thenReturn(Map.of("processingResult",
                        ProcessingResult.builder().action(action.name()).build()));
                return context;
            } finally {
                running.decrementAndGet();
            }
        });
        return service;
    }

    private static boolean restriction(ZeroTrustAction action) {
        return action == ZeroTrustAction.BLOCK || action == ZeroTrustAction.CHALLENGE
                || action == ZeroTrustAction.ESCALATE;
    }

    private ZeroTrustSpringEvent event(Map<String, Object> payload) {
        return ZeroTrustSpringEvent.builder(this)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId(USER)
                .sessionId("session-1")
                .resource(String.valueOf(payload.get("requestPath")))
                .payload(payload)
                .build();
    }

    private static Map<String, Object> request(String kind, String path, boolean sync, String importance,
                                               String sensitivity) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("requestPath", path);
        payload.put("httpMethod", "GET");
        payload.put("executionSubjectKind", kind);
        payload.put("protectableSync", sync);
        if (importance != null) {
            payload.put("resourceImportance", importance);
        }
        if (sensitivity != null) {
            payload.put("resourceSensitivity", sensitivity);
        }
        return payload;
    }

    private Object together(SynchronousProtectableDecisionService service, List<Map<String, Object>> requests)
            throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(requests.size());
        try {
            CountDownLatch go = new CountDownLatch(1);
            List<Future<Object>> futures = new ArrayList<>();
            for (Map<String, Object> payload : requests) {
                futures.add(pool.submit((Callable<Object>) () -> {
                    current.set(payload);
                    go.await();
                    try {
                        return service.analyze(invocation, authentication);
                    } catch (RuntimeException refused) {
                        return refused;
                    }
                }));
            }
            go.countDown();
            List<Object> outcomes = new ArrayList<>();
            for (Future<Object> future : futures) {
                outcomes.add(future.get(30, TimeUnit.SECONDS));
            }
            return outcomes;
        } finally {
            pool.shutdownNow();
        }
    }

    @SuppressWarnings("unchecked")
    private static List<SyncDecisionResult> answers(Object outcomes) {
        List<SyncDecisionResult> results = new ArrayList<>();
        for (Object outcome : (List<Object>) outcomes) {
            if (outcome instanceof SyncDecisionResult result) {
                results.add(result);
            }
        }
        return results;
    }

    @SuppressWarnings("unchecked")
    private static List<ZeroTrustAccessDeniedException> refusals(Object outcomes) {
        List<ZeroTrustAccessDeniedException> refused = new ArrayList<>();
        for (Object outcome : (List<Object>) outcomes) {
            if (outcome instanceof ZeroTrustAccessDeniedException denied) {
                refused.add(denied);
            }
        }
        return refused;
    }

    private static List<Map<String, Object>> same(int count, String path, boolean sync, String importance) {
        List<Map<String, Object>> requests = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            requests.add(request("DELEGATED_AGENT", path, sync, importance, null));
        }
        return requests;
    }

    // SV-01
    @RepeatedTest(20)
    void synchronousAgentRequestsAreEachDecidedOneAfterAnotherNoneSharesAVerdict() throws Exception {
        SynchronousProtectableDecisionService service = service(true, 3, 20, 20_000, 3);
        analysisMillis = 15;

        Object outcomes = together(service, same(5, "/api/projects/GB-500/exports", true, "SENSITIVE"));

        assertThat(started.get()).isEqualTo(5);
        assertThat(mostAtOnce.get()).isEqualTo(1);
        assertThat(answers(outcomes)).hasSize(5).allSatisfy(r -> assertThat(r.action()).isEqualTo(ZeroTrustAction.ALLOW));
    }

    // SV-02
    @RepeatedTest(20)
    void aBlockOnASynchronousRequestBlocksTheOthersWithoutAnalysingThem() throws Exception {
        SynchronousProtectableDecisionService service = service(true, 3, 20, 20_000, 3);
        verdict = order -> ZeroTrustAction.BLOCK;
        analysisMillis = 40;

        Object outcomes = together(service, same(5, "/api/projects/GB-500/exports", true, "SENSITIVE"));

        assertThat(started.get()).isEqualTo(1);
        assertThat(answers(outcomes)).hasSize(5).allSatisfy(r -> assertThat(r.action()).isEqualTo(ZeroTrustAction.BLOCK));
        // the four that were not analysed are recorded as requests that reached no analysis
        verify(recorder, times(4)).record(any(ZeroTrustSpringEvent.class), eq(ZeroTrustAction.BLOCK));
    }

    // SV-03
    @RepeatedTest(20)
    void tenAsynchronousAgentRequestsForOneResourceAreOneAnalysis() throws Exception {
        SynchronousProtectableDecisionService service = service(true, 3, 20, 20_000, 3);

        Object outcomes = together(service, same(10, "/api/projects/HX-310/documents", false, "NON_SENSITIVE"));

        assertThat(started.get()).isEqualTo(1);
        assertThat(answers(outcomes)).hasSize(10).allSatisfy(r -> assertThat(r.action()).isEqualTo(ZeroTrustAction.ALLOW));
        verify(recorder, times(9)).record(any(ZeroTrustSpringEvent.class), eq(ZeroTrustAction.ALLOW));
    }

    // SV-09: thirty identical asynchronous requests are one analysis, however many the request limit would allow
    @RepeatedTest(20)
    void thirtyIdenticalAsynchronousAgentRequestsAreOneAnalysisAndNoneIsRefused() throws Exception {
        SynchronousProtectableDecisionService service = service(true, 3, 20, 20_000, 3);
        analysisMillis = 400;

        Object outcomes = together(service, same(30, "/api/projects/HX-310/documents", false, "SENSITIVE"));

        assertThat(started.get()).isEqualTo(1);
        assertThat(refusals(outcomes)).isEmpty();
        assertThat(answers(outcomes)).hasSize(30).allSatisfy(r -> assertThat(r.action()).isEqualTo(ZeroTrustAction.ALLOW));
        verify(recorder, times(29)).record(any(ZeroTrustSpringEvent.class), eq(ZeroTrustAction.ALLOW));
    }

    // SV-04
    @Test
    void whenTheAgentHasNoPlaceLeftTheRequestIsRefusedAsBusyAndNeverPassed() throws Exception {
        SynchronousProtectableDecisionService service = service(true, 1, 0, 200, 3);
        analysisMillis = 800;
        List<Map<String, Object>> requests = new ArrayList<>();
        for (int i = 1; i <= 3; i++) {
            requests.add(request("DELEGATED_AGENT", "/api/customers/CUS-" + i, true, "SENSITIVE", null));
        }

        Object outcomes = together(service, requests);

        assertThat(started.get()).isEqualTo(1);
        assertThat(answers(outcomes)).hasSize(1);
        assertThat(refusals(outcomes)).hasSize(2).allSatisfy(denied -> {
            assertThat(denied.getHttpStatus()).isEqualTo(429);
            assertThat(denied.getErrorCode()).isEqualTo("ZERO_TRUST_ANALYSIS_BUSY");
            assertThat(denied.getBusyRetryAfterSeconds()).isPositive();
        });
    }

    // SV-05 (GT-01)
    @Test
    void anAllowIsNotReleasedWhenARestrictionWasStoredWhileItWasDecided() throws Exception {
        SynchronousProtectableDecisionService service = service(true, 3, 20, 5_000, 3);
        // while the analysis runs, another request's decision stores a BLOCK
        beforeAnswer = () -> stored.set(ZeroTrustAction.BLOCK);
        current.set(request("DELEGATED_AGENT", "/api/customers/CUS-1", true, "SENSITIVE", null));

        SyncDecisionResult result = service.analyze(invocation, authentication);

        assertThat(result.action()).isEqualTo(ZeroTrustAction.BLOCK);
    }

    // SV-06 (PB-01, PB-03..PB-07)
    @Test
    void theGatePassesAFewExplicitNonSensitiveReadsAndDecidesTheRestInPlace() {
        SynchronousProtectableDecisionService service = service(true, 3, 20, 5_000, 3);
        stored.set(ZeroTrustAction.PENDING_ANALYSIS);

        AsyncProtectableGate first = gate(service, request("DELEGATED_AGENT", "/api/docs/1", false, "NON_SENSITIVE", null));
        AsyncProtectableGate second = gate(service, request("DELEGATED_AGENT", "/api/docs/2", false, "NON_SENSITIVE", null));
        AsyncProtectableGate third = gate(service, request("DELEGATED_AGENT", "/api/docs/3", false, "NON_SENSITIVE", null));
        AsyncProtectableGate fourth = gate(service, request("DELEGATED_AGENT", "/api/docs/4", false, "NON_SENSITIVE", null));

        assertThat(first.passed()).isTrue();
        assertThat(first.publishesEvent()).as("the first pass is analysed in the background").isTrue();
        assertThat(second.passed()).isTrue();
        assertThat(second.publishesEvent()).as("the others are only recorded").isFalse();
        assertThat(third.passed()).isTrue();
        assertThat(third.publishesEvent()).isFalse();
        assertThat(fourth.passed()).isFalse();
        assertThat(fourth.decideInPlace()).as("past the budget it waits for the verdict").isTrue();
    }

    @Test
    void theGatePassesNothingElse() {
        SynchronousProtectableDecisionService service = service(true, 3, 20, 5_000, 3);
        stored.set(ZeroTrustAction.PENDING_ANALYSIS);

        assertThat(gate(service, request("DELEGATED_AGENT", "/api/docs/1", false, null, null)).passed())
                .as("unspecified").isFalse();
        assertThat(gate(service, request("DELEGATED_AGENT", "/api/docs/1", false, "SENSITIVE", null)).passed())
                .as("sensitive").isFalse();
        assertThat(gate(service, request("DELEGATED_AGENT", "/api/docs/1", false, "NON_SENSITIVE", "RESTRICTED")).passed())
                .as("raised by the host").isFalse();
        assertThat(gate(service, request("DELEGATED_AGENT", "/api/projects/1/exports", false, "NON_SENSITIVE", null))
                .passed()).as("an export").isFalse();
        AsyncProtectableGate person = gate(service, request("HUMAN_USER", "/api/docs/1", false, "NON_SENSITIVE", null));
        assertThat(person.passed()).as("a person is not an agent").isFalse();
        assertThat(person.decideInPlace()).isFalse();
    }

    @Test
    void withTheFlightsOffTheGateIsAsItWas() {
        SynchronousProtectableDecisionService service = service(false, 3, 20, 5_000, 3);
        stored.set(ZeroTrustAction.PENDING_ANALYSIS);

        AsyncProtectableGate gate = gate(service, request("DELEGATED_AGENT", "/api/docs/1", false, "NON_SENSITIVE", null));

        assertThat(gate.passed()).isFalse();
        assertThat(gate.decideInPlace()).isTrue();
    }

    @Test
    void aStoredVerdictEndsThePassesAndARestrictionIsNeverPassedOver() {
        SynchronousProtectableDecisionService service = service(true, 3, 20, 5_000, 2);
        stored.set(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(gate(service, request("DELEGATED_AGENT", "/api/docs/1", false, "NON_SENSITIVE", null)).passed()).isTrue();

        stored.set(ZeroTrustAction.BLOCK);
        AsyncProtectableGate blocked = gate(service, request("DELEGATED_AGENT", "/api/docs/2", false, "NON_SENSITIVE", null));
        assertThat(blocked.passed()).isFalse();
        assertThat(blocked.restriction()).isEqualTo(ZeroTrustAction.BLOCK);

        // the verdict having been stored ends the window: a later pending window starts from nothing
        stored.set(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(gate(service, request("DELEGATED_AGENT", "/api/docs/3", false, "NON_SENSITIVE", null)).publishesEvent())
                .isTrue();
    }

    // SV-07
    @Test
    void aPersonsRequestsAreNotTouchedByTheFlights() throws Exception {
        SynchronousProtectableDecisionService service = service(true, 1, 0, 200, 3);
        analysisMillis = 30;
        List<Map<String, Object>> requests = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            requests.add(request("HUMAN_USER", "/api/docs/1", true, "SENSITIVE", null));
        }

        Object outcomes = together(service, requests);

        assertThat(started.get()).isEqualTo(3);
        assertThat(refusals(outcomes)).isEmpty();
        assertThat(answers(outcomes)).hasSize(3);
    }

    // SV-08
    @Test
    void withTheFlightsOffEveryAgentRequestIsAnalysedOnItsOwnAsBefore() throws Exception {
        SynchronousProtectableDecisionService service = service(false, 1, 0, 200, 3);
        analysisMillis = 30;

        Object outcomes = together(service, same(4, "/api/projects/GB-500/exports", true, "SENSITIVE"));

        assertThat(started.get()).isEqualTo(4);
        assertThat(mostAtOnce.get()).as("not limited").isGreaterThan(1);
        assertThat(refusals(outcomes)).isEmpty();
    }

    private AsyncProtectableGate gate(SynchronousProtectableDecisionService service, Map<String, Object> payload) {
        current.set(payload);
        return service.asyncGate(invocation, authentication);
    }

    @Test
    void anAnalysisThatFailsIsTheFailureOfTheRequestsThatFollowedItToo() throws Exception {
        SynchronousProtectableDecisionService service = service(true, 3, 20, 20_000, 3);
        doAnswer(call -> {
            started.incrementAndGet();
            Thread.sleep(60);
            throw new IllegalStateException("model unavailable");
        }).when(agent).processSecurityEvent(any(SecurityEvent.class));

        Object outcomes = together(service, same(4, "/api/projects/HX-310/documents", false, "NON_SENSITIVE"));

        assertThat(started.get()).isEqualTo(1);
        @SuppressWarnings("unchecked")
        List<Object> list = (List<Object>) outcomes;
        assertThat(list).hasSize(4).allSatisfy(o -> assertThat(o).isInstanceOf(IllegalStateException.class));
        assertThatThrownBy(() -> {
            current.set(request("DELEGATED_AGENT", "/api/projects/HX-310/documents", false, "NON_SENSITIVE", null));
            service.analyze(invocation, authentication);
        }).isInstanceOf(IllegalStateException.class);
    }
}
