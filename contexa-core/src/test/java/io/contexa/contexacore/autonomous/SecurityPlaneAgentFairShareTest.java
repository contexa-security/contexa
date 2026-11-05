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
package io.contexa.contexacore.autonomous;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Q-23 (PR-81): what one user may hold of the analysis, what comes first when the engine is behind, and how the engine
 * tells that it is behind.
 */
@Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class SecurityPlaneAgentFairShareTest {

    private final SecurityMonitoringService monitor = mock(SecurityMonitoringService.class);
    private final SecurityEventProcessor processor = mock(SecurityEventProcessor.class);
    private final SecurityPlaneProperties properties = new SecurityPlaneProperties();
    private final ExecutorService analysis = Executors.newCachedThreadPool();
    private final CountDownLatch release = new CountDownLatch(1);
    private final List<String> analysed = new CopyOnWriteArrayList<>();
    private final AtomicReference<Boolean> modelDecides = new AtomicReference<>(true);
    private SecurityMonitoringService.SecurityEventBatchProcessor batches;
    private SecurityPlaneAgent agent;

    @BeforeEach
    void setUp() {
        when(processor.process(any(SecurityEvent.class))).thenAnswer(call -> {
            SecurityEvent event = call.getArgument(0);
            analysed.add(event.getEventId());
            release.await();
            SecurityEventContext context = SecurityEventContext.builder().securityEvent(event)
                    .processingStatus(SecurityEventContext.ProcessingStatus.COMPLETED).build();
            context.addMetadata("processingResult", ProcessingResult.builder().success(true).action("ALLOW")
                    .llmDecisionPresent(modelDecides.get()).build());
            return context;
        });
        agent = new SecurityPlaneAgent(monitor, new InMemorySecurityContextDataStore(), mock(CentralAuditFacade.class),
                processor, properties, analysis);
        agent.initialize();
        agent.start();
        ArgumentCaptor<SecurityMonitoringService.SecurityEventBatchProcessor> captor =
                ArgumentCaptor.forClass(SecurityMonitoringService.SecurityEventBatchProcessor.class);
        verify(monitor).setBatchProcessor(captor.capture());
        batches = captor.getValue();
    }

    @AfterEach
    void tearDown() {
        release.countDown();
        agent.shutdown();
        analysis.shutdownNow();
    }

    private static SecurityEvent request(String user, String session) {
        return event(user, session, "AUTHORIZATION");
    }

    private static SecurityEvent event(String user, String session, String category) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("zerotrust.category", category);
        return SecurityEvent.builder().eventId(UUID.randomUUID().toString()).userId(user).sessionId(session)
                .sourceIp("10.0.0.1").metadata(metadata).build();
    }

    private void sessions(String user, int count) {
        List<SecurityEvent> events = new ArrayList<>();
        for (int session = 0; session < count; session++) {
            events.add(request(user, "session-" + session));
        }
        batches.processBatch(events);
    }

    // ----- what one user may hold -----

    @Test
    void oneUserHoldsNoMoreThanTheShareHoweverManySessionsItOpens() {
        sessions("flooder", SecurityPlaneAgent.USER_SHARE + 20);

        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(SecurityPlaneAgent.USER_SHARE));
        assertThat(agent.analysesInProgress()).isEqualTo(SecurityPlaneAgent.USER_SHARE);
    }

    @Test
    void anotherUserIsNotHeldBackByThatShare() {
        sessions("flooder", SecurityPlaneAgent.USER_SHARE + 20);

        batches.processBatch(List.of(request("quiet", "session-1")));

        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(SecurityPlaneAgent.USER_SHARE + 1));
    }

    @Test
    void aRequestPastTheShareIsKeptInItsSessionAndNotAnalysed() {
        SecurityPlaneAgent.QueuedEventRecheck recheck = mock(SecurityPlaneAgent.QueuedEventRecheck.class);
        agent.setQueuedEventRecheck(recheck);

        sessions("flooder", SecurityPlaneAgent.USER_SHARE + 2);

        Awaitility.await().untilAsserted(() -> verify(recheck, times(2)).leftOut(any()));
    }

    @Test
    void aSignInIsAnalysedPastTheShare() {
        sessions("flooder", SecurityPlaneAgent.USER_SHARE);

        batches.processBatch(List.of(event("flooder", "session-new", "AUTHENTICATION")));

        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(SecurityPlaneAgent.USER_SHARE + 1));
    }

    @Test
    void anAgentsEventIsNotLeftOut() {
        List<SecurityEvent> events = new ArrayList<>();
        for (int session = 0; session < SecurityPlaneAgent.USER_SHARE + 2; session++) {
            SecurityEvent event = request("owner", "session-" + session);
            event.addMetadata("executionSubjectKind", "AUTONOMOUS_AGENT");
            events.add(event);
        }

        batches.processBatch(events);

        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(SecurityPlaneAgent.USER_SHARE + 2));
    }

    @Test
    void theShareComesBackWhenAnAnalysisEnds() {
        sessions("flooder", SecurityPlaneAgent.USER_SHARE);
        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(SecurityPlaneAgent.USER_SHARE));

        release.countDown();

        Awaitility.await().untilAsserted(() -> assertThat(agent.analysesInProgress()).isZero());
        batches.processBatch(List.of(request("flooder", "session-later")));
        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(SecurityPlaneAgent.USER_SHARE + 1));
        Awaitility.await().untilAsserted(() -> assertThat(agent.analysesInProgress()).isZero());
    }

    @Test
    void aSynchronousRequestPastTheShareIsToldThereIsNoRoom() throws Exception {
        for (int call = 0; call < SecurityPlaneAgent.USER_SHARE; call++) {
            agent.processSecurityEventOffThread(request("flooder", "session-" + call));
        }

        CompletableFuture<SecurityEventContext> past =
                agent.processSecurityEventOffThread(request("flooder", "session-past"));

        assertThatThrownBy(() -> past.get(5, TimeUnit.SECONDS)).isInstanceOf(ExecutionException.class)
                .hasCauseInstanceOf(RejectedExecutionException.class);
    }

    // ----- what comes first -----

    @Test
    void aSessionWithoutADecisionIsFirstInLineUntilTheModelDecidesOne() {
        release.countDown();
        SecurityEvent first = request("alice", "session-1");
        batches.processBatch(List.of(first));
        Awaitility.await().untilAsserted(() -> assertThat(agent.analysesInProgress()).isZero());
        assertThat(first.getMetadata()).containsEntry(AnalysisTurn.FIRST_DECISION, true);

        SecurityEvent next = request("alice", "session-1");
        batches.processBatch(List.of(next));
        Awaitility.await().untilAsserted(() -> assertThat(agent.analysesInProgress()).isZero());

        assertThat(next.getMetadata()).containsEntry(AnalysisTurn.FIRST_DECISION, false);
    }

    @Test
    void aFailedAnalysisLeavesTheSessionFirstInLine() {
        release.countDown();
        modelDecides.set(false);
        batches.processBatch(List.of(request("alice", "session-1")));
        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(1));
        Awaitility.await().untilAsserted(() -> assertThat(agent.analysesInProgress()).isZero());

        SecurityEvent next = request("alice", "session-1");
        batches.processBatch(List.of(next));
        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(2));
        Awaitility.await().untilAsserted(() -> assertThat(agent.analysesInProgress()).isZero());

        assertThat(next.getMetadata()).containsEntry(AnalysisTurn.FIRST_DECISION, true);
    }

    @Test
    void anotherSessionOfTheUserHasItsOwnFirstDecision() {
        release.countDown();
        batches.processBatch(List.of(request("alice", "session-1")));
        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(1));
        Awaitility.await().untilAsserted(() -> assertThat(agent.analysesInProgress()).isZero());

        SecurityEvent otherSession = request("alice", "session-2");
        batches.processBatch(List.of(otherSession));
        Awaitility.await().untilAsserted(() -> assertThat(agent.analysesInProgress()).isZero());

        assertThat(otherSession.getMetadata()).containsEntry(AnalysisTurn.FIRST_DECISION, true);
    }

    // ----- how the engine tells it is behind -----

    @Test
    void itIsBehindOnceTheAnalysesReachTheConfiguredThreshold() {
        properties.getLlmExecutor().setBackpressureQueueThreshold(3);
        assertThat(agent.isBehind()).isFalse();

        batches.processBatch(List.of(request("a", "s"), request("b", "s")));
        assertThat(agent.isBehind()).isFalse();

        batches.processBatch(List.of(request("c", "s")));
        assertThat(agent.isBehind()).isTrue();
    }

    @Test
    void itIsNotBehindWhenBackpressureIsOff() {
        properties.getLlmExecutor().setBackpressureQueueThreshold(1);
        properties.getLlmExecutor().setBackpressureEnabled(false);

        batches.processBatch(List.of(request("a", "s")));

        assertThat(agent.isBehind()).isFalse();
    }

    @Test
    void aSynchronousAnalysisCountsToo() {
        properties.getLlmExecutor().setBackpressureQueueThreshold(1);

        agent.processSecurityEventOffThread(request("a", "s"));

        assertThat(agent.isBehind()).isTrue();
    }

    @Test
    void noRoomInTheAnalysisLeavesNothingCounted() {
        SecurityPlaneAgent full = new SecurityPlaneAgent(monitor, new InMemorySecurityContextDataStore(),
                mock(CentralAuditFacade.class), processor, properties, task -> {
                    throw new RejectedExecutionException("full");
                });

        CompletableFuture<SecurityEventContext> decided = full.processSecurityEventOffThread(request("a", "s"));

        assertThat(decided).isCompletedExceptionally();
        assertThat(full.analysesInProgress()).isZero();
        verify(processor, never()).process(any());
    }
}
