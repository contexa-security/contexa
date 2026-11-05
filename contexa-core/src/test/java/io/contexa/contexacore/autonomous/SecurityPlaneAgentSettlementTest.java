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
import io.contexa.contexacore.autonomous.handler.handler.SecurityDecisionEnforcementHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.ArgumentCaptor;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The record of an event may be committed once the analysis is done with it, and not before: a node that dies leaves
 * what it had not finished to be delivered again.
 */
@Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class SecurityPlaneAgentSettlementTest {

    private static final Duration SOON = Duration.ofMillis(150);

    private final SecurityMonitoringService monitor = mock(SecurityMonitoringService.class);
    private final SecurityEventProcessor processor = mock(SecurityEventProcessor.class);
    private final SecurityPlaneProperties properties = new SecurityPlaneProperties();
    private final SecurityContextDataStore store = new InMemorySecurityContextDataStore();
    private final ExecutorService analysis = Executors.newCachedThreadPool();
    private final AtomicInteger modelCalls = new AtomicInteger();
    private SecurityMonitoringService.SecurityEventBatchProcessor batches;
    private SecurityPlaneAgent agent;
    private long batchedAt;

    @BeforeEach
    void setUp() {
        when(processor.process(any(SecurityEvent.class))).thenAnswer(call -> {
            modelCalls.incrementAndGet();
            return decided(call.getArgument(0));
        });
        agent = agent(store);
    }

    private SecurityPlaneAgent agent(SecurityContextDataStore usedStore) {
        SecurityPlaneAgent made = new SecurityPlaneAgent(monitor, usedStore, mock(CentralAuditFacade.class), processor,
                properties, analysis);
        made.setJudgeAgainInterval(SOON);
        made.initialize();
        made.start();
        ArgumentCaptor<SecurityMonitoringService.SecurityEventBatchProcessor> captor =
                ArgumentCaptor.forClass(SecurityMonitoringService.SecurityEventBatchProcessor.class);
        verify(monitor, atLeastOnce()).setBatchProcessor(captor.capture());
        batches = captor.getValue();
        return made;
    }

    @AfterEach
    void tearDown() {
        agent.shutdown();
        analysis.shutdownNow();
    }

    private static SecurityEventContext decided(SecurityEvent event) {
        SecurityEventContext context = SecurityEventContext.builder().securityEvent(event)
                .processingStatus(SecurityEventContext.ProcessingStatus.COMPLETED).build();
        context.addMetadata("processingResult",
                ProcessingResult.builder().success(true).action("ALLOW").llmDecisionPresent(true).build());
        return context;
    }

    private static SecurityEvent event(String category) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("zerotrust.category", category);
        return SecurityEvent.builder().eventId(UUID.randomUUID().toString()).userId("alice").sessionId("session-1")
                .sourceIp("10.0.0.1").metadata(metadata).build();
    }

    private static SecurityEvent signIn() {
        return event("AUTHENTICATION");
    }

    @Test
    void aDecidedEventIsSettledOnce() {
        SecurityEvent event = signIn();

        batches.processBatch(List.of(event));

        verify(monitor, timeout(3000)).settled(event);
        verify(monitor, after(200).times(1)).settled(event);
        assertThat(modelCalls).hasValue(1);
    }

    @Test
    void anEventIsNotSettledBeforeItsDecision() throws Exception {
        CountDownLatch deciding = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(processor.process(any(SecurityEvent.class))).thenAnswer(call -> {
            deciding.countDown();
            release.await();
            return decided(call.getArgument(0));
        });
        SecurityEvent event = signIn();

        batches.processBatch(List.of(event));
        assertThat(deciding.await(3, TimeUnit.SECONDS)).isTrue();

        verify(monitor, after(200).never()).settled(any());
        release.countDown();
        verify(monitor, timeout(3000)).settled(event);
    }

    // ----- a record delivered again -----

    @Test
    void anEventAlreadyDecidedIsSettledWithoutAskingTheModel() {
        SecurityEvent event = signIn();
        batches.processBatch(List.of(event));
        verify(monitor, timeout(3000)).settled(event);

        SecurityEvent deliveredAgain = copyOf(event);
        batches.processBatch(List.of(deliveredAgain));

        verify(monitor, timeout(3000)).settled(deliveredAgain);
        assertThat(modelCalls).as("the processed mark answers the second delivery").hasValue(1);
    }

    @Test
    void aDecisionOnRecordAnswersTheEventDeliveredAgainWithoutAskingTheModel() {
        AiSecurityDecisionObservationWriter writer = mock(AiSecurityDecisionObservationWriter.class);
        when(writer.findFinalDecision(anyString())).thenReturn(new AiSecurityDecisionObservationWriter.PersistedFinalDecision(
                "observation-1", null, "alice", "ALLOW", null, "generation-1", "request-1"));
        agent.setAiSecurityDecisionObservationWriterSupplier(() -> writer);
        agent.setZeroTrustActionRepository(mock(ZeroTrustActionRepository.class));
        agent.setDecisionEnforcementHandlerSupplier(() -> mock(SecurityDecisionEnforcementHandler.class));
        SecurityEvent event = signIn();

        batches.processBatch(List.of(event));

        verify(monitor, timeout(3000)).settled(event);
        assertThat(modelCalls).as("the first analysis stored its decision before the node died").hasValue(0);
    }

    private static SecurityEvent copyOf(SecurityEvent event) {
        return SecurityEvent.builder().eventId(event.getEventId()).userId(event.getUserId()).sessionId(event.getSessionId())
                .sourceIp(event.getSourceIp()).metadata(new LinkedHashMap<>(Map.of("zerotrust.category", "AUTHENTICATION")))
                .build();
    }

    // ----- no decision comes of it -----

    @Test
    void anEventTheDecisionInForceAnswersIsSettled() {
        agent.setQueuedEventRecheck(event -> true);
        SecurityEvent event = event("AUTHORIZATION");

        batches.processBatch(List.of(event));

        verify(monitor, timeout(3000)).settled(event);
        assertThat(modelCalls).hasValue(0);
    }

    @Test
    void anEventPastTheUsersShareIsSettled() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        when(processor.process(any(SecurityEvent.class))).thenAnswer(call -> {
            release.await();
            return decided(call.getArgument(0));
        });
        List<SecurityEvent> events = new ArrayList<>();
        for (int index = 0; index <= SecurityPlaneAgent.USER_SHARE; index++) {
            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("zerotrust.category", "AUTHORIZATION");
            events.add(SecurityEvent.builder().eventId("event-" + index).userId("alice").sessionId("session-" + index)
                    .sourceIp("10.0.0.1").metadata(metadata).build());
        }

        batches.processBatch(events);

        verify(monitor, timeout(3000)).settled(events.get(SecurityPlaneAgent.USER_SHARE));
        release.countDown();
        verify(monitor, timeout(3000).times(events.size())).settled(any());
    }

    @Test
    void anEventNothingCanAnalyseIsSettled() {
        when(processor.process(any(SecurityEvent.class))).thenAnswer(call -> {
            ((SecurityEvent) call.getArgument(0)).addMetadata(SecurityPlaneAgent.PROCESSING_STRATEGY_UNAVAILABLE, true);
            throw new IllegalStateException("no strategy");
        });
        SecurityEvent event = signIn();

        batches.processBatch(List.of(event));

        verify(monitor, timeout(3000)).settled(event);
        verify(monitor, never()).deferEvent(any(), anyString());
    }

    // ----- a failed analysis -----

    @Test
    void anEventToBeTriedAgainIsNotSettledUntilItsTriesAreOver() {
        properties.getAgent().setMaxDeferredRetries(2);
        AtomicInteger tries = new AtomicInteger();
        when(processor.process(any(SecurityEvent.class))).thenAnswer(call -> {
            tries.incrementAndGet();
            throw new IllegalStateException("the model is away");
        });
        doAnswer(call -> {
            SecurityEvent deferred = call.getArgument(0);
            deferred.addMetadata("deferredCount", tries.get());
            batches.processBatch(List.of(deferred));
            return null;
        }).when(monitor).deferEvent(any(), anyString());
        SecurityEvent event = signIn();

        batches.processBatch(List.of(event));

        verify(monitor, timeout(3000)).settled(event);
        assertThat(tries).hasValue(3);
    }

    @Test
    void anEventDeferredIsNotSettled() {
        when(processor.process(any(SecurityEvent.class))).thenThrow(new IllegalStateException("the model is away"));
        SecurityEvent event = signIn();

        batches.processBatch(List.of(event));

        verify(monitor, timeout(3000)).deferEvent(any(), anyString());
        verify(monitor, after(200).never()).settled(any());
    }

    /** What stops a thread can stop the node: the record stays to be delivered again. */
    @Test
    void anAnalysisStoppedByAnErrorLeavesTheEventToBeDeliveredAgain() throws Exception {
        CountDownLatch failed = new CountDownLatch(1);
        when(processor.process(any(SecurityEvent.class))).thenAnswer(call -> {
            failed.countDown();
            throw new OutOfMemoryError("test");
        });
        properties.getAgent().setMaxDeferredRetries(0);
        SecurityEvent event = signIn();

        batches.processBatch(List.of(event));

        assertThat(failed.await(3, TimeUnit.SECONDS)).isTrue();
        verify(monitor, after(300).never()).settled(any());
    }

    @Test
    void anEventAskedAgainIsNoRecordOfItsOwn() {
        when(processor.process(any(SecurityEvent.class))).thenAnswer(call -> decided(call.getArgument(0)));
        SecurityEvent again = signIn();
        again.addMetadata("judgedAgainEvent", "event-1");

        batches.processBatch(List.of(again));

        verify(monitor, after(300).never()).settled(any());
    }

    // ----- an event another owner holds -----

    private void heldByAnother(SecurityEvent event, List<Long> deferrals) {
        SecurityContextDataStore held = mock(SecurityContextDataStore.class);
        when(held.claimEventProcessingLease(anyString())).thenReturn(new SecurityContextDataStore.EventProcessingLease(
                SecurityContextDataStore.EventProcessingClaim.IN_FLIGHT, null));
        agent.shutdown();
        agent = agent(held);
        doAnswer(call -> {
            deferrals.add(System.nanoTime());
            SecurityEvent deferred = call.getArgument(0);
            deferred.addMetadata("deferredCount", deferrals.size());
            batches.processBatch(List.of(deferred));
            return null;
        }).when(monitor).deferEvent(any(), anyString());
        batchedAt = System.nanoTime();
        batches.processBatch(List.of(event));
    }

    @Test
    void theTriesOnAnEventAnotherOwnerHoldsAreSpreadOverTimeForThatOwnerToBeSeenGone() {
        List<Long> deferrals = new CopyOnWriteArrayList<>();
        SecurityEvent event = signIn();

        heldByAnother(event, deferrals);

        verify(monitor, timeout(5000)).settled(event);
        assertThat(deferrals).hasSize(3);
        assertThat(Duration.ofNanos(deferrals.get(0) - batchedAt)).as("the first try is at once").isLessThan(Duration.ofSeconds(2));
        assertThat(Duration.ofNanos(deferrals.get(1) - deferrals.get(0))).isGreaterThanOrEqualTo(SOON);
        assertThat(Duration.ofNanos(deferrals.get(2) - deferrals.get(1))).isGreaterThanOrEqualTo(SOON.multipliedBy(2));
    }

    @Test
    void anEventAnotherOwnerFinishesMeanwhileIsSettledWithoutAskingTheModel() {
        SecurityContextDataStore held = mock(SecurityContextDataStore.class);
        when(held.claimEventProcessingLease(anyString()))
                .thenReturn(new SecurityContextDataStore.EventProcessingLease(
                        SecurityContextDataStore.EventProcessingClaim.IN_FLIGHT, null))
                .thenReturn(new SecurityContextDataStore.EventProcessingLease(
                        SecurityContextDataStore.EventProcessingClaim.PROCESSED, null));
        agent.shutdown();
        agent = agent(held);
        doAnswer(call -> {
            batches.processBatch(List.of((SecurityEvent) call.getArgument(0)));
            return null;
        }).when(monitor).deferEvent(any(), anyString());
        SecurityEvent event = signIn();

        batches.processBatch(List.of(event));

        verify(monitor, timeout(3000)).settled(event);
        verify(monitor, times(1)).deferEvent(any(), anyString());
        assertThat(modelCalls).hasValue(0);
    }

    @Test
    void aFailureOtherThanAnOwnerIsTriedAgainAtOnce() {
        agent.setJudgeAgainInterval(Duration.ofMinutes(1));
        when(processor.process(any(SecurityEvent.class))).thenThrow(new IllegalStateException("the model is away"));
        SecurityEvent event = signIn();
        event.addMetadata("deferredCount", 1);

        batches.processBatch(List.of(event));

        verify(monitor, timeout(3000)).deferEvent(any(), anyString());
    }
}
