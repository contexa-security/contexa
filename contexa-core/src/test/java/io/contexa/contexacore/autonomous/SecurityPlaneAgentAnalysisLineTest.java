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
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The analyses waiting for their turn have a limit. An event past it is not queued and not analysed: it is
 * kept in its session as a request no analysis reached and counted, and nothing upstream waits for room.
 */
@Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class SecurityPlaneAgentAnalysisLineTest {

    private static final long MIB = 1024L * 1024;

    private final SecurityMonitoringService monitor = mock(SecurityMonitoringService.class);
    private final SecurityEventProcessor processor = mock(SecurityEventProcessor.class);
    private final SecurityPlaneProperties properties = new SecurityPlaneProperties();
    private final ExecutorService analysis = Executors.newCachedThreadPool();
    private final CountDownLatch release = new CountDownLatch(1);
    private final List<String> analysed = new CopyOnWriteArrayList<>();
    private final Set<String> leftOut = ConcurrentHashMap.newKeySet();
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
            context.addMetadata("processingResult",
                    ProcessingResult.builder().success(true).action("ALLOW").llmDecisionPresent(true).build());
            return context;
        });
        agent = new SecurityPlaneAgent(monitor, new InMemorySecurityContextDataStore(), mock(CentralAuditFacade.class),
                processor, properties, analysis);
        agent.initialize();
        agent.start();
        agent.setQueuedEventRecheck(new SecurityPlaneAgent.QueuedEventRecheck() {
            @Override
            public boolean answeredWithoutAnalysis(SecurityEvent event) {
                return false;
            }

            @Override
            public void leftOut(SecurityEvent event) {
                SecurityPlaneAgentAnalysisLineTest.this.leftOut.add(event.getEventId());
            }
        });
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

    private static SecurityEvent signIn(int user) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("zerotrust.category", "AUTHENTICATION");
        return SecurityEvent.builder().eventId(UUID.randomUUID().toString()).userId("user-" + user)
                .sessionId("session-" + user).sourceIp("10.0.0.1").metadata(metadata).build();
    }

    private static List<SecurityEvent> signIns(int from, int to) {
        List<SecurityEvent> events = new ArrayList<>();
        for (int user = from; user < to; user++) {
            events.add(signIn(user));
        }
        return events;
    }

    @Test
    void theEventsPastTheLineAreKeptInTheirSessionsAndNotAnalysed() {
        int bound = agent.analysisLineBound();

        batches.processBatch(signIns(0, bound + 7));

        assertThat(agent.analysesInProgress()).isEqualTo(bound);
        assertThat(leftOut).hasSize(7);
        assertThat(agent.analysesLeftOut()).isEqualTo(7);
    }

    @Test
    void oneSessionsEventsCountAgainstTheLineLikeAnyOther() {
        agent.setAnalysisLineBound(5);
        List<SecurityEvent> events = new ArrayList<>();
        for (int event = 0; event < 12; event++) {
            events.add(signIn(1));
        }

        batches.processBatch(events);

        assertThat(agent.analysesInProgress()).isEqualTo(5);
        assertThat(leftOut).hasSize(7);
    }

    @Test
    void nothingUpstreamWaitsForRoom() throws Exception {
        agent.setAnalysisLineBound(5);
        batches.processBatch(signIns(0, 5));
        CountDownLatch handed = new CountDownLatch(1);

        Thread dispatcher = new Thread(() -> {
            batches.processBatch(signIns(5, 2_000));
            handed.countDown();
        });
        dispatcher.start();

        assertThat(handed.await(10, TimeUnit.SECONDS)).as("the batch is taken although the line is full").isTrue();
        assertThat(leftOut).hasSize(1_995);
    }

    @Test
    void theLineHasRoomAgainOnceAnAnalysisEnds() {
        agent.setAnalysisLineBound(2);
        batches.processBatch(signIns(0, 3));
        assertThat(leftOut).hasSize(1);

        release.countDown();
        Awaitility.await().untilAsserted(() -> assertThat(agent.analysesInProgress()).isZero());
        batches.processBatch(signIns(3, 4));

        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(3));
        assertThat(leftOut).hasSize(1);
    }

    @Test
    void aFullLineIsBehindWhateverTheThresholdSays() {
        properties.getLlmExecutor().setBackpressureQueueThreshold(1_000_000);
        agent.setAnalysisLineBound(3);

        batches.processBatch(signIns(0, 3));

        assertThat(agent.isBehind()).isTrue();
    }

    @Test
    void aRequestThatDecidesInPlaceHasItsOwnBound() throws Exception {
        agent.setAnalysisLineBound(1);
        batches.processBatch(signIns(0, 1));

        agent.processSecurityEventOffThread(signIn(1));

        Awaitility.await().untilAsserted(() -> assertThat(analysed).hasSize(2));
    }

    @RepeatedTest(5)
    void theLineHoldsUnderWritersAtOnceAndEveryEventIsAccountedFor() throws Exception {
        agent.setAnalysisLineBound(50);
        int writers = 8;
        int each = 100;
        ExecutorService threads = Executors.newFixedThreadPool(writers);
        AtomicInteger next = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> running = new ArrayList<>();
        for (int writer = 0; writer < writers; writer++) {
            running.add(threads.submit(() -> {
                start.await();
                for (int event = 0; event < each; event++) {
                    int user = next.getAndIncrement();
                    batches.processBatch(signIns(user, user + 1));
                }
                return null;
            }));
        }
        start.countDown();
        for (Future<?> writer : running) {
            writer.get();
        }
        threads.shutdown();

        assertThat(agent.analysesInProgress()).isLessThanOrEqualTo(50);
        assertThat(agent.analysesInProgress() + leftOut.size()).isEqualTo(writers * each);
    }

    @Test
    void theDefaultBoundIsAShareOfTheHeapWithinTheMonitorsQueue() {
        // A twentieth of the heap at 16 KiB an event.
        assertThat(SecurityPlaneAgent.defaultAnalysisLineBound(384 * MIB, 10_000)).isEqualTo(1_228);
        assertThat(SecurityPlaneAgent.defaultAnalysisLineBound(2_048 * MIB, 10_000)).isEqualTo(6_553);
        assertThat(SecurityPlaneAgent.defaultAnalysisLineBound(8_192 * MIB, 10_000)).isEqualTo(10_000);
        assertThat(SecurityPlaneAgent.defaultAnalysisLineBound(Long.MAX_VALUE, 10_000)).isEqualTo(10_000);
        assertThat(SecurityPlaneAgent.defaultAnalysisLineBound(64 * MIB, 10_000)).isEqualTo(1_000);
        assertThat(SecurityPlaneAgent.defaultAnalysisLineBound(8_192 * MIB, 100)).isEqualTo(1_000);
    }
}
