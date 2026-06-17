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

import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SecurityPlaneAgentOrderingTest {

    @Mock
    private SecurityMonitoringService securityMonitor;

    @Mock
    private SecurityContextDataStore dataStore;

    @Mock
    private CentralAuditFacade centralAuditFacade;

    @Mock
    private SecurityEventProcessor securityEventProcessor;

    @Mock
    private SecurityPlaneProperties securityPlaneProperties;

    private ExecutorService llmExecutor;
    private SecurityPlaneAgent agent;

    @AfterEach
    void tearDown() {
        if (agent != null) {
            agent.shutdown();
        }
        if (llmExecutor != null) {
            llmExecutor.shutdownNow();
        }
    }

    @Test
    @DisplayName("같은 analysisKey 이벤트는 입력 순서를 유지한 채 순차 처리되어야 한다")
    void shouldPreserveOrderForSameAnalysisKey() throws Exception {
        SecurityMonitoringService.SecurityEventBatchProcessor batchProcessor = initializeAgent(4);
        when(dataStore.claimEventProcessing(anyString())).thenReturn(SecurityContextDataStore.EventProcessingClaim.ACQUIRED);

        List<String> expectedOrder = List.of("evt-1", "evt-2", "evt-3", "evt-4");
        CopyOnWriteArrayList<String> actualOrder = new CopyOnWriteArrayList<>();
        CountDownLatch latch = new CountDownLatch(expectedOrder.size());
        when(securityEventProcessor.process(any(SecurityEvent.class))).thenAnswer(invocation -> {
            SecurityEvent event = invocation.getArgument(0);
            actualOrder.add(event.getEventId());
            latch.countDown();
            return SecurityEventContext.builder()
                    .securityEvent(event)
                    .processingStatus(SecurityEventContext.ProcessingStatus.COMPLETED)
                    .build();
        });

        batchProcessor.processBatch(List.of(
                event("evt-1", "same-user", "same-session"),
                event("evt-2", "same-user", "same-session"),
                event("evt-3", "same-user", "same-session"),
                event("evt-4", "same-user", "same-session")
        ));

        assertThat(latch.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(actualOrder).containsExactlyElementsOf(expectedOrder);
    }

    @Test
    @DisplayName("서로 다른 analysisKey 이벤트는 서로 다른 stripe에서 병렬 처리 가능해야 한다")
    void shouldAllowParallelProcessingForDifferentAnalysisKeys() throws Exception {
        SecurityMonitoringService.SecurityEventBatchProcessor batchProcessor = initializeAgent(4);
        when(dataStore.claimEventProcessing(anyString())).thenReturn(SecurityContextDataStore.EventProcessingClaim.ACQUIRED);

        CountDownLatch started = new CountDownLatch(2);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch completed = new CountDownLatch(2);
        AtomicInteger inFlight = new AtomicInteger(0);
        AtomicInteger maxInFlight = new AtomicInteger(0);

        when(securityEventProcessor.process(any(SecurityEvent.class))).thenAnswer(invocation -> {
            int current = inFlight.incrementAndGet();
            maxInFlight.updateAndGet(previous -> Math.max(previous, current));
            started.countDown();
            started.await(2, TimeUnit.SECONDS);
            release.await(2, TimeUnit.SECONDS);
            inFlight.decrementAndGet();
            completed.countDown();

            SecurityEvent event = invocation.getArgument(0);
            return SecurityEventContext.builder()
                    .securityEvent(event)
                    .processingStatus(SecurityEventContext.ProcessingStatus.COMPLETED)
                    .build();
        });

        batchProcessor.processBatch(List.of(
                event("evt-a", "user-a", "session-a"),
                event("evt-b", "user-b", "session-b")
        ));

        assertThat(started.await(2, TimeUnit.SECONDS)).isTrue();
        release.countDown();
        assertThat(completed.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(maxInFlight.get()).isGreaterThanOrEqualTo(2);
    }

    private SecurityMonitoringService.SecurityEventBatchProcessor initializeAgent(int llmConcurrency) {
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        properties.getAgent().setAutoStart(false);
        properties.getAgent().setEventTimeoutMs(5000L);
        properties.getLlmExecutor().setCorePoolSize(llmConcurrency);
        properties.getLlmExecutor().setMaxPoolSize(llmConcurrency);
        properties.getLlmExecutor().setQueueCapacity(32);

        when(securityPlaneProperties.getAgent()).thenReturn(properties.getAgent());
        when(securityPlaneProperties.getLlmExecutor()).thenReturn(properties.getLlmExecutor());
        clearInvocations(securityMonitor);

        llmExecutor = Executors.newFixedThreadPool(llmConcurrency);
        agent = new SecurityPlaneAgent(
                securityMonitor, dataStore, centralAuditFacade,
                securityEventProcessor, securityPlaneProperties, llmExecutor);
        agent.initialize();
        agent.start();

        ArgumentCaptor<SecurityMonitoringService.SecurityEventBatchProcessor> processorCaptor =
                ArgumentCaptor.forClass(SecurityMonitoringService.SecurityEventBatchProcessor.class);
        verify(securityMonitor, timeout(1000)).setBatchProcessor(processorCaptor.capture());
        return processorCaptor.getValue();
    }

    private SecurityEvent event(String eventId, String userId, String sessionId) {
        return SecurityEvent.builder()
                .eventId(eventId)
                .userId(userId)
                .sessionId(sessionId)
                .build();
    }
}
