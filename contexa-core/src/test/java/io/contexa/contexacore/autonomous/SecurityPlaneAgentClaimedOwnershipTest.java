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
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * QF-55: an attempt marks and releases its event's processing with the claim it holds. The identity and the owner token
 * it writes on the event's metadata are copies for the handlers; a read of that map while another thread writes it can
 * miss them, and the attempt's own decision must not then be discarded as stale.
 */
class SecurityPlaneAgentClaimedOwnershipTest {

    /** What a racing read of the event's metadata can see: the claim's copies missing. */
    private static void losesTheClaimCopies(SecurityEvent attempt) {
        Map<String, Object> metadata = attempt.getMetadata();
        metadata.remove(SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY);
        metadata.remove(SecurityPlaneAgent.EVENT_PROCESSING_OWNER_TOKEN);
    }

    private static SecurityPlaneProperties properties(String name) {
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        properties.getAgent().setAutoStart(false);
        properties.getAgent().setName(name);
        properties.getAgent().setEventTimeoutMs(5_000L);
        properties.getAgent().setMaxDeferredRetries(1);
        return properties;
    }

    private static SecurityEvent event(String eventId) {
        return SecurityEvent.builder().eventId(eventId).userId("user-claim").sessionId("session-claim")
                .sourceIp("10.0.0.1").build();
    }

    private static SecurityEventContext completed(SecurityEvent event) {
        return SecurityEventContext.builder()
                .securityEvent(event)
                .processingStatus(SecurityEventContext.ProcessingStatus.COMPLETED)
                .build();
    }

    @Test
    @DisplayName("QF-55: the decision of an attempt whose event lost the claim's copies is kept and marked processed")
    void anAttemptMarksItsEventProcessedWithTheClaimItHolds() {
        SecurityEventProcessor processor = mock(SecurityEventProcessor.class);
        SecurityPlaneAgent agent = new SecurityPlaneAgent(mock(SecurityMonitoringService.class),
                new InMemorySecurityContextDataStore(), mock(CentralAuditFacade.class), processor,
                properties("ClaimedOwnershipAgent"), Runnable::run);
        agent.initialize();
        SecurityEvent event = event("evt-claim-direct");
        AtomicReference<SecurityEventContext> decided = new AtomicReference<>();
        when(processor.process(any(SecurityEvent.class))).thenAnswer(invocation -> {
            SecurityEvent attempt = invocation.getArgument(0);
            losesTheClaimCopies(attempt);
            decided.set(completed(attempt));
            return decided.get();
        });

        SecurityEventContext result = agent.processSecurityEvent(event);

        assertThat(result).isSameAs(decided.get());
        assertThat(event.getMetadata()).doesNotContainKey("staleProcessingResultDiscarded");
        // Marked processed under the claim: the same event again is a duplicate and is not analysed again.
        assertThat(agent.processSecurityEvent(event).getMetadata()).containsEntry("skipReason", "duplicate_event");
        verify(processor, times(1)).process(any(SecurityEvent.class));
    }

    @Test
    @DisplayName("QF-55: a queued attempt whose event lost the claim's copies is marked processed and not deferred")
    void aQueuedAttemptMarksItsEventProcessedWithTheClaimItHolds() throws Exception {
        CountDownLatch marked = new CountDownLatch(1);
        AtomicReference<Boolean> markedWithTheClaim = new AtomicReference<>();
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore() {
            @Override
            public boolean markEventProcessed(String eventId, String ownerToken) {
                boolean result = super.markEventProcessed(eventId, ownerToken);
                markedWithTheClaim.set(result);
                marked.countDown();
                return result;
            }
        };
        SecurityMonitoringService monitor = mock(SecurityMonitoringService.class);
        SecurityEventProcessor processor = mock(SecurityEventProcessor.class);
        SecurityPlaneAgent agent = new SecurityPlaneAgent(monitor, store, mock(CentralAuditFacade.class), processor,
                properties("QueuedClaimedOwnershipAgent"), Runnable::run);
        agent.initialize();
        agent.start();
        ArgumentCaptor<SecurityMonitoringService.SecurityEventBatchProcessor> batch =
                ArgumentCaptor.forClass(SecurityMonitoringService.SecurityEventBatchProcessor.class);
        verify(monitor).setBatchProcessor(batch.capture());
        SecurityEvent event = event("evt-claim-queued");
        when(processor.process(any(SecurityEvent.class))).thenAnswer(invocation -> {
            SecurityEvent attempt = invocation.getArgument(0);
            losesTheClaimCopies(attempt);
            return completed(attempt);
        });

        try {
            batch.getValue().processBatch(List.of(event));

            assertThat(marked.await(5, TimeUnit.SECONDS)).isTrue();
            assertThat(markedWithTheClaim.get()).isTrue();
            verify(monitor, after(300).never()).deferEvent(any(SecurityEvent.class), anyString());
        } finally {
            agent.shutdown();
        }
    }
}
