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
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SecurityPlaneAgentTest {

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

    @Mock
    private Executor llmAnalysisExecutor;

    @Mock
    private AiSecurityDecisionObservationWriter aiSecurityDecisionObservationWriter;

    private SecurityPlaneAgent agent;

    @BeforeEach
    void setUp() {
        SecurityPlaneProperties.AgentSettings agentSettings = new SecurityPlaneProperties.AgentSettings();
        SecurityPlaneProperties.LlmExecutorSettings llmExecutorSettings = new SecurityPlaneProperties.LlmExecutorSettings();
        agentSettings.setName("TestAgent");
        agentSettings.setAutoStart(false);
        when(securityPlaneProperties.getAgent()).thenReturn(agentSettings);
        when(securityPlaneProperties.getLlmExecutor()).thenReturn(llmExecutorSettings);

        agent = new SecurityPlaneAgent(
                securityMonitor, dataStore, centralAuditFacade,
                securityEventProcessor, securityPlaneProperties, llmAnalysisExecutor);
        agent.initialize();
    }

    @Test
    @DisplayName("processSecurityEvent should process event normally")
    void processSecurityEvent_shouldProcessNormally() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-normal")
                .userId("user-1")
                .sourceIp("10.0.0.1")
                .build();

        SecurityEventContext expectedContext = SecurityEventContext.builder()
                .securityEvent(event)
                .processingStatus(SecurityEventContext.ProcessingStatus.COMPLETED)
                .build();

        when(dataStore.claimEventProcessing(anyString())).thenReturn(SecurityContextDataStore.EventProcessingClaim.ACQUIRED);
        when(securityEventProcessor.process(any(SecurityEvent.class))).thenReturn(expectedContext);

        SecurityEventContext result = agent.processSecurityEvent(event);

        assertThat(result).isEqualTo(expectedContext);
        verify(securityEventProcessor).process(event);
        verify(dataStore).markEventProcessed(anyString());
    }

    @Test
    @DisplayName("이미 처리 완료된 이벤트는 duplicate 로 skip 되어야 한다")
    void duplicateEvent_shouldBeSkipped() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-duplicate")
                .userId("user-2")
                .build();

        when(dataStore.claimEventProcessing(anyString())).thenReturn(SecurityContextDataStore.EventProcessingClaim.PROCESSED);

        SecurityEventContext result = agent.processSecurityEvent(event);

        assertThat(result.getProcessingStatus()).isEqualTo(SecurityEventContext.ProcessingStatus.SKIPPED);
        assertThat(result.getMetadata()).containsEntry("skipReason", "duplicate_event");
        verify(securityEventProcessor, never()).process(any(SecurityEvent.class));
    }

    @Test
    @DisplayName("다른 스레드에서 처리 중인 이벤트는 in-flight skip 으로 반환되어야 한다")
    void inflightEvent_shouldBeMarkedAsInflightSkip() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-inflight-skip")
                .userId("user-2")
                .build();

        when(dataStore.claimEventProcessing(anyString())).thenReturn(SecurityContextDataStore.EventProcessingClaim.IN_FLIGHT);

        SecurityEventContext result = agent.processSecurityEvent(event);

        assertThat(result.getProcessingStatus()).isEqualTo(SecurityEventContext.ProcessingStatus.SKIPPED);
        assertThat(result.getMetadata()).containsEntry("skipReason", "event_processing_in_flight");
        verify(securityEventProcessor, never()).process(any(SecurityEvent.class));
    }

    @Test
    @DisplayName("start/stop should transition agent state correctly")
    void startStop_shouldTransitionState() {
        agent.start();
        agent.stop();
        agent.start();
        agent.start();
    }

    @Test
    @DisplayName("processSecurityEvent exception should propagate as RuntimeException")
    void processSecurityEvent_exception_shouldPropagate() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-error")
                .userId("user-4")
                .sourceIp("10.0.0.4")
                .build();

        when(dataStore.claimEventProcessing(anyString())).thenReturn(SecurityContextDataStore.EventProcessingClaim.ACQUIRED);
        when(securityEventProcessor.process(any(SecurityEvent.class)))
                .thenThrow(new RuntimeException("Processing error"));

        assertThatThrownBy(() -> agent.processSecurityEvent(event))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Event processing failed");
        verify(dataStore).releaseEventProcessing(anyString());
    }

    @Test
    @DisplayName("배치 처리 중 event whole-budget timeout이 발생하면 defer 경로로 되돌려야 한다")
    void batchProcessingTimeout_shouldDeferEvent() throws Exception {
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        properties.getAgent().setAutoStart(false);
        properties.getAgent().setName("TimeoutAgent");
        properties.getAgent().setEventTimeoutMs(1001L);
        properties.getAgent().setMaxDeferredRetries(1);

        when(securityPlaneProperties.getAgent()).thenReturn(properties.getAgent());
        when(securityPlaneProperties.getLlmExecutor()).thenReturn(properties.getLlmExecutor());
        when(dataStore.claimEventProcessing(anyString())).thenReturn(SecurityContextDataStore.EventProcessingClaim.ACQUIRED);
        clearInvocations(securityMonitor);

        ExecutorService actualLlmExecutor = Executors.newSingleThreadExecutor();
        SecurityPlaneAgent timedAgent = new SecurityPlaneAgent(
                securityMonitor, dataStore, centralAuditFacade,
                securityEventProcessor, securityPlaneProperties, actualLlmExecutor);
        timedAgent.setAiSecurityDecisionObservationWriterSupplier(() -> aiSecurityDecisionObservationWriter);
        timedAgent.initialize();
        timedAgent.start();

        ArgumentCaptor<SecurityMonitoringService.SecurityEventBatchProcessor> processorCaptor =
                ArgumentCaptor.forClass(SecurityMonitoringService.SecurityEventBatchProcessor.class);
        verify(securityMonitor, timeout(1000)).setBatchProcessor(processorCaptor.capture());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-timeout")
                .userId("user-timeout")
                .sessionId("session-timeout")
                .build();
        when(aiSecurityDecisionObservationWriter.recordDecision(
                eq(event), any(ProcessingResult.class), eq(ZeroTrustAction.PENDING_ANALYSIS)))
                .thenReturn("timeout-observation-1");

        when(securityEventProcessor.process(any(SecurityEvent.class))).thenAnswer(invocation -> {
            Thread.sleep(1500L);
            return SecurityEventContext.builder()
                    .securityEvent(invocation.getArgument(0))
                    .processingStatus(SecurityEventContext.ProcessingStatus.COMPLETED)
                    .build();
        });

        processorCaptor.getValue().processBatch(List.of(event));

        verify(securityMonitor, timeout(4000)).deferEvent(eq(event), anyString());
        verify(dataStore, timeout(4000)).releaseEventProcessing(eq("evt-timeout"));
        verify(dataStore, never()).markEventProcessed(eq("evt-timeout"));
        assertThat(event.getMetadata()).containsEntry("processingTimedOut", true);
        assertThat(event.getMetadata()).containsEntry("lateProcessingResultDiscarded", true);
        ArgumentCaptor<ProcessingResult> timeoutResultCaptor = ArgumentCaptor.forClass(ProcessingResult.class);
        verify(aiSecurityDecisionObservationWriter, timeout(4000)).recordDecision(
                eq(event), timeoutResultCaptor.capture(), eq(ZeroTrustAction.PENDING_ANALYSIS));
        assertThat(timeoutResultCaptor.getValue().getStatus()).isEqualTo(ProcessingResult.ProcessingStatus.TIMEOUT);
        assertThat(timeoutResultCaptor.getValue().getErrorMessage()).contains("timeout");
        assertThat(event.getMetadata()).containsEntry("timeoutObservationRecorded", true);
        assertThat(event.getMetadata()).containsEntry("timeoutObservationId", "timeout-observation-1");

        timedAgent.shutdown();
        actualLlmExecutor.shutdownNow();
    }

    @Test
    @DisplayName("배치 처리 중 동일 eventId 가 아직 in-flight 이면 defer 경로로 되돌려야 한다")
    void inflightEventDuringBatch_shouldDeferEvent() throws Exception {
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        properties.getAgent().setAutoStart(false);
        properties.getAgent().setName("InflightAgent");
        properties.getAgent().setEventTimeoutMs(5000L);
        properties.getAgent().setMaxDeferredRetries(1);

        when(securityPlaneProperties.getAgent()).thenReturn(properties.getAgent());
        when(securityPlaneProperties.getLlmExecutor()).thenReturn(properties.getLlmExecutor());
        when(dataStore.claimEventProcessing(anyString())).thenReturn(SecurityContextDataStore.EventProcessingClaim.IN_FLIGHT);
        clearInvocations(securityMonitor);

        ExecutorService actualLlmExecutor = Executors.newSingleThreadExecutor();
        SecurityPlaneAgent inflightAgent = new SecurityPlaneAgent(
                securityMonitor, dataStore, centralAuditFacade,
                securityEventProcessor, securityPlaneProperties, actualLlmExecutor);
        inflightAgent.initialize();
        inflightAgent.start();

        ArgumentCaptor<SecurityMonitoringService.SecurityEventBatchProcessor> processorCaptor =
                ArgumentCaptor.forClass(SecurityMonitoringService.SecurityEventBatchProcessor.class);
        verify(securityMonitor, timeout(1000)).setBatchProcessor(processorCaptor.capture());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-inflight")
                .userId("user-inflight")
                .sessionId("session-inflight")
                .build();

        processorCaptor.getValue().processBatch(List.of(event));

        verify(securityMonitor, timeout(4000)).deferEvent(eq(event), eq("event_processing_in_flight"));

        inflightAgent.shutdown();
        actualLlmExecutor.shutdownNow();
    }
}
