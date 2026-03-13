package io.contexa.contexacore.autonomous;

import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.concurrent.Executor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
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

    private SecurityPlaneAgent agent;

    @BeforeEach
    void setUp() {
        SecurityPlaneProperties.AgentSettings agentSettings = new SecurityPlaneProperties.AgentSettings();
        agentSettings.setName("TestAgent");
        agentSettings.setAutoStart(false);
        when(securityPlaneProperties.getAgent()).thenReturn(agentSettings);

        agent = new SecurityPlaneAgent(
                securityMonitor, dataStore, centralAuditFacade,
                securityEventProcessor, securityPlaneProperties, llmAnalysisExecutor);
        agent.initialize();
    }

    @Test
    @DisplayName("processSecurityEvent should process event normally")
    void processSecurityEvent_shouldProcessNormally() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-1")
                .sourceIp("10.0.0.1")
                .build();

        SecurityEventContext expectedContext = SecurityEventContext.builder()
                .securityEvent(event)
                .processingStatus(SecurityEventContext.ProcessingStatus.COMPLETED)
                .build();

        when(dataStore.tryMarkEventAsProcessed(anyString())).thenReturn(true);
        when(securityEventProcessor.process(any(SecurityEvent.class))).thenReturn(expectedContext);

        // when
        SecurityEventContext result = agent.processSecurityEvent(event);

        // then
        assertThat(result).isEqualTo(expectedContext);
        verify(securityEventProcessor).process(event);
    }

    @Test
    @DisplayName("Duplicate event should be skipped when tryMarkEventAsProcessed returns false")
    void duplicateEvent_shouldBeSkipped() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-2")
                .build();

        when(dataStore.tryMarkEventAsProcessed(anyString())).thenReturn(false);

        // when
        SecurityEventContext result = agent.processSecurityEvent(event);

        // then
        assertThat(result.getProcessingStatus()).isEqualTo(SecurityEventContext.ProcessingStatus.SKIPPED);
        assertThat(result.getMetadata()).containsEntry("skipReason", "duplicate_event");
        verify(securityEventProcessor, never()).process(any(SecurityEvent.class));
    }

    @Test
    @DisplayName("start/stop should transition agent state correctly")
    void startStop_shouldTransitionState() {
        // when - start
        agent.start();

        // then - can stop after start
        agent.stop();

        // start again should work
        agent.start();

        // second start should not throw (already running)
        agent.start();
    }

    @Test
    @DisplayName("processSecurityEvent exception should propagate as RuntimeException")
    void processSecurityEvent_exception_shouldPropagate() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-4")
                .sourceIp("10.0.0.4")
                .build();

        when(dataStore.tryMarkEventAsProcessed(anyString())).thenReturn(true);
        when(securityEventProcessor.process(any(SecurityEvent.class)))
                .thenThrow(new RuntimeException("Processing error"));

        // when/then
        assertThatThrownBy(() -> agent.processSecurityEvent(event))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Event processing failed");
    }
}
