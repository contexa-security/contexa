package io.contexa.contexacore.autonomous;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * An Error raised while an event is analysed must release the event's processing claim; otherwise the event stays
 * IN_FLIGHT and is never analysed again in this JVM.
 */
class SecurityPlaneAgentErrorReleaseTest {

    @Test
    void anErrorDuringAnalysisReleasesTheClaimSoTheEventCanBeAnalysedAgain() {
        SecurityEventProcessor processor = mock(SecurityEventProcessor.class);
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        properties.getAgent().setAutoStart(false);
        properties.getAgent().setName("ErrorReleaseAgent");
        SecurityPlaneAgent agent = new SecurityPlaneAgent(mock(SecurityMonitoringService.class),
                new InMemorySecurityContextDataStore(), mock(CentralAuditFacade.class), processor, properties,
                Runnable::run);
        agent.initialize();
        SecurityEvent event = SecurityEvent.builder().eventId("evt-error-release").userId("user-1")
                .sourceIp("10.0.0.1").build();

        when(processor.process(any(SecurityEvent.class))).thenThrow(new StackOverflowError("analysis recursion"));
        assertThatThrownBy(() -> agent.processSecurityEvent(event)).isInstanceOf(StackOverflowError.class);

        SecurityEventContext completed = SecurityEventContext.builder()
                .securityEvent(event)
                .processingStatus(SecurityEventContext.ProcessingStatus.COMPLETED)
                .build();
        when(processor.process(any(SecurityEvent.class))).thenReturn(completed);
        SecurityEventContext retried = agent.processSecurityEvent(event);

        assertThat(retried.getProcessingStatus()).isEqualTo(SecurityEventContext.ProcessingStatus.COMPLETED);
    }
}
