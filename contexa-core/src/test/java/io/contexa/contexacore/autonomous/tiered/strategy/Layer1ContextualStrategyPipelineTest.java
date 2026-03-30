package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class Layer1ContextualStrategyPipelineTest {

    @Mock
    private PipelineOrchestrator pipelineOrchestrator;

    @Test
    void analyzeWithContextShouldUseStandardPipeline() {
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setAction("ALLOW");
        response.setReasoning("The request matches the normal work pattern.");
        response.setRiskScore(0.22);
        response.setConfidence(0.83);

        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        Layer1ContextualStrategy strategy = new Layer1ContextualStrategy(
                null,
                null,
                new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), new TieredStrategyProperties()),
                null,
                null,
                null,
                null,
                null,
                null,
                new PromptContextAuthorizationService(),
                null,
                pipelineOrchestrator,
                new TieredStrategyProperties()
        );

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-layer1-pipeline-001")
                .timestamp(LocalDateTime.of(2026, 3, 24, 14, 0))
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("203.0.113.10")
                .description("POST /api/customer/export")
                .build();
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("requestPath", "/api/customer/export");

        SecurityDecision decision = strategy.analyzeWithContext(event);

        ArgumentCaptor<SecurityDecisionRequest> requestCaptor = ArgumentCaptor.forClass(SecurityDecisionRequest.class);
        verify(pipelineOrchestrator).execute(requestCaptor.capture(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class));

        assertThat(requestCaptor.getValue().getContext().getSecurityEvent().getEventId()).isEqualTo("event-layer1-pipeline-001");
        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(decision.getReasoning()).isEqualTo("The request matches the normal work pattern.");
        assertThat(decision.resolveAuditRiskScore()).isEqualTo(0.22);
        assertThat(decision.resolveAuditConfidence()).isEqualTo(0.83);
    }
}
