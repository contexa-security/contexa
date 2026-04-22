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
import org.junit.jupiter.api.DisplayName;
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
    @DisplayName("Layer1 파이프라인은 표준 SecurityDecisionRequest를 구성해 오케스트레이터에 전달해야 한다")
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

        // eventId가 request context에 그대로 전달되어야 후단 evidence, prompt audit, outbox linkage가 맞물린다.
        assertThat(requestCaptor.getValue().getContext().getSecurityEvent().getEventId()).isEqualTo("event-layer1-pipeline-001");
        // 파이프라인 응답은 ZeroTrustAction과 audit score로 정확히 변환되어야 한다.
        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(decision.getReasoning()).isEqualTo("The request matches the normal work pattern.");
        assertThat(decision.resolveAuditRiskScore()).isEqualTo(0.22);
        assertThat(decision.resolveAuditConfidence()).isEqualTo(0.83);
    }

    @Test
    @DisplayName("Layer1 pipeline should fail closed when LLM execution exceeds layer budget")
    void analyzeWithContext_pipelineTimeout_returnsEscalationFallback() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer1().getTimeout().setLlmMs(10);

        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.never());

        Layer1ContextualStrategy strategy = new Layer1ContextualStrategy(
                null,
                null,
                new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), properties),
                null,
                null,
                null,
                null,
                null,
                null,
                new PromptContextAuthorizationService(),
                null,
                pipelineOrchestrator,
                properties
        );

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-layer1-timeout-001")
                .timestamp(LocalDateTime.of(2026, 4, 22, 10, 0))
                .userId("alice")
                .sessionId("session-timeout")
                .sourceIp("203.0.113.10")
                .description("POST /api/customer/export")
                .build();

        SecurityDecision decision = strategy.analyzeWithContext(event);

        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(decision.getTechnicalFallbackApplied()).isTrue();
        assertThat(decision.getProcessingLayer()).isEqualTo(1);
    }
}
