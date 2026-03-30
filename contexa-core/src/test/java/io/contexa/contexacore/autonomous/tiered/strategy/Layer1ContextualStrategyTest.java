package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class Layer1ContextualStrategyTest {

    @Mock
    private PipelineOrchestrator pipelineOrchestrator;

    private Layer1ContextualStrategy strategy;

    @BeforeEach
    void setUp() {
        strategy = new Layer1ContextualStrategy(
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
    }

    @Test
    @DisplayName("evaluate should return shouldEscalate=false when pipeline decides ALLOW")
    void evaluate_allowDecision_shouldEscalateFalse() {
        SecurityEvent event = buildTestEvent();
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.1);
        response.setConfidence(0.9);
        response.setAction("ALLOW");
        response.setReasoning("Normal activity");
        when(pipelineOrchestrator.execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        ThreatAssessment assessment = strategy.evaluate(event);

        assertThat(assessment).isNotNull();
        assertThat(assessment.isShouldEscalate()).isFalse();
        assertThat(assessment.getAction()).isEqualTo("ALLOW");
        assertThat(assessment.getStrategyName()).isEqualTo("Layer1-Contextual");
        assertThat(assessment.getLlmAuditConfidence()).isEqualTo(0.9);
    }

    @Test
    @DisplayName("evaluate should return shouldEscalate=true when pipeline decides ESCALATE")
    void evaluate_escalateDecision_shouldEscalateTrue() {
        SecurityEvent event = buildTestEvent();
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.7);
        response.setConfidence(0.5);
        response.setAction("ESCALATE");
        response.setReasoning("Suspicious patterns detected");
        when(pipelineOrchestrator.execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        ThreatAssessment assessment = strategy.evaluate(event);

        assertThat(assessment).isNotNull();
        assertThat(assessment.isShouldEscalate()).isTrue();
        assertThat(assessment.getAction()).isEqualTo("ESCALATE");
        assertThat(assessment.getRecommendedActions()).contains("ESCALATE_TO_EXPERT");
    }

    @Test
    @DisplayName("evaluate should fallback to ESCALATE when pipeline fails")
    void evaluate_pipelineFailure_fallbackToEscalate() {
        SecurityEvent event = buildTestEvent();
        when(pipelineOrchestrator.execute(any(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.error(new RuntimeException("pipeline unavailable")));

        ThreatAssessment assessment = strategy.evaluate(event);

        assertThat(assessment).isNotNull();
        assertThat(assessment.isShouldEscalate()).isTrue();
        assertThat(assessment.getAction()).isEqualTo("ESCALATE");
        assertThat(assessment.getRecommendedActions()).contains("ESCALATE_TO_EXPERT");
    }

    @Test
    @DisplayName("getLayerName should return Layer1")
    void getLayerName_returnsLayer1() {
        assertThat(strategy.getStrategyName()).isEqualTo("Layer1");
    }

    private SecurityEvent buildTestEvent() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("httpMethod", "GET");
        metadata.put("requestPath", "/api/data");

        return SecurityEvent.builder()
                .eventId("test-event-layer1")
                .userId("user-001")
                .sessionId("session-001")
                .sourceIp("192.168.1.100")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                .timestamp(LocalDateTime.now())
                .metadata(metadata)
                .build();
    }
}
