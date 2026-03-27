package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class Layer2ExpertStrategyTest {

    @Mock
    private ApprovalService approvalService;

    @Mock
    private PipelineOrchestrator pipelineOrchestrator;

    private Layer2ExpertStrategy strategy;

    @BeforeEach
    void setUp() {
        strategy = new Layer2ExpertStrategy(
                null,
                approvalService,
                null,
                new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), new TieredStrategyProperties()),
                null,
                null,
                null,
                new TieredStrategyProperties(),
                null,
                null,
                null,
                null,
                new PromptContextAuthorizationService(),
                null,
                pipelineOrchestrator
        );
    }

    @Test
    @DisplayName("performDeepAnalysis should use standard pipeline and return valid SecurityDecision")
    void performDeepAnalysis_pipelineSuccess_returnsValidDecision() {
        SecurityEvent event = buildTestEvent();
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.3);
        response.setConfidence(0.85);
        response.setAction("ALLOW");
        response.setReasoning("Legitimate access confirmed");
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        SecurityDecision decision = strategy.performDeepAnalysis(event);

        ArgumentCaptor<SecurityDecisionRequest> requestCaptor = ArgumentCaptor.forClass(SecurityDecisionRequest.class);
        verify(pipelineOrchestrator).execute(requestCaptor.capture(), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class));

        assertThat(requestCaptor.getValue().getContext().getSecurityEvent().getEventId()).isEqualTo("test-event-layer2");
        assertThat(decision).isNotNull();
        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(decision.resolveAuditRiskScore()).isEqualTo(0.3);
        assertThat(decision.resolveAuditConfidence()).isEqualTo(0.85);
        assertThat(decision.getProcessingLayer()).isEqualTo(2);
    }

    @Test
    @DisplayName("performDeepAnalysis should return failsafe BLOCK when pipeline fails")
    void performDeepAnalysis_pipelineFailure_returnsFailsafeBlock() {
        SecurityEvent event = buildTestEvent();
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.error(new RuntimeException("pipeline unavailable")));

        SecurityDecision decision = strategy.performDeepAnalysis(event);

        assertThat(decision).isNotNull();
        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(decision.getProcessingLayer()).isEqualTo(2);
        assertThat(decision.getReasoning()).contains("failsafe blocking");
    }

    @Test
    @DisplayName("performDeepAnalysis should return failsafe BLOCK for null event")
    void performDeepAnalysis_nullEvent_returnsFailsafeBlock() {
        SecurityDecision decision = strategy.performDeepAnalysis(null);

        assertThat(decision).isNotNull();
        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("getLayerName should return Layer2")
    void getLayerName_returnsLayer2() {
        assertThat(strategy.getStrategyName()).isEqualTo("Layer2-Expert-Strategy");
    }

    @Test
    @DisplayName("evaluate should return ThreatAssessment with shouldEscalate=false")
    void evaluate_returnsAssessmentWithShouldEscalateFalse() {
        SecurityEvent event = buildTestEvent();
        SecurityDecisionResponse response = new SecurityDecisionResponse();
        response.setRiskScore(0.4);
        response.setConfidence(0.8);
        response.setAction("CHALLENGE");
        response.setReasoning("Verify user");
        when(pipelineOrchestrator.execute(any(SecurityDecisionRequest.class), any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class)))
                .thenReturn(Mono.just(response));

        ThreatAssessment assessment = strategy.evaluate(event);

        assertThat(assessment).isNotNull();
        assertThat(assessment.isShouldEscalate()).isFalse();
        assertThat(assessment.getStrategyName()).isEqualTo("Layer2-Expert");
        assertThat(assessment.getAction()).isEqualTo("CHALLENGE");
    }

    private SecurityEvent buildTestEvent() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("httpMethod", "POST");
        metadata.put("requestPath", "/api/admin/config");

        return SecurityEvent.builder()
                .eventId("test-event-layer2")
                .userId("user-002")
                .sessionId("session-002")
                .sourceIp("10.0.0.50")
                .userAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
                .timestamp(LocalDateTime.now())
                .metadata(metadata)
                .build();
    }
}
