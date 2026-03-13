package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class Layer2ExpertStrategyTest {

    @Mock
    private UnifiedLLMOrchestrator llmOrchestrator;

    @Mock
    private ApprovalService approvalService;

    @Mock
    private SecurityContextDataStore dataStore;

    @Mock
    private SecurityEventEnricher eventEnricher;

    @Mock
    private SecurityPromptTemplate promptTemplate;

    @Mock
    private UnifiedVectorService unifiedVectorService;

    @Mock
    private BehaviorVectorService behaviorVectorService;

    @Mock
    private BaselineLearningService baselineLearningService;

    @Mock
    private SecurityLearningService securityLearningService;

    private TieredStrategyProperties tieredStrategyProperties;

    private Layer2ExpertStrategy strategy;

    @BeforeEach
    void setUp() {
        tieredStrategyProperties = new TieredStrategyProperties();

        SecurityPromptTemplate.StructuredPrompt structuredPrompt =
                new SecurityPromptTemplate.StructuredPrompt("system text", "user text");
        when(promptTemplate.buildStructuredPrompt(any(), any(), any(), any()))
                .thenReturn(structuredPrompt);

        strategy = new Layer2ExpertStrategy(
                llmOrchestrator,
                approvalService,
                dataStore,
                eventEnricher,
                promptTemplate,
                unifiedVectorService,
                behaviorVectorService,
                baselineLearningService,
                tieredStrategyProperties,
                securityLearningService
        );
    }

    @Test
    @DisplayName("performDeepAnalysis should return valid SecurityDecision on successful LLM response")
    void performDeepAnalysis_llmSuccess_returnsValidDecision() {
        SecurityEvent event = buildTestEvent();
        String successJson = "{\"riskScore\":0.3,\"confidence\":0.85,\"action\":\"ALLOW\",\"reasoning\":\"Legitimate access confirmed\"}";
        when(llmOrchestrator.execute(any())).thenReturn(Mono.just(successJson));

        SecurityDecision decision = strategy.performDeepAnalysis(event);

        assertThat(decision).isNotNull();
        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(decision.getRiskScore()).isEqualTo(0.3);
        assertThat(decision.getConfidence()).isEqualTo(0.85);
        assertThat(decision.getProcessingLayer()).isEqualTo(2);
    }

    @Test
    @DisplayName("performDeepAnalysis should return failsafe BLOCK with riskScore 0.9 on LLM failure")
    void performDeepAnalysis_llmFailure_returnsFailsafeBlock() {
        SecurityEvent event = buildTestEvent();
        when(llmOrchestrator.execute(any()))
                .thenReturn(Mono.error(new RuntimeException("LLM service unavailable")));

        SecurityDecision decision = strategy.performDeepAnalysis(event);

        assertThat(decision).isNotNull();
        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(decision.getRiskScore()).isEqualTo(0.9);
        assertThat(decision.getConfidence()).isEqualTo(0.3);
        assertThat(decision.getProcessingLayer()).isEqualTo(2);
    }

    @Test
    @DisplayName("performDeepAnalysis should return failsafe BLOCK for null event")
    void performDeepAnalysis_nullEvent_returnsFailsafeBlock() {
        SecurityDecision decision = strategy.performDeepAnalysis(null);

        assertThat(decision).isNotNull();
        assertThat(decision.getAction()).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(decision.getRiskScore()).isEqualTo(0.9);
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
        String json = "{\"riskScore\":0.4,\"confidence\":0.8,\"action\":\"CHALLENGE\",\"reasoning\":\"Verify user\"}";
        when(llmOrchestrator.execute(any())).thenReturn(Mono.just(json));

        ThreatAssessment assessment = strategy.evaluate(event);

        assertThat(assessment).isNotNull();
        assertThat(assessment.isShouldEscalate()).isFalse();
        assertThat(assessment.getStrategyName()).isEqualTo("Layer2-Expert");
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
