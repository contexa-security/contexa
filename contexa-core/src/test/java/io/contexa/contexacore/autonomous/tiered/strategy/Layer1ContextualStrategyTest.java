package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.properties.TieredStrategyProperties;
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

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class Layer1ContextualStrategyTest {

    @Mock
    private UnifiedLLMOrchestrator llmOrchestrator;

    @Mock
    private SecurityContextDataStore dataStore;

    @Mock
    private SecurityEventEnricher eventEnricher;

    @Mock
    private SecurityPromptTemplate promptTemplate;

    @Mock
    private BehaviorVectorService behaviorVectorService;

    @Mock
    private UnifiedVectorService unifiedVectorService;

    @Mock
    private BaselineLearningService baselineLearningService;

    @Mock
    private SecurityLearningService securityLearningService;

    private TieredStrategyProperties tieredStrategyProperties;

    private Layer1ContextualStrategy strategy;

    @BeforeEach
    void setUp() {
        tieredStrategyProperties = new TieredStrategyProperties();

        SecurityPromptTemplate.StructuredPrompt structuredPrompt =
                new SecurityPromptTemplate.StructuredPrompt("system text", "user text");
        when(promptTemplate.buildStructuredPrompt(any(), any(), any(), any()))
                .thenReturn(structuredPrompt);

        strategy = new Layer1ContextualStrategy(
                llmOrchestrator,
                unifiedVectorService,
                dataStore,
                eventEnricher,
                promptTemplate,
                behaviorVectorService,
                baselineLearningService,
                securityLearningService,
                tieredStrategyProperties
        );
    }

    @Test
    @DisplayName("evaluate should return shouldEscalate=false when LLM decides ALLOW")
    void evaluate_allowDecision_shouldEscalateFalse() {
        SecurityEvent event = buildTestEvent();
        String allowJson = "{\"riskScore\":0.1,\"confidence\":0.9,\"action\":\"ALLOW\",\"reasoning\":\"Normal activity\"}";
        when(llmOrchestrator.execute(any())).thenReturn(Mono.just(allowJson));

        ThreatAssessment assessment = strategy.evaluate(event);

        assertThat(assessment).isNotNull();
        assertThat(assessment.isShouldEscalate()).isFalse();
        assertThat(assessment.getAction()).isEqualTo("ALLOW");
        assertThat(assessment.getStrategyName()).isEqualTo("Layer1-Contextual");
    }

    @Test
    @DisplayName("evaluate should return shouldEscalate=true when LLM decides ESCALATE")
    void evaluate_escalateDecision_shouldEscalateTrue() {
        SecurityEvent event = buildTestEvent();
        String escalateJson = "{\"riskScore\":0.7,\"confidence\":0.5,\"action\":\"ESCALATE\",\"reasoning\":\"Suspicious patterns detected\"}";
        when(llmOrchestrator.execute(any())).thenReturn(Mono.just(escalateJson));

        ThreatAssessment assessment = strategy.evaluate(event);

        assertThat(assessment).isNotNull();
        assertThat(assessment.isShouldEscalate()).isTrue();
        assertThat(assessment.getAction()).isEqualTo("ESCALATE");
    }

    @Test
    @DisplayName("evaluate should fallback to ESCALATE with riskScore 0.7 on LLM timeout")
    void evaluate_llmTimeout_fallbackToEscalate() {
        SecurityEvent event = buildTestEvent();
        when(llmOrchestrator.execute(any()))
                .thenReturn(Mono.delay(Duration.ofSeconds(30)).map(l -> "delayed"));

        ThreatAssessment assessment = strategy.evaluate(event);

        assertThat(assessment).isNotNull();
        assertThat(assessment.isShouldEscalate()).isTrue();
        assertThat(assessment.getRiskScore()).isEqualTo(0.7);
        assertThat(assessment.getAction()).isEqualTo("ESCALATE");
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
