package io.contexa.contexacore.autonomous.processor;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ColdPathEventProcessorTest {

    @Mock
    private Layer1ContextualStrategy contextualStrategy;

    @Mock
    private Layer2ExpertStrategy expertStrategy;

    @Mock
    private LlmAnalysisEventListener llmAnalysisEventListener;

    private ColdPathEventProcessor processor;

    @BeforeEach
    void setUp() {
        processor = new ColdPathEventProcessor(contextualStrategy, expertStrategy, llmAnalysisEventListener);
    }

    @Test
    @DisplayName("Layer1 ALLOW decision should not invoke Layer2")
    void layer1AllowDecision_shouldNotInvokeLayer2() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-1")
                .sourceIp("10.0.0.1")
                .build();
        event.addMetadata("requestPath", "/api/test");

        ThreatAssessment layer1Assessment = ThreatAssessment.builder()
                .riskScore(0.1)
                .confidence(0.95)
                .action(ZeroTrustAction.ALLOW.name())
                .reasoning("Normal traffic")
                .shouldEscalate(false)
                .build();

        when(contextualStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer1Assessment);

        // when
        ProcessingResult result = processor.processEvent(event, 0.2);

        // then
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getProcessingPath()).isEqualTo(ProcessingResult.ProcessingPath.COLD_PATH);
        verify(expertStrategy, never()).evaluate(any(SecurityEvent.class));
    }

    @Test
    @DisplayName("Layer1 ESCALATE should invoke Layer2")
    void layer1Escalate_shouldInvokeLayer2() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-2")
                .sourceIp("10.0.0.2")
                .build();
        event.addMetadata("requestPath", "/api/admin");

        ThreatAssessment layer1Assessment = ThreatAssessment.builder()
                .riskScore(0.6)
                .confidence(0.4)
                .action(ZeroTrustAction.ESCALATE.name())
                .reasoning("Low confidence, escalating")
                .shouldEscalate(true)
                .build();

        ThreatAssessment layer2Assessment = ThreatAssessment.builder()
                .riskScore(0.8)
                .confidence(0.9)
                .action(ZeroTrustAction.BLOCK.name())
                .reasoning("Confirmed threat")
                .shouldEscalate(false)
                .build();

        when(contextualStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer1Assessment);
        when(expertStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer2Assessment);

        // when
        ProcessingResult result = processor.processEvent(event, 0.5);

        // then
        assertThat(result.isSuccess()).isTrue();
        verify(expertStrategy).evaluate(any(SecurityEvent.class));
        assertThat(result.getAction()).isEqualTo(ZeroTrustAction.BLOCK.name());
    }

    @Test
    @DisplayName("Layer2 failure should use fallback result")
    void layer2Failure_shouldUseFallback() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-3")
                .sourceIp("10.0.0.3")
                .build();
        event.addMetadata("requestPath", "/api/resource");

        ThreatAssessment layer1Assessment = ThreatAssessment.builder()
                .riskScore(0.6)
                .confidence(0.3)
                .shouldEscalate(true)
                .build();

        when(contextualStrategy.evaluate(any(SecurityEvent.class))).thenReturn(layer1Assessment);
        when(expertStrategy.evaluate(any(SecurityEvent.class)))
                .thenThrow(new RuntimeException("Layer2 service unavailable"));

        // when
        ProcessingResult result = processor.processEvent(event, 0.5);

        // then
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getAction()).isEqualTo(ZeroTrustAction.CHALLENGE.name());
        assertThat(result.getConfidence()).isEqualTo(0.3);
    }

    @Test
    @DisplayName("Missing userId should return failure result")
    void missingUserId_shouldReturnFailure() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId(null)
                .sourceIp("10.0.0.4")
                .build();

        // when
        ProcessingResult result = processor.processEvent(event, 0.5);

        // then
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getProcessingPath()).isEqualTo(ProcessingResult.ProcessingPath.COLD_PATH);
    }

    @Test
    @DisplayName("getProcessingMode should return AI_ANALYSIS")
    void getProcessingMode_shouldReturnAiAnalysis() {
        // when
        ProcessingMode mode = processor.getProcessingMode();

        // then
        assertThat(mode).isEqualTo(ProcessingMode.AI_ANALYSIS);
    }
}
