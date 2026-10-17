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
package io.contexa.contexacore.autonomous.tiered.strategy;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.ThreatAssessment;
import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import io.contexa.contexacore.autonomous.processor.ColdPathEventProcessor;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContract;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.pipeline.step.PromptEvidenceComposer;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptTraceStore;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageAssembler;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * N-RSN-1: a Layer2 second pass that does not call the model again (W3-9, nothing new) keeps the first pass's model
 * verdict and, with it, the first pass's model values: the reason codes with the fact IDs they cite, the risk score,
 * the confidence and the provenance of these fields. The reason codes reach Layer2 on the cold path's own hand-over,
 * not on a key a test puts by hand (as N-L2-1 asks of the first prompt); the sealed decision record holds them.
 */
class FirstPassModelValuesHandOverTest {

    /** The host's mapper writes the assessment times (LocalDateTime), as Spring Boot's does for the assembler bean. */
    private static final ObjectMapper JSON = new ObjectMapper().registerModule(new JavaTimeModule());
    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };
    private static final List<SecurityDecisionOutputContract.Citation> REASON_CODES = List.of(
            new SecurityDecisionOutputContract.Citation("MIN_P3_POLICY_NOT_SATISFIED", "F4"),
            new SecurityDecisionOutputContract.Citation("DEVIATION_SIZE", "F1"));
    private static final Map<String, String> PROVENANCE = Map.of("reasoning", "MODEL", "riskScore", "MODEL",
            "confidence", "MODEL", "reasonCodes", "MODEL");

    private final PipelineOrchestrator pipelineOrchestrator = mock(PipelineOrchestrator.class);
    private final SealedEvidencePromptTraceStore traceStore = new SealedEvidencePromptTraceStore();

    @Test
    void theDecisionKeepsTheFirstPassModelValuesWhenLayer2DoesNotCallTheModel() {
        SecurityEvent event = event("n-rsn-1-result");

        ProcessingResult result = processor(event).processEvent(event, 0.5);

        verify(pipelineOrchestrator, never()).execute(any(SecurityDecisionRequest.class),
                any(PipelineConfiguration.class), eq(SecurityDecisionResponse.class));
        assertThat(event.getMetadata()).containsEntry("layer2ModelCallSkipped", "NO_NEW_FACTS")
                .doesNotContainKey("firstPassReasonCodes");
        assertThat(result.getProposedAction()).isEqualTo(ZeroTrustAction.ESCALATE.name());
        assertThat(result.getReasonCodes()).containsExactlyElementsOf(REASON_CODES);
        assertThat(result.resolveAuditRiskScore()).isEqualTo(0.78);
        assertThat(result.resolveAuditConfidence()).isEqualTo(0.97);
        assertThat(result.getFieldProvenance()).isEqualTo(PROVENANCE);
    }

    @Test
    void theSealedDecisionRecordKeepsTheFirstPassModelValues() throws Exception {
        SecurityEvent event = event("n-rsn-1-seal");
        ProcessingResult result = processor(event).processEvent(event, 0.5);
        SecurityEventContext context = new SecurityEventContext(event);
        context.addMetadata("processingResult", result);

        SealedEvidencePackage sealed = new SealedEvidencePackageAssembler(JSON,
                new CanonicalSecurityContextSerializer(JSON), new SealedEvidencePackageIntegrity(), traceStore)
                .assemble(context);

        assertThat(sealed).isNotNull();
        Map<String, Object> decision = JSON.readValue(sealed.getDecisionJson(), MAP);
        assertThat(decision)
                .containsEntry("decisionAppliedStage", "LAYER2")
                .containsEntry("reasonCodes", List.of(Map.of("code", "MIN_P3_POLICY_NOT_SATISFIED", "fact", "F4"),
                        Map.of("code", "DEVIATION_SIZE", "fact", "F1")))
                .containsEntry("riskScore", 0.78)
                .containsEntry("confidence", 0.97)
                .containsEntry("fieldProvenance", PROVENANCE);
    }

    /** The cold path with a Layer1 that leaves on the event what its pipeline leaves, and the real Layer2. */
    private ColdPathEventProcessor processor(SecurityEvent event) {
        PromptGenerator generator = mock(PromptGenerator.class);
        when(generator.generatePrompt(any(), any(), any())).thenReturn(drawn());
        PromptEvidenceComposer composer = new PromptEvidenceComposer(generator);
        Layer1ContextualStrategy layer1 = mock(Layer1ContextualStrategy.class);
        when(layer1.evaluate(any(SecurityEvent.class))).thenAnswer(invocation -> {
            // The Layer1 pipeline draws the prompt (the composer keeps the first one for a second pass, N-L2-1) and
            // records its past record search; the capture aspects keep the prompt the seal holds.
            SecurityDecisionContext drawnFor = new SecurityDecisionContext(event,
                    new SecurityDecisionStandardPromptTemplate.SessionContext(), null, List.of());
            composer.compose(new SecurityDecisionRequest(drawnFor), new PipelineExecutionContext("n-rsn-1-first"));
            event.addMetadata("ragRetrievalState", "AVAILABLE");
            traceStore.capture(drawnFor, drawn());
            traceStore.complete(event);
            return firstPassEscalation();
        });
        Layer2ExpertStrategy layer2 = new Layer2ExpertStrategy(null, null, new SecurityEventEnricher(),
                new SecurityDecisionStandardPromptTemplate(new SecurityEventEnricher(), new TieredStrategyProperties()),
                null, null, null, new TieredStrategyProperties(), null, null, null, null,
                new PromptContextAuthorizationService(), null, pipelineOrchestrator);
        return new ColdPathEventProcessor(layer1, layer2, mock(LlmAnalysisEventListener.class));
    }

    /** The first pass's model verdict as Layer1 hands it to the cold path. */
    private static ThreatAssessment firstPassEscalation() {
        return ThreatAssessment.builder()
                .strategyName("Layer1-Contextual")
                .action(ZeroTrustAction.ESCALATE.name())
                .autonomousAction(ZeroTrustAction.ESCALATE.name())
                .shouldEscalate(true)
                .llmDecisionPresent(true)
                .technicalFallbackApplied(false)
                .llmAuditRiskScore(0.78)
                .llmAuditConfidence(0.97)
                .reasoning("Policy requires a covering approval, but none exists for GB-500.")
                .reasonCodes(REASON_CODES)
                .fieldProvenance(PROVENANCE)
                .build();
    }

    private static PromptGenerationResult drawn() {
        return new PromptGenerationResult(null, "SYSTEM", "FIRST PROMPT",
                Map.of("userPromptLayoutVersion", Layer2SecondPass.V20_LAYOUT), null);
    }

    private static SecurityEvent event(String requestId) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("requestId", requestId);
        metadata.put("requestPath", "/api/projects/GB-500/exports");
        return SecurityEvent.builder().eventId("evt-" + requestId).userId("user-1").sessionId("session-1")
                .sourceIp("10.0.0.9").metadata(metadata).build();
    }
}
