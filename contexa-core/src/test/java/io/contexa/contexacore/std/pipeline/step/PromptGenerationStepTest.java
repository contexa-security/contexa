package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.LearningEvidenceScope;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PromptGenerationStepTest {

    @Test
    void executeShouldPropagatePromptTokenTelemetryIntoPipelineMetadata() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());
        PromptGenerator promptGenerator = new PromptGenerator(List.of(template));
        promptGenerator.registerTemplate(SecurityDecisionRequest.TEMPLATE_TYPE.name(), template);
        PromptGenerationStep step = new PromptGenerationStep(promptGenerator);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-prompt-step-001")
                .timestamp(LocalDateTime.of(2026, 3, 31, 11, 0))
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("203.0.113.10")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(noDataBaselineEvidence());

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of()));
        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PREPROCESSING,
                "systemMetadata");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL,
                new ContextRetriever.ContextRetrievalResult("contextInfo", List.<org.springframework.ai.document.Document>of(), java.util.Map.of()));

        Object result = step.execute(request, context).block();

        assertThat(result).isNotNull();
        assertThat(context.getMetadata("promptTokenEstimator", String.class)).isEqualTo("MODEL_AWARE_TOKEN_COUNTING_V1");
        assertThat(context.getMetadata("estimatedSystemTokens", Integer.class)).isPositive();
        assertThat(context.getMetadata("estimatedUserTokens", Integer.class)).isPositive();
        assertThat(context.getMetadata("estimatedTotalTokens", Integer.class)).isPositive();
        assertThat(context.getMetadata("promptBudgetEnforcementMode", String.class)).isEqualTo("LLM_VIEW_ENFORCED");
        assertThat(context.getMetadata("promptTransformationMode", String.class)).isIn("IDENTITY", "NORMALIZE_ONLY", "NORMALIZE_AND_COMPACT", "NORMALIZE_AND_FUSE");
        assertThat(context.getMetadata("promptRawTruthParity", Boolean.class)).isNotNull();
        assertThat(context.getMetadata("rawPromptHash", String.class)).startsWith("sha256:");
        assertThat(context.getMetadata("promptExecutionMetadata", Object.class)).isNotNull();
        assertThat(context.getMetadata("promptSourceContextFieldCount", Integer.class)).isPositive();
        assertThat(context.getMetadata("promptRawUserFieldCount", Integer.class)).isPositive();
        assertThat(context.getMetadata("promptFinalUserFieldCount", Integer.class)).isPositive();
        assertThat(context.getMetadata("promptUserFieldDiffCount", Integer.class)).isNotNull();
        assertThat(context.getMetadata("promptSourceContextExhaustive", Boolean.class)).isNotNull();
        assertThat(context.getMetadata("promptFieldStateCount", Integer.class)).isPositive();
        assertThat(context.getMetadata("promptBlockingFieldStateCount", Integer.class)).isNotNull();

        PromptExecutionMetadata executionMetadata = context.getMetadata("promptExecutionMetadata", PromptExecutionMetadata.class);
        assertThat(context.getMetadata("promptCompressionApplied", Boolean.class))
                .isEqualTo(executionMetadata.promptCompressionLedger().compressionApplied());
        Map<String, Object> eventMetadata = event.getMetadata();
        assertThat(eventMetadata).containsKeys(
                "promptSourceContextLedger",
                "promptRawUserFieldLedger",
                "promptFinalUserFieldLedger",
                "promptUserFieldDiffLedger",
                "promptFieldStateLedger",
                "promptFieldStateSummary");
        assertThat(eventMetadata.get("promptSourceContextLedger")).asList()
                .anySatisfy(item -> assertThat(item)
                        .asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.MAP)
                        .containsEntry("sourcePath", "securityEvent.metadata.requestPath")
                        .containsEntry("valueText", "/admin/api/security-test/sensitive/resource-001"));
        assertThat(eventMetadata.get("promptFieldStateLedger")).asList()
                .anySatisfy(item -> assertThat(item)
                        .asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.MAP)
                        .containsEntry("fieldKey", "source:securityEvent.metadata.requestPath")
                        .containsEntry("fieldState", "VALUE_PRESENT"));
    }

    private BaselineEvidenceSnapshot noDataBaselineEvidence() {
        return new BaselineEvidenceSnapshot(
                LearningEvidenceScope.PERSONAL,
                false,
                false,
                null,
                null,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                "",
                BaselineEvidenceStatus.NO_DATA,
                "");
    }
}
