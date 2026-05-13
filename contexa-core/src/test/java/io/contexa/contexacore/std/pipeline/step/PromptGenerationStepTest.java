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
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
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
        assertThat(context.getMetadata("promptCacheSystemStable", Boolean.class)).isTrue();
        assertThat(context.getMetadata("promptCacheSystemHash", String.class)).startsWith("sha256:");
        assertThat(context.getMetadata("promptCacheContextMode", String.class)).isEqualTo("FULL_FIELD_PRESERVED");
        assertThat(context.getMetadata("pqaReferencePrompt", String.class)).isEqualTo("FINAL_USER_PROMPT");
        assertThat(context.getMetadata("pqaRawPromptRole", String.class)).isEqualTo("TRACEABILITY_ONLY");

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
        assertThat(eventMetadata)
                .containsEntry("promptCacheSystemStable", true)
                .containsEntry("promptCacheContextMode", "FULL_FIELD_PRESERVED")
                .containsEntry("pqaReferencePrompt", "FINAL_USER_PROMPT")
                .containsEntry("pqaRawPromptRole", "TRACEABILITY_ONLY");
        assertThat(eventMetadata.get("promptCacheSystemHash")).asString().startsWith("sha256:");
        assertThat(eventMetadata.get("promptSourceContextLedger")).asList()
                .anySatisfy(item -> assertThat(item)
                        .asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.MAP)
                        .containsEntry("sourcePath", "securityEvent.metadata.requestPath")
                        .containsEntry("valueText", "/admin/api/security-test/sensitive/resource-001"));
        assertThat(eventMetadata.get("promptSourceContextLedger")).asList()
                .anySatisfy(item -> assertThat(item)
                        .asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.MAP)
                        .containsEntry("sourcePath", "sessionContext.userId")
                        .containsEntry("valueText", "alice"))
                .anySatisfy(item -> assertThat(item)
                        .asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.MAP)
                        .containsEntry("sourcePath", "behaviorAnalysis.personalBaselineEvidence.scope"))
                .anySatisfy(item -> assertThat(item)
                        .asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.MAP)
                        .containsEntry("sourcePath", "relatedDocuments.size")
                        .containsEntry("valueText", "0"));
        assertThat(eventMetadata.get("promptFieldStateLedger")).asList()
                .anySatisfy(item -> assertThat(item)
                        .asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.MAP)
                        .containsEntry("fieldKey", "source:securityEvent.metadata.requestPath")
                        .containsEntry("fieldState", "VALUE_PRESENT")
                        .containsEntry("qualityRelevance", "LLM_DECISION_CONTRACT")
                        .containsEntry("remediationOwner", "REQUEST_CONTEXT_PRODUCER"));
        assertThat(eventMetadata.get("promptFieldStateLedger")).asList()
                .anySatisfy(item -> {
                    assertThat(item)
                            .asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.MAP)
                            .containsEntry("sourceType", "FINAL_USER_PROMPT_FIELD")
                            .containsEntry("qualityRelevance", "LLM_DECISION_CONTRACT")
                            .containsKey("metricCodes");
                    assertThat(((Map<?, ?>) item).get("metricCodes")).asList().isNotEmpty();
                });
    }

    @Test
    void executeShouldPreserveRawIdentityPromptIntoFinalPromptAndEventMetadata() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());
        PromptGenerator promptGenerator = new PromptGenerator(List.of(template));
        promptGenerator.registerTemplate(SecurityDecisionRequest.TEMPLATE_TYPE.name(), template);
        PromptGenerationStep step = new PromptGenerationStep(promptGenerator);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-prompt-step-identity-001")
                .timestamp(LocalDateTime.of(2026, 5, 11, 16, 52))
                .userId("persona_fin_lead")
                .sessionId("official-verification-session:persona_fin_lead")
                .sourceIp("0:0:0:0:0:0:0:1")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36")
                .description("GET /admin/api/enterprise/verification/runtime/probe/normal/resource-001")
                .build();
        event.addMetadata("tenantId", "demo");
        event.addMetadata("organizationId", "demo-org");
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/enterprise/verification/runtime/probe/normal/resource-001");
        event.addMetadata("resourceId", "resource-001");
        event.addMetadata("authorizationEffect", "ALLOW");
        event.addMetadata("effectiveRoles", List.of("USER", "DEVELOPER", "INFRA", "PENDING_ANALYSIS", "ADMIN", "MANAGER"));
        event.addMetadata("effectivePermissions", List.of("READ", "WRITE", "UPDATE", "DELETE", "role.user", "role.admin"));
        event.addMetadata("authenticationType", "PASSWORD");
        event.addMetadata("mfaVerified", false);
        event.addMetadata("currentAccessHour", 16);

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("persona_fin_lead");
        sessionContext.setSessionId("official-verification-session:persona_fin_lead");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(noDataBaselineEvidence());

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of()));
        request.withParameter("promptBudgetProfile", PromptBudgetProfile.CORTEX_L1_RAW_IDENTITY.profileKey());

        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PREPROCESSING,
                "systemMetadata");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL,
                new ContextRetriever.ContextRetrievalResult("contextInfo", List.<org.springframework.ai.document.Document>of(), Map.of()));

        Object result = step.execute(request, context).block();

        assertThat(result).isInstanceOf(PromptGenerationResult.class);
        PromptGenerationResult promptResult = (PromptGenerationResult) result;
        assertThat(promptResult.getRawSystemPrompt()).isEqualTo(promptResult.getSystemPrompt());
        assertThat(promptResult.getRawUserPrompt()).isEqualTo(promptResult.getUserPrompt());
        assertThat(context.getMetadata("promptTransformationMode", String.class)).isEqualTo("IDENTITY");
        assertThat(context.getMetadata("promptRawTruthParity", Boolean.class)).isTrue();
        assertThat(context.getMetadata("promptUserFieldDiffCount", Integer.class)).isZero();
        assertThat(context.getMetadata("promptCacheContextMode", String.class)).isEqualTo("FULL_FIELD_PRESERVED");
        assertThat(context.getMetadata("pqaReferencePrompt", String.class)).isEqualTo("FINAL_USER_PROMPT");

        Map<String, Object> eventMetadata = event.getMetadata();
        assertThat(eventMetadata.get("rawSystemPrompt")).isEqualTo(promptResult.getRawSystemPrompt());
        assertThat(eventMetadata.get("rawUserPrompt")).isEqualTo(promptResult.getRawUserPrompt());
        assertThat(eventMetadata.get("systemPrompt")).isEqualTo(promptResult.getSystemPrompt());
        assertThat(eventMetadata.get("userPrompt")).isEqualTo(promptResult.getUserPrompt());
        assertThat(eventMetadata).containsKeys(
                "promptFieldStateLedger",
                "promptSourceContextLedger",
                "rawSystemPromptHash",
                "rawUserPromptHash",
                "systemPromptHash",
                "userPromptHash");
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
