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
package io.contexa.contexacore.std.pipeline.step;

import java.time.ZoneId;
import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacommon.domain.SecurityEvent;
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
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;


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
                .timestamp(LocalDateTime.of(2026, 3, 31, 11, 0).atZone(ZoneId.systemDefault()).toInstant())
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
                new ContextRetriever.ContextRetrievalResult("contextInfo", List.<Document>of(), Map.of()));

        Object result = step.execute(request, context).block();

        assertThat(result).isNotNull();
        assertThat(context.getMetadata("promptTokenEstimator", String.class)).isEqualTo("MODEL_AWARE_TOKEN_COUNTING_V1");
        assertThat(context.getMetadata("estimatedSystemTokens", Integer.class)).isPositive();
        assertThat(context.getMetadata("estimatedUserTokens", Integer.class)).isPositive();
        assertThat(context.getMetadata("estimatedTotalTokens", Integer.class)).isPositive();
        assertThat(context.getMetadata("promptBudgetEnforcementMode", String.class)).isEqualTo("OBSERVE_ONLY");
        assertThat(context.getMetadata("promptTransformationMode", String.class)).isIn("IDENTITY", "NORMALIZE_ONLY", "NORMALIZE_AND_COMPACT", "NORMALIZE_AND_FUSE");
        assertThat(context.getMetadata("promptRawTruthParity", Boolean.class)).isNotNull();
        assertThat(context.getMetadata("rawPromptHash", String.class)).startsWith("sha256:");
        assertThat(context.getMetadata("promptExecutionMetadata", Object.class)).isNotNull();

        assertThat(context.getMetadata("promptRenderCacheSystemStable", Boolean.class)).isTrue();
        assertThat(context.getMetadata("promptRenderCacheSystemHash", String.class)).startsWith("sha256:");
        assertThat(context.getMetadata("promptRenderCacheContextMode", String.class)).isEqualTo("FULL_FIELD_PRESERVED");
        assertThat(context.getMetadata("pqaReferencePrompt", String.class)).isNull();
        assertThat(context.getMetadata("pqaRawPromptRole", String.class)).isNull();

        PromptExecutionMetadata executionMetadata = context.getMetadata("promptExecutionMetadata", PromptExecutionMetadata.class);
        assertThat(context.getMetadata("promptCompressionApplied", Boolean.class))
                .isEqualTo(executionMetadata.promptCompressionLedger().compressionApplied());
        Map<String, Object> eventMetadata = event.getMetadata();
        assertThat(eventMetadata)
                .containsEntry("promptRuntimeTelemetryLinked", true)
                .containsEntry("promptRuntimeTelemetryLayer", "LIGHTWEIGHT_RUNTIME")
                .containsEntry("promptRenderCacheSystemStable", true)
                .containsEntry("promptRenderCacheContextMode", "FULL_FIELD_PRESERVED")
                .doesNotContainKeys("pqaReferencePrompt", "pqaRawPromptRole");
        assertThat(eventMetadata.get("promptRenderCacheSystemHash")).asString().startsWith("sha256:");
        assertThat(eventMetadata).doesNotContainKeys(
                "promptSourceContextLedger",
                "promptRawUserFieldLedger",
                "promptFinalUserFieldLedger",
                "promptUserFieldDiffLedger",
                "promptFieldStateLedger",
                "promptFieldStateSummary",
                "systemPrompt",
                "userPrompt",
                "rawSystemPrompt",
                "rawUserPrompt");
    }

    @Test
    void executeKeepsOnlyTheLightweightRecordForOfficialVerificationMarkers() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());
        PromptGenerator promptGenerator = new PromptGenerator(List.of(template));
        promptGenerator.registerTemplate(SecurityDecisionRequest.TEMPLATE_TYPE.name(), template);
        PromptGenerationStep step = new PromptGenerationStep(promptGenerator);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-prompt-step-official-001")
                .timestamp(LocalDateTime.of(2026, 5, 11, 16, 52).atZone(ZoneId.systemDefault()).toInstant())
                .userId("persona_fin_lead")
                .sessionId("official-verification-session:persona_fin_lead")
                .sourceIp("0:0:0:0:0:0:0:1")
                .description("GET /admin/api/enterprise/verification/runtime/probe/normal/resource-001")
                .build();
        event.addMetadata("officialVerificationDecisionBoundaryMode", "OFFICIAL_VERIFICATION_RUNTIME");
        event.addMetadata("officialVerificationMaxTokens", 4096);
        event.addMetadata("tenantId", "demo");
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/enterprise/verification/runtime/probe/normal/resource-001");
        event.addMetadata("resourceId", "resource-001");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("persona_fin_lead");
        sessionContext.setSessionId("official-verification-session:persona_fin_lead");

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
                new ContextRetriever.ContextRetrievalResult("contextInfo", List.<Document>of(), Map.of()));

        Object result = step.execute(request, context).block();

        assertThat(result).isNotNull();
        Map<String, Object> eventMetadata = event.getMetadata();
        assertThat(eventMetadata)
                .containsEntry("promptRuntimeTelemetryLinked", true)
                .containsEntry("promptRuntimeTelemetryLayer", "LIGHTWEIGHT_RUNTIME")
                .containsEntry("officialVerificationDecisionBoundaryMode", "OFFICIAL_VERIFICATION_RUNTIME")
                .doesNotContainKeys(
                        "promptLineageCaptureMode",
                        "promptSourceContextLedger",
                        "promptRawUserFieldLedger",
                        "promptFinalUserFieldLedger",
                        "promptUserFieldDiffLedger",
                        "promptFieldStateLedger",
                        "promptFieldStateSummary",
                        "systemPrompt",
                        "userPrompt",
                        "rawSystemPrompt",
                        "rawUserPrompt");
    }

    @Test
    void executeShouldPreserveRawIdentityPromptIntoFinalPrompt() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());
        PromptGenerator promptGenerator = new PromptGenerator(List.of(template));
        promptGenerator.registerTemplate(SecurityDecisionRequest.TEMPLATE_TYPE.name(), template);
        PromptGenerationStep step = new PromptGenerationStep(promptGenerator);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-prompt-step-identity-001")
                .timestamp(LocalDateTime.of(2026, 5, 11, 16, 52).atZone(ZoneId.systemDefault()).toInstant())
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
        event.addMetadata("officialVerificationDecisionBoundaryMode", "OFFICIAL_VERIFICATION_RUNTIME");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("persona_fin_lead");
        sessionContext.setSessionId("official-verification-session:persona_fin_lead");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(noDataBaselineEvidence());

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of()));
        request.withParameter("promptBudgetProfile", PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT.profileKey());

        PipelineExecutionContext context = new PipelineExecutionContext(request.getRequestId());
        context.addStepResult(
                PipelineConfiguration.PipelineStep.PREPROCESSING,
                "systemMetadata");
        context.addStepResult(
                PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL,
                new ContextRetriever.ContextRetrievalResult("contextInfo", List.<Document>of(), Map.of()));

        Object result = step.execute(request, context).block();

        assertThat(result).isInstanceOf(PromptGenerationResult.class);
        PromptGenerationResult promptResult = (PromptGenerationResult) result;
        assertThat(promptResult.getRawSystemPrompt()).isNotBlank();
        assertThat(promptResult.getRawUserPrompt()).isNotBlank();
        assertThat(context.getMetadata("promptTransformationMode", String.class)).isEqualTo("IDENTITY");
        assertThat(context.getMetadata("promptRawTruthParity", Boolean.class)).isTrue();
        assertThat(context.getMetadata("promptRenderCacheContextMode", String.class)).isEqualTo("FULL_FIELD_PRESERVED");
        assertThat(context.getMetadata("pqaReferencePrompt", String.class)).isNull();
        assertThat(event.getMetadata())
                .containsKeys("rawSystemPromptHash", "rawUserPromptHash", "systemPromptHash", "userPromptHash")
                .doesNotContainKeys("rawSystemPrompt", "rawUserPrompt", "systemPrompt", "userPrompt",
                        "promptFieldStateLedger", "promptSourceContextLedger");
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
