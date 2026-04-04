package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PromptGeneratorTest {

    @Test
    @DisplayName("PromptGenerator는 governance metadata와 raw/view prompt telemetry를 함께 제공해야 한다")
    void generatePromptShouldAttachGovernanceMetadata() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());
        PromptGenerator promptGenerator = new PromptGenerator(List.of(template));
        promptGenerator.registerTemplate(SecurityDecisionRequest.TEMPLATE_TYPE.name(), template);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-generator-001")
                .timestamp(LocalDateTime.of(2026, 3, 26, 11, 0))
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("203.0.113.10")
                .description("POST /api/customer/export")
                .build();
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("requestPath", "/api/customer/export");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setBaselineContext("[NO_DATA] Baseline not loaded");

        PromptGenerationResult result = promptGenerator.generatePrompt(
                new SecurityDecisionRequest(
                        new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of())),
                "",
                "");

        PromptExecutionMetadata executionMetadata = result.getPromptExecutionMetadata();
        assertThat(executionMetadata).isNotNull();
        assertThat(executionMetadata.governanceDescriptor().promptVersion()).isEqualTo("2026.04.04-e0.2");
        assertThat(executionMetadata.governanceDescriptor().contractVersion()).isEqualTo("CORTEX_PROMPT_CONTRACT_V2");
        assertThat(executionMetadata.governanceDescriptor().releaseStatus().name()).isEqualTo("PRODUCTION");
        assertThat(executionMetadata.governanceDescriptor().releaseApprovalReference()).isEqualTo("P0-Preflight/E0-2");
        assertThat(executionMetadata.governanceDescriptor().evaluationBaselineReference()).isEqualTo("2026.03.26-e0.1");
        assertThat(executionMetadata.governanceDescriptor().rollbackPromptVersion()).isEqualTo("2026.03.26-e0.1");
        assertThat(executionMetadata.budgetProfile().profileKey()).isEqualTo("CORTEX_L1_STANDARD");
        assertThat(executionMetadata.promptTokenEstimate().estimatorKey()).isEqualTo("heuristic-char-div4-v1");
        assertThat(executionMetadata.promptTokenEstimate().budgetEnforcementMode()).isEqualTo("LLM_VIEW_ENFORCED");
        assertThat(executionMetadata.promptTokenEstimate().estimatedTotalTokens()).isPositive();
        assertThat(executionMetadata.promptTokenEstimate().compressionApplied())
                .isEqualTo(executionMetadata.promptCompressionLedger().compressionApplied());
        assertThat(executionMetadata.promptCompressionLedger().transformationMode()).isIn("IDENTITY", "NORMALIZE_ONLY", "NORMALIZE_AND_COMPACT", "NORMALIZE_AND_FUSE");
        assertThat(executionMetadata.promptEvidenceCompleteness().name()).isEqualTo("INCOMPLETE");
        assertThat(executionMetadata.omittedSections()).contains("BRIDGE_AND_COVERAGE", "IDENTITY_AND_ROLE");
        assertThat(executionMetadata.sectionSet())
                .contains("SYSTEM_INSTRUCTION", "DECISION_CONTRACT", "CURRENT_REQUEST_AND_EVENT", "OBSERVED_AND_PERSONAL_WORK_PATTERN");
        assertThat(executionMetadata.promptHash()).startsWith("sha256:");
        assertThat(executionMetadata.rawPromptHash()).startsWith("sha256:");
        assertThat(result.getMetadata()).containsKeys(
                "promptKey",
                "promptVersion",
                "contractVersion",
                "promptReleaseStatus",
                "budgetProfile",
                "promptSectionSet",
                "omittedSections",
                "promptEvidenceCompleteness",
                "promptHash",
                "systemPromptHash",
                "userPromptHash",
                "rawPromptHash",
                "rawSystemPromptHash",
                "rawUserPromptHash",
                "promptTokenEstimator",
                "estimatedSystemTokens",
                "estimatedUserTokens",
                "estimatedTotalTokens",
                "promptBudgetRemainingTokens",
                "promptBudgetUtilizationRate",
                "promptBudgetExceeded",
                "promptBudgetEnforcementMode",
                "promptCompressionApplied",
                "promptTransformationMode",
                "promptRawTruthParity",
                "promptCompressionOperationCount",
                "promptCompressionSavedCharacters",
                "promptCompressionSavedEstimatedTokens",
                "promptCompressionLedger");
        assertThat(result.getMetadata().get("promptSectionSet")).asList()
                .contains("SYSTEM_INSTRUCTION", "DECISION_CONTRACT", "CURRENT_REQUEST_AND_EVENT", "OBSERVED_AND_PERSONAL_WORK_PATTERN");
        assertThat(result.getMetadata().get("omittedSections")).asList()
                .contains("BRIDGE_AND_COVERAGE", "IDENTITY_AND_ROLE");
        assertThat(result.getSystemPrompt()).doesNotContain("promptHash");
        assertThat(result.getUserPrompt()).doesNotContain("promptHash");
        assertThat(result.getRawSystemPrompt()).isNotBlank();
        assertThat(result.getRawUserPrompt()).isNotBlank();
        assertThat(result.getMetadata().get("promptCompressionApplied"))
                .isEqualTo(executionMetadata.promptCompressionLedger().compressionApplied());
    }
}