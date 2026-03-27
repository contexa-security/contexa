package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PromptGeneratorTest {

    @Test
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

        assertThat(result.getPromptExecutionMetadata()).isNotNull();
        assertThat(result.getPromptExecutionMetadata().governanceDescriptor().promptVersion()).isEqualTo("2026.03.26-e0.1");
        assertThat(result.getPromptExecutionMetadata().governanceDescriptor().contractVersion()).isEqualTo("CORTEX_PROMPT_CONTRACT_V2");
        assertThat(result.getPromptExecutionMetadata().governanceDescriptor().releaseStatus().name()).isEqualTo("PRODUCTION");
        assertThat(result.getPromptExecutionMetadata().budgetProfile().profileKey()).isEqualTo("CORTEX_L1_STANDARD");
        assertThat(result.getPromptExecutionMetadata().promptEvidenceCompleteness().name()).isEqualTo("INCOMPLETE");
        assertThat(result.getPromptExecutionMetadata().omittedSections()).contains(
                "BRIDGE_AND_COVERAGE",
                "IDENTITY_AND_ROLE",
                "RESOURCE_AND_ACTION",
                "SESSION_NARRATIVE",
                "OBSERVED_AND_PERSONAL_WORK_PATTERN",
                "ROLE_SCOPE",
                "FRICTION_AND_APPROVAL",
                "DELEGATED_OBJECTIVE");
        assertThat(result.getPromptExecutionMetadata().promptHash()).startsWith("sha256:");
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
                "userPromptHash");
    }
}
