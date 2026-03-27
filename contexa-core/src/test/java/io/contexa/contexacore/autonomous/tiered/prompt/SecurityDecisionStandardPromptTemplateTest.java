package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityDecisionStandardPromptTemplateTest {

    @Test
    void generatePromptShouldUseGovernedStandardTemplate() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-001")
                .timestamp(LocalDateTime.of(2026, 3, 24, 10, 30))
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
        sessionContext.setRequestCount(5);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setBaselineContext("[NO_DATA] Baseline not loaded");

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of())
        );

        String systemPrompt = template.generateSystemPrompt(request, "");
        String userPrompt = template.generateUserPrompt(request, "");
        PromptGovernanceDescriptor descriptor = template.getPromptGovernanceDescriptor();
        PromptExecutionMetadata executionMetadata = template.buildStructuredPrompt(
                event,
                sessionContext,
                behaviorAnalysis,
                List.of()
        ).executionMetadata();

        assertThat(systemPrompt).contains("You are a Zero Trust security analyst AI.");
        assertThat(systemPrompt).contains("<output_format>");
        assertThat(userPrompt).contains("=== CURRENT REQUEST AND EVENT ===");
        assertThat(userPrompt).contains("/api/customer/export");
        assertThat(userPrompt).contains("alice");
        assertThat(executionMetadata.budgetProfile().profileKey()).isEqualTo("CORTEX_L1_STANDARD");
        assertThat(executionMetadata.promptEvidenceCompleteness().name()).isEqualTo("INCOMPLETE");
        assertThat(executionMetadata.omittedSections()).contains("BRIDGE_AND_COVERAGE", "IDENTITY_AND_ROLE");
        assertThat(descriptor.promptVersion()).isEqualTo("2026.03.26-e0.1");
        assertThat(descriptor.contractVersion()).isEqualTo("CORTEX_PROMPT_CONTRACT_V2");
        assertThat(descriptor.releaseStatus().name()).isEqualTo("PRODUCTION");
        assertThat(descriptor.supportedModelProfiles()).contains("STRICT_JSON_SCHEMA");
    }
}
