package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.ContextCoverageEvaluator;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.InMemoryResourceContextRegistry;
import io.contexa.contexacore.autonomous.context.PromptContextComposer;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import org.springframework.ai.document.Document;
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
        assertThat(template.getAIGenerationType()).isEqualTo(SecurityDecisionResponseLite.class);
        assertThat(systemPrompt)
                .doesNotContain("errorMessage")
                .doesNotContain("executionTime")
                .doesNotContain("\"metadata\"");
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

    @Test
    void generateUserPromptShouldPreferCanonicalSessionNarrativeOverBehaviorFallback() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                null,
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                new PromptContextComposer());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-002")
                .timestamp(LocalDateTime.of(2026, 3, 30, 11, 31))
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("203.0.113.10")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("previousPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("previousActionFamily", "READ");
        event.addMetadata("lastRequestIntervalMs", 42000L);
        event.addMetadata("sessionActionSequence", List.of("READ", "READ"));
        event.addMetadata("sessionProtectableSequence", List.of("/admin/api/security-test/sensitive/resource-001", "/admin/api/security-test/sensitive/resource-001"));
        event.addMetadata("bridgeCoverageLevel", "AUTHORIZATION_CONTEXT");
        event.addMetadata("bridgeCoverageSummary", "Bridge resolved authentication and authorization context for the current request.");
        event.addMetadata("bridgeAuthenticationSource", "SECURITY_CONTEXT");
        event.addMetadata("bridgeAuthorizationSource", "HEADER");
        event.addMetadata("userRoles", List.of("ROLE_ADMIN"));
        event.addMetadata("effectivePermissions", List.of("report.read"));
        event.addMetadata("scopeTags", List.of("customer_data"));
        event.addMetadata("mfaVerified", true);
        event.addMetadata("resourceSensitivity", "HIGH");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");
        sessionContext.setRequestCount(2);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPreviousPath("/admin/api/security-test/evidence/server-truth");
        behaviorAnalysis.setLastRequestIntervalMs(0L);

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of())
        );

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("Previous request path: /admin/api/security-test/sensitive/resource-001.");
        assertThat(userPrompt).contains("Time since last request: 42 seconds.");
        assertThat(userPrompt).doesNotContain("Previous request path: /admin/api/security-test/evidence/server-truth.");
        assertThat(userPrompt).doesNotContain("Time since last request: 0 seconds.");
    }

    @Test
    void generateUserPromptShouldKeepBaselineNarrativeProvisionalUntilPersonalBaselineIsEstablished() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-003")
                .timestamp(LocalDateTime.of(2026, 3, 30, 11, 35))
                .userId("alice")
                .sessionId("session-1")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("userRoles", List.of("ADMIN"));

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setBaselineContext("User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:30 (Mon)");
        behaviorAnalysis.setBaselineEstablished(true);
        behaviorAnalysis.setPersonalBaselineAvailable(true);
        behaviorAnalysis.setPersonalBaselineEstablished(false);
        behaviorAnalysis.setBaselineUpdateCount(1L);

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of())
        );

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("Provisional baseline evidence (learning in progress):");
        assertThat(userPrompt).doesNotContain("This user normally");
        assertThat(userPrompt).doesNotContain("Frequent paths:");
        assertThat(userPrompt).doesNotContain("Established baseline (from learned behavior):");
    }

    @Test
    void generateUserPromptShouldRenderHistoricalComparableEventsWhenRagDocumentsExist() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-004")
                .timestamp(LocalDateTime.of(2026, 3, 30, 11, 40))
                .userId("alice")
                .sessionId("session-1")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setBaselineContext("[NO_DATA] Baseline not loaded");

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        sessionContext,
                        behaviorAnalysis,
                        List.of(new Document("User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:30 (Mon)"))));

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("HistoricalComparableEvents:");
        assertThat(userPrompt).contains("Historical records for context:");
        assertThat(userPrompt).contains("/admin/api/security-test/sensitive/resource-001");
    }
}
