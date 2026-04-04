package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.ContextCoverageEvaluator;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.InMemoryResourceContextRegistry;
import io.contexa.contexacore.autonomous.context.PromptContextComposer;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityDecisionStandardPromptTemplateTest {

    @Test
    @DisplayName("governed standard prompt should keep core contract sections only")
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
        assertThat(systemPrompt).contains("The reasoning field must be exactly one short sentence, no more than 24 words.");
        assertThat(systemPrompt).contains("Do not repeat the same factor in different wording.");
        assertThat(systemPrompt).contains("If any of those labels is false, you must not claim the opposite.");
        assertThat(systemPrompt).contains("If NewUser is false, do not say \"new user\".");
        assertThat(systemPrompt).contains("Treat the CURRENT REQUEST sensitivity label as authoritative.");
        assertThat(systemPrompt).contains("If the prompt says Sensitivity: STANDARD or LOW, do not describe");
        assertThat(systemPrompt).contains("not sufficient grounds for confident ALLOW on HIGH or CRITICAL access");
        assertThat(systemPrompt).contains("do not return ALLOW above 0.70 confidence");
        assertThat(systemPrompt).contains("prefer CHALLENGE or ESCALATE over ALLOW");
        assertThat(systemPrompt).contains("at least one uncertainty term such as limited, provisional, thin");
        assertThat(systemPrompt).doesNotContain("HIGH sensitivity access without reliable baseline or scope evidence.");
        assertThat(systemPrompt).contains("When uncertainty drives CHALLENGE or ESCALATE");
        assertThat(systemPrompt).contains("limited, provisional,");
        assertThat(systemPrompt).contains("Follow the <output_format> schema exactly.");
        assertThat(systemPrompt).contains("Use only ALLOW, CHALLENGE, BLOCK, or ESCALATE for action.");
        assertThat(systemPrompt).contains("If no supported MITRE tactic or technique applies, return mitre as UNKNOWN.");
        assertThat(systemPrompt)
                .doesNotContain("RESPOND WITH JSON ONLY:")
                .doesNotContain("\"reasoning\":\"<exactly 1 short sentence, max 24 words>\"")
                .doesNotContain("<optional MITRE tactic, technique, or UNKNOWN>");
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
        assertThat(descriptor.promptVersion()).isEqualTo("2026.04.04-e0.2");
        assertThat(descriptor.contractVersion()).isEqualTo("CORTEX_PROMPT_CONTRACT_V2");
        assertThat(descriptor.releaseStatus().name()).isEqualTo("PRODUCTION");
        assertThat(descriptor.releaseApprovalReference()).isEqualTo("P0-Preflight/E0-2");
        assertThat(descriptor.evaluationBaselineReference()).isEqualTo("2026.03.26-e0.1");
        assertThat(descriptor.rollbackPromptVersion()).isEqualTo("2026.03.26-e0.1");
        assertThat(descriptor.supportedModelProfiles()).contains("STRICT_JSON_SCHEMA");
    }

    @Test
    @DisplayName("configured layer1 default budget profile should flow into direct browser-style prompt generation")
    void generatePromptShouldUseConfiguredLayer1DefaultBudgetProfile() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getLayer1().setDefaultBudgetProfile("CORTEX_L1_DECISION_COMPACT");
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                properties);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-budget-profile")
                .timestamp(LocalDateTime.of(2026, 4, 2, 10, 0))
                .userId("alice")
                .sessionId("session-1")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");

        PromptExecutionMetadata executionMetadata = template.buildStructuredPrompt(
                event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(),
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                List.of()
        ).executionMetadata();

        assertThat(executionMetadata.budgetProfile().profileKey())
                .isEqualTo(PromptBudgetProfile.CORTEX_L1_DECISION_COMPACT.profileKey());
    }

    @Test
    @DisplayName("current request section should prefer canonical session narrative over behavior fallback")
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
    @DisplayName("baseline narrative should stay provisional until personal baseline is established")
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
    @DisplayName("sparse personal history should not be promoted into new user")
    void generateUserPromptShouldNotPromoteSparsePersonalHistoryIntoNewUser() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-003b")
                .timestamp(LocalDateTime.of(2026, 4, 1, 15, 0))
                .userId("alice")
                .sessionId("session-2")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("isNewUser", false);
        event.addMetadata("userRoles", List.of("ADMIN"));

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-2");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setBaselineContext("""
                [NO_PERSONAL_BASELINE] This user has no personal behavioral history.

                Organization Baseline (reference only - NOT this user's personal patterns):
                Known Hours: 9, 10, 11
                Frequent Paths: /admin/api/security-test/sensitive/resource-001
                """);
        behaviorAnalysis.setPersonalBaselineAvailable(false);
        behaviorAnalysis.setPersonalBaselineEstablished(false);
        behaviorAnalysis.setOrganizationBaselineAvailable(true);
        behaviorAnalysis.setOrganizationBaselineEstablished(true);
        behaviorAnalysis.setBaselineUpdateCount(1L);

        String userPrompt = template.generateUserPrompt(new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of())), "");

        assertThat(userPrompt).contains("NewUser: false");
        assertThat(userPrompt).contains("This user is not marked as new, but personal behavioral history is still sparse.");
        assertThat(userPrompt).doesNotContain("This is a new user without established behavioral baseline.");
        assertThat(userPrompt).doesNotContain("Personal behavioral baseline is not established yet.");
    }

    @Test
    @DisplayName("historical comparable evidence should be rendered when RAG documents exist")
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

    @Test
    @DisplayName("browser follow-up prompt should render bridge and friction evidence")
    void generateUserPromptShouldRenderBridgeAndFrictionEvidenceForBrowserStyleFollowUpRequest() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                null,
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                new PromptContextComposer());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-005")
                .timestamp(LocalDateTime.of(2026, 3, 30, 11, 45))
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("192.168.1.100")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("previousPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("lastRequestIntervalMs", 42000L);
        event.addMetadata("sessionActionSequence", List.of(
                "11:30 | MFA_COMPLETED (Zero Trust Challenge verified) | 192.168.1.100",
                "11:31 | GET /admin/api/security-test/sensitive/resource-001 | 192.168.1.100"));
        event.addMetadata("bridgeCoverageLevel", "AUTHORIZATION_CONTEXT");
        event.addMetadata("bridgeCoverageSummary", "Bridge completeness reached authentication and authorization context for the current request.");
        event.addMetadata("bridgeAuthenticationSource", "SECURITY_CONTEXT");
        event.addMetadata("bridgeAuthorizationSource", "HEADER");
        event.addMetadata("effectiveRoles", List.of("ADMIN"));
        event.addMetadata("effectivePermissions", List.of("report.read"));
        event.addMetadata("scopeTags", List.of("customer_data"));
        event.addMetadata("authorizationEffect", "ALLOW");
        event.addMetadata("mfaVerified", true);
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("resourceLabel", "Sensitive Security Test Resource");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");
        sessionContext.setRequestCount(2);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setBaselineContext("[NO_DATA] Baseline not loaded");

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        sessionContext,
                        behaviorAnalysis,
                        List.of(new Document("User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:30 (Mon)"))));

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("=== BRIDGE RESOLUTION CONTEXT ===");
        assertThat(userPrompt).contains("AuthorizationEffect: ALLOW");
        assertThat(userPrompt).contains("=== FRICTION AND APPROVAL HISTORY ===");
        assertThat(userPrompt).contains("RecentChallengeCount: 1");
        assertThat(userPrompt).contains("HistoricalComparableEvents:");
    }

    @Test
    @DisplayName("evidence should evolve across rounds without regression")
    void generateUserPromptShouldEvolveEvidenceAcrossRoundsWithoutRegression() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-006")
                .timestamp(LocalDateTime.of(2026, 3, 30, 12, 10))
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("192.168.1.100")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("mfaVerified", true);
        event.addMetadata("effectiveRoles", List.of("ADMIN"));
        event.addMetadata("effectivePermissions", List.of("report.read"));
        event.addMetadata("authorizationEffect", "ALLOW");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis round1 = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        round1.setBaselineContext("[NO_DATA] Baseline not loaded");
        round1.setPersonalBaselineAvailable(false);
        round1.setPersonalBaselineEstablished(false);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis round2 = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        round2.setBaselineContext("User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:30 (Mon)");
        round2.setBaselineEstablished(true);
        round2.setPersonalBaselineAvailable(true);
        round2.setPersonalBaselineEstablished(false);
        round2.setBaselineUpdateCount(1L);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis round3 = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        round3.setBaselineContext("User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:30 (Mon)");
        round3.setBaselineEstablished(true);
        round3.setPersonalBaselineAvailable(true);
        round3.setPersonalBaselineEstablished(true);
        round3.setBaselineUpdateCount(5L);

        String round1Prompt = template.generateUserPrompt(new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, round1, List.of())), "");
        String round2Prompt = template.generateUserPrompt(new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        sessionContext,
                        round2,
                        List.of(new Document("Round2: previously allowed access for the same sensitive resource")))), "");
        String round3Prompt = template.generateUserPrompt(new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        sessionContext,
                        round3,
                        List.of(
                                new Document("Round2: previously allowed access for the same sensitive resource"),
                                new Document("Round3: repeated follow-up access from the same session and environment")))), "");

        assertThat(round1Prompt).doesNotContain("HistoricalComparableEvents:");
        assertThat(round2Prompt).contains("HistoricalComparableEvents:");
        assertThat(round2Prompt).contains("Provisional baseline evidence (learning in progress):");
        assertThat(round3Prompt).contains("HistoricalComparableEvents:");
        assertThat(round3Prompt).contains("Established baseline (from learned behavior):");
        assertThat(round3Prompt).doesNotContain("Provisional baseline evidence (learning in progress):");
        assertThat(countOccurrences(round2Prompt, "Round2:")).isGreaterThanOrEqualTo(1);
        assertThat(countOccurrences(round3Prompt, "Round")).isGreaterThanOrEqualTo(2);
    }

    private int countOccurrences(String text, String token) {
        int count = 0;
        int cursor = 0;
        while (cursor >= 0) {
            cursor = text.indexOf(token, cursor);
            if (cursor >= 0) {
                count++;
                cursor += token.length();
            }
        }
        return count;
    }
}



