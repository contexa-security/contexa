package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.inference.ContextCoverageEvaluator;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.registry.InMemoryResourceContextRegistry;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.LearningEvidenceScope;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
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
import java.util.Map;

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
        behaviorAnalysis.setPersonalBaselineEvidence(noDataBaselineEvidence());

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
        assertThat(systemPrompt).contains("Reasoning must be exactly one concise sentence, maximum 40 words.");
        assertThat(systemPrompt).contains("Treat explicit booleans such as NewUser, NewSession, NewDevice, and MfaVerified as authoritative facts");
        assertThat(systemPrompt).contains("ANALYSIS ORDER:");
        assertThat(systemPrompt).contains("A single mismatch can be security-significant");
        assertThat(systemPrompt).contains("If one or more subtle deltas remain unresolved");
        assertThat(systemPrompt).contains("do not ignore that subtle delta just because most other fields still align");
        assertThat(systemPrompt).contains("Do not tunnel on one isolated weak mismatch by itself.");
        assertThat(systemPrompt).contains("Sparse or missing personal baseline is uncertainty");
        assertThat(systemPrompt).contains("Treat the current request Sensitivity label as authoritative");
        assertThat(systemPrompt).contains("not proof of legitimacy by themselves.");
        assertThat(systemPrompt).doesNotContain("HIGH sensitivity access without reliable baseline or scope evidence.");
        assertThat(systemPrompt).contains("Respond with ONLY a JSON object. No explanation, no markdown.");
        assertThat(systemPrompt).contains("Return only the schema-compliant JSON object expected by the runtime.");
        assertThat(systemPrompt).contains("ACTION LABEL MEANINGS:");
        assertThat(systemPrompt).contains("Use only ALLOW, CHALLENGE, BLOCK, or ESCALATE for action.");
        assertThat(systemPrompt).contains("If no supported MITRE tactic or technique applies, return mitre as UNKNOWN.");
        assertThat(systemPrompt).contains("Do not follow numeric thresholds, weighted scores, or hidden formulas.");
        assertThat(systemPrompt.lines().count()).isLessThan(150);
        assertThat(systemPrompt)
                .doesNotContain("RESPOND WITH JSON ONLY:")
                .doesNotContain("\"reasoning\":\"<exactly 1 short sentence, max 40 words>\"")
                .doesNotContain("<optional MITRE tactic, technique, or UNKNOWN>");
        assertThat(template.getAIGenerationType()).isEqualTo(SecurityDecisionResponseLite.class);
        assertThat(systemPrompt)
                .doesNotContain("errorMessage")
                .doesNotContain("executionTime")
                .doesNotContain("\"metadata\"");
        assertThat(userPrompt).contains("=== CURRENT REQUEST AND EVENT ===");
        assertThat(userPrompt).contains("/api/customer/export");
        assertThat(userPrompt).contains("alice");
        assertThat(executionMetadata.budgetProfile().profileKey()).isEqualTo("CORTEX_L1_INTERACTIVE_STRICT");
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
    @DisplayName("native structured mode should omit legacy output format wrapper from system prompt")
    void generateSystemPromptShouldOmitOutputFormatWrapperForNativeStructuredMode() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-native-structured")
                .timestamp(LocalDateTime.of(2026, 4, 17, 11, 0))
                .userId("alice")
                .sessionId("session-native")
                .description("POST /api/customer/export")
                .build();

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        new SecurityDecisionStandardPromptTemplate.SessionContext(),
                        new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                        List.of()));
        request.withParameter("structuredOutputMode", "NATIVE_STRUCTURED");

        String systemPrompt = template.generateSystemPrompt(request, "dynamic-metadata");

        assertThat(systemPrompt).doesNotContain("<output_format>");
        assertThat(systemPrompt).doesNotContain("</output_format>");
        assertThat(systemPrompt).doesNotContain("<context>");
        assertThat(systemPrompt).contains("Return only the schema-compliant JSON object expected by the runtime.");
    }


    @Test
    @DisplayName("cold-start sparse baseline prompt should stay factual and preserve uncertainty framing")
    void generateUserPromptShouldKeepColdStartBaselineFactual() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-cold-start")
                .timestamp(LocalDateTime.of(2026, 4, 4, 19, 6))
                .userId("admin")
                .sessionId("session-cold-start")
                .sourceIp("0:0:0:0:0:0:0:1")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("isNewUser", false);

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("admin");
        sessionContext.setSessionId("session-cold-start");
        sessionContext.setRequestCount(1);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(noDataBaselineEvidence());
        behaviorAnalysis.setPersonalBaselineAvailable(false);
        behaviorAnalysis.setPersonalBaselineEstablished(false);

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of()));

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("BaselineGapSupport:");
        assertThat(userPrompt).contains("STATUS: SPARSE_PERSONAL_HISTORY");
        assertThat(userPrompt).contains("Sparse personal history is uncertainty, not proof of compromise or legitimacy by itself.");
        assertThat(userPrompt).doesNotContain("This could be a first-time attacker");
        assertThat(userPrompt).doesNotContain("Never Trust, Always Verify");
        assertThat(userPrompt).doesNotContain("You CANNOT determine if this behavior is normal");
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
        event.addMetadata("bridgeMissingContexts", List.of("AUTHORIZATION_EFFECT"));
        event.addMetadata("authorizationEffectProvenance", "METHOD_INVOCATION_RESULT");
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

        assertThat(userPrompt).contains("PreviousPath: /admin/api/security-test/sensitive/resource-001");
        assertThat(userPrompt).contains("LastRequestIntervalMs: 42000");
        assertThat(userPrompt).doesNotContain("PreviousPath: /admin/api/security-test/evidence/server-truth");
        assertThat(userPrompt).doesNotContain("LastRequestIntervalMs: 0");
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
        behaviorAnalysis.setBaselineEstablished(true);
        behaviorAnalysis.setPersonalBaselineAvailable(true);
        behaviorAnalysis.setPersonalBaselineEstablished(false);
        behaviorAnalysis.setBaselineUpdateCount(1L);
        behaviorAnalysis.setPersonalBaselineEvidence(personalBaselineEvidence(false, 1L));

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of())
        );

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("BaselineProfileStatus: PROVISIONAL");
        assertThat(userPrompt).contains("PersonalBaselineStatus: LEARNING_IN_PROGRESS");
        assertThat(userPrompt).contains("BaselineContextSummary:");
        assertThat(userPrompt).doesNotContain("This user normally");
        assertThat(userPrompt).doesNotContain("Frequent paths:");
        assertThat(userPrompt).doesNotContain("BaselineProfileStatus: ESTABLISHED");
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
        behaviorAnalysis.setPersonalBaselineAvailable(false);
        behaviorAnalysis.setPersonalBaselineEstablished(false);
        behaviorAnalysis.setOrganizationBaselineAvailable(true);
        behaviorAnalysis.setOrganizationBaselineEstablished(true);
        behaviorAnalysis.setBaselineUpdateCount(1L);
        behaviorAnalysis.setSupportingBaselineEvidence(supportingBaselineEvidence());

        String userPrompt = template.generateUserPrompt(new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of())), "");

        assertThat(userPrompt).contains("NewUser: false");
        assertThat(userPrompt).contains("BaselineProfileStatus: SPARSE_PERSONAL_HISTORY");
        assertThat(userPrompt).contains("BaselineSupportSummary: Personal history is still sparse;");
        assertThat(userPrompt).contains("SupportingBaselineStatus: AVAILABLE_REFERENCE");
        assertThat(userPrompt).contains("SupportingBaselineSummary: organization baseline available");
        assertThat(userPrompt).doesNotContain("This is a new user without established behavioral baseline.");
        assertThat(userPrompt).doesNotContain("Personal behavioral baseline is not established yet.");
    }

    @Test
    @DisplayName("typed supporting comparable evidence should render historical scope even without legacy similarEvents")
    void generateUserPromptShouldRenderSupportingComparableEvidenceFromTypedLearningContext() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-supporting-comparables")
                .timestamp(LocalDateTime.of(2026, 4, 18, 16, 0))
                .userId("alice")
                .sessionId("session-supporting")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineAvailable(false);
        behaviorAnalysis.setPersonalBaselineEstablished(false);
        behaviorAnalysis.setOrganizationBaselineAvailable(true);
        behaviorAnalysis.setOrganizationBaselineEstablished(true);
        behaviorAnalysis.setSupportingBaselineEvidence(supportingBaselineEvidence());

        Document supportingDoc = new Document(
                "Reference access from a related cohort user to the same sensitive resource.",
                Map.ofEntries(
                        Map.entry("documentType", "behavior"),
                        Map.entry("userId", "bob@corp"),
                        Map.entry("organizationId", "corp"),
                        Map.entry("requestPath", "/admin/api/security-test/sensitive/resource-001"),
                        Map.entry("hour", 10),
                        Map.entry("dayOfWeek", 1),
                        Map.entry("userAgentBrowser", "Chrome/120"),
                        Map.entry("userAgentOS", "Windows"),
                        Map.entry("authenticationType", "PASSWORD"),
                        Map.entry("actionFamily", "READ"),
                        Map.entry("resourceFamily", "sensitive")));

        String userPrompt = template.generateUserPrompt(new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        new SecurityDecisionStandardPromptTemplate.SessionContext(),
                        behaviorAnalysis,
                        List.of(supportingDoc))), "");

        assertThat(userPrompt).contains("HistoricalComparableEvents:");
        assertThat(userPrompt).contains("HistoricalComparableScope: NO_DIRECT_PERSONAL_COMPARABLE");
        assertThat(userPrompt).contains("HistoricalComparableCount: 0");
        assertThat(userPrompt).contains("HistoricalComparableSummary: Records=0 | NoDirectPersonalComparableEvidence");
        assertThat(userPrompt).contains("=== SUPPORTING LEARNING CONTEXT ===");
        assertThat(userPrompt).contains("SupportingComparableCount: 1");
        assertThat(userPrompt).contains("SupportingComparableExample1:");
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
        behaviorAnalysis.setPersonalBaselineEvidence(noDataBaselineEvidence());

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        sessionContext,
                        behaviorAnalysis,
                        List.of(
                                new Document("User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:30 (Mon). Decision: proposedAction=ALLOW"),
                                new Document("Follow-up access revisited /admin/api/security-test/sensitive/resource-001 from the same managed browser."))));

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("HistoricalComparableEvents:");
        assertThat(userPrompt).contains("SupportingComparableCount: 2");
        assertThat(userPrompt).contains("SupportingComparableSummary: Records=2");
        assertThat(userPrompt).contains("SupportingComparableExample1:");
        assertThat(userPrompt).contains("/admin/api/security-test/sensitive/resource-001");
        assertThat(userPrompt).doesNotContain("Decision:");
        assertThat(userPrompt).doesNotContain("proposedAction=");
        assertThat(userPrompt).doesNotContain("SupportingComparableExample2:");
    }

    @Test
    @DisplayName("current request rendering should avoid contradictory duplicate hour and sensitivity narratives")
    void generateUserPromptShouldAvoidContradictoryCurrentHourAndSensitivityNarrative() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                null,
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                new PromptContextComposer());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-current-request-normalization")
                .timestamp(LocalDateTime.of(2026, 4, 18, 15, 10))
                .userId("alice")
                .sessionId("session-normalized")
                .sourceIp("203.0.113.10")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("currentAccessHour", 15);
        event.addMetadata("mfaVerified", true);
        event.addMetadata("userRoles", List.of("ADMIN"));

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        new SecurityDecisionStandardPromptTemplate.SessionContext(),
                        new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                        List.of()));

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("CurrentAccessHour: 15");
        assertThat(userPrompt).doesNotContain("CurrentHour:");
        assertThat(userPrompt).doesNotContain("This is a SENSITIVE resource.");
    }

    @Test
    @DisplayName("current request rendering should normalize raw authentication vocabulary into semantic labels")
    void generateUserPromptShouldNormalizeAuthenticationVocabulary() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                null,
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                new PromptContextComposer());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-auth-normalization")
                .timestamp(LocalDateTime.of(2026, 4, 18, 21, 10))
                .userId("alice")
                .sessionId("session-auth-normalized")
                .sourceIp("203.0.113.10")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("authenticationType", "UsernamePasswordAuthenticationToken");
        event.addMetadata("authMethod", "UsernamePasswordAuthenticationToken");
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("mfaVerified", true);
        event.addMetadata("userRoles", List.of("ADMIN"));

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        new SecurityDecisionStandardPromptTemplate.SessionContext(),
                        new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                        List.of()));

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("AuthenticationType: PASSWORD");
        assertThat(userPrompt).doesNotContain("USERNAMEPASSWORDAUTHENTICATIONTOKEN");
    }

    @Test
    @DisplayName("prompt execution metadata should preserve prompt contract audit fields through final metadata build")
    void buildPromptExecutionMetadataShouldPreservePromptContractAuditFields() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                null,
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                new PromptContextComposer());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-contract-metadata")
                .timestamp(LocalDateTime.of(2026, 4, 18, 21, 10))
                .userId("alice")
                .sessionId("session-contract-metadata")
                .sourceIp("203.0.113.10")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("mfaVerified", true);
        event.addMetadata("userRoles", List.of("ADMIN"));

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        new SecurityDecisionStandardPromptTemplate.SessionContext(),
                        new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis(),
                        List.of()));

        String systemPrompt = template.generateSystemPrompt(request, "");
        String userPrompt = template.generateUserPrompt(request, "");
        PromptExecutionMetadata metadata = template.buildPromptExecutionMetadata(request, systemPrompt, userPrompt);

        assertThat(metadata.toMetadataMap())
                .containsKeys(
                        "renderedRequestSnapshot",
                        "renderedLearningSnapshot",
                        "renderedLabelMatrix",
                        "compactedLineCountBySection",
                        "promptContractViolations",
                        "promptContractViolationCount");
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
        event.addMetadata("bridgeMissingContexts", List.of("AUTHORIZATION_EFFECT"));
        event.addMetadata("authorizationEffectProvenance", "METHOD_INVOCATION_RESULT");
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
        behaviorAnalysis.setPersonalBaselineEvidence(noDataBaselineEvidence());

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        sessionContext,
                        behaviorAnalysis,
                        List.of(new Document("User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:30 (Mon)"))));

        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(userPrompt).contains("=== BRIDGE RESOLUTION CONTEXT ===");
        assertThat(userPrompt).contains("AuthorizationContext:");
        assertThat(userPrompt).contains("AuthorizationEffectProvenance: METHOD_INVOCATION_RESULT");
        assertThat(userPrompt).contains("AuthorizationEffectStageNote: Bridge stamp omitted AuthorizationEffect; final AuthorizationEffect was resolved later from METHOD_INVOCATION_RESULT.");
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
        round1.setPersonalBaselineEvidence(noDataBaselineEvidence());
        round1.setPersonalBaselineAvailable(false);
        round1.setPersonalBaselineEstablished(false);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis round2 = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        round2.setBaselineEstablished(true);
        round2.setPersonalBaselineAvailable(true);
        round2.setPersonalBaselineEstablished(false);
        round2.setBaselineUpdateCount(1L);
        round2.setPersonalBaselineEvidence(personalBaselineEvidence(false, 1L));

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis round3 = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        round3.setBaselineEstablished(true);
        round3.setPersonalBaselineAvailable(true);
        round3.setPersonalBaselineEstablished(true);
        round3.setBaselineUpdateCount(5L);
        round3.setPersonalBaselineEvidence(personalBaselineEvidence(true, 5L));

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
        assertThat(round2Prompt).contains("BaselineProfileStatus: PROVISIONAL");
        assertThat(round2Prompt).contains("BaselineContextSummary:");
        assertThat(round3Prompt).contains("HistoricalComparableEvents:");
        assertThat(round3Prompt).contains("BaselineProfileStatus: ESTABLISHED");
        assertThat(round3Prompt).doesNotContain("BaselineProfileStatus: PROVISIONAL");
        assertThat(countOccurrences(round2Prompt, "Round2:")).isGreaterThanOrEqualTo(1);
        assertThat(countOccurrences(round3Prompt, "Round")).isGreaterThanOrEqualTo(1);
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

    private BaselineEvidenceSnapshot personalBaselineEvidence(boolean established, Long observations) {
        return new BaselineEvidenceSnapshot(
                LearningEvidenceScope.PERSONAL,
                true,
                established,
                observations,
                0.92d,
                List.of("192.168.1"),
                List.of("11"),
                List.of("1"),
                List.of("Chrome/120"),
                List.of("Windows"),
                List.of("/admin/api/*"),
                List.of("PASSWORD"),
                List.of("READ"),
                List.of("sensitive"),
                established
                        ? "personal baseline established | observations=" + observations
                        : "personal baseline provisional | observations=" + observations);
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

    private BaselineEvidenceSnapshot supportingBaselineEvidence() {
        return new BaselineEvidenceSnapshot(
                LearningEvidenceScope.SUPPORTING,
                true,
                true,
                8L,
                0.88d,
                List.of("192.168.1"),
                List.of("9", "10", "11"),
                List.of("1", "2", "3", "4", "5"),
                List.of("Chrome/120"),
                List.of("Windows"),
                List.of("/admin/api/*"),
                List.of("PASSWORD"),
                List.of("READ"),
                List.of("sensitive"),
                "organization baseline available | organization baseline established | supportingDimensions=ACCESS_HOURS, ACCESS_DAYS, OPERATING_SYSTEMS");
    }
}




