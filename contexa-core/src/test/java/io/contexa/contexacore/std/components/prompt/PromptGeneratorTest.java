package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.inference.ContextCoverageEvaluator;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.registry.InMemoryResourceContextRegistry;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.LearningEvidenceScope;
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
    @DisplayName("PromptGenerator should prefer provider-usage calibrated prompt estimation when observed usage exists for the requested model")
    void generatePromptShouldUseProviderUsageCalibratedEstimatorWhenModelCalibrationExists() {
        ObservedPromptTokenUsageRegistry.clear();
        try {
            ObservedPromptTokenUsageRegistry.recordObservation("gpt-4o-mini", 1200, 300);

            SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                    new SecurityEventEnricher(),
                    new TieredStrategyProperties());
            PromptGenerator promptGenerator = new PromptGenerator(List.of(template));
            promptGenerator.registerTemplate(SecurityDecisionRequest.TEMPLATE_TYPE.name(), template);

            SecurityEvent event = SecurityEvent.builder()
                    .eventId("event-generator-calibrated-001")
                    .timestamp(LocalDateTime.of(2026, 4, 18, 9, 30))
                    .userId("alice")
                    .sessionId("session-calibrated")
                    .sourceIp("203.0.113.11")
                    .description("POST /api/customer/export")
                    .build();
            event.addMetadata("httpMethod", "POST");
            event.addMetadata("requestPath", "/api/customer/export");

            SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
            sessionContext.setUserId("alice");
            sessionContext.setSessionId("session-calibrated");

            SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
            behaviorAnalysis.setPersonalBaselineEvidence(noDataBaselineEvidence());

            SecurityDecisionRequest request = new SecurityDecisionRequest(
                    new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of()));
            request.withParameter("requestedModelId", "gpt-4o-mini");

            PromptGenerationResult result = promptGenerator.generatePrompt(request, "", "");

            assertThat(result.getPromptExecutionMetadata()).isNotNull();
            assertThat(result.getPromptExecutionMetadata().promptTokenEstimate().estimatorKey())
                    .isEqualTo("MODEL_AWARE_TOKEN_COUNTING_V1");
        } finally {
            ObservedPromptTokenUsageRegistry.clear();
        }
    }

    @Test
    @DisplayName("PromptGenerator should attach governance metadata and raw/view prompt telemetry")
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
        behaviorAnalysis.setPersonalBaselineEvidence(noDataBaselineEvidence());

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
        assertThat(executionMetadata.budgetProfile().profileKey()).isEqualTo("CORTEX_L1_INTERACTIVE_STRICT");
        assertThat(executionMetadata.promptTokenEstimate().estimatorKey()).isEqualTo("MODEL_AWARE_TOKEN_COUNTING_V1");
        assertThat(executionMetadata.promptTokenEstimate().budgetEnforcementMode()).isEqualTo("LLM_VIEW_ENFORCED");
        assertThat(executionMetadata.promptTokenEstimate().estimatedTotalTokens()).isPositive();
        assertThat(executionMetadata.promptTokenEstimate().compressionApplied())
                .isEqualTo(executionMetadata.promptCompressionLedger().compressionApplied());
        assertThat(executionMetadata.promptCompressionLedger().transformationMode()).isIn("IDENTITY", "NORMALIZE_ONLY", "NORMALIZE_AND_COMPACT", "NORMALIZE_AND_FUSE");
        assertThat(executionMetadata.promptEvidenceCompleteness().name()).isEqualTo("INCOMPLETE");
        assertThat(executionMetadata.omittedSections()).contains("BRIDGE_AND_COVERAGE", "IDENTITY_AND_ROLE");
        assertThat(executionMetadata.duplicationInventory()).isNotEmpty();
        assertThat(executionMetadata.duplicationInventory())
                .extracting(PromptDuplicationRecord::dimension)
                .contains("session", "device", "location");
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
                "promptDuplicationInventory",
                "promptDuplicationInventoryVersion",
                "promptDuplicationInventoryCount",
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
        assertThat(result.getMetadata().get("promptDuplicationInventoryCount")).isEqualTo(executionMetadata.duplicationInventory().size());
        assertThat(result.getMetadata().get("promptDuplicationInventory")).asList().isNotEmpty();
        assertThat(result.getSystemPrompt()).doesNotContain("promptHash");
        assertThat(result.getUserPrompt()).doesNotContain("promptHash");
        assertThat(result.getRawSystemPrompt()).isNotBlank();
        assertThat(result.getRawUserPrompt()).isNotBlank();
        assertThat(result.getMetadata().get("promptCompressionApplied"))
                .isEqualTo(executionMetadata.promptCompressionLedger().compressionApplied());
    }

    @Test
    @DisplayName("PromptGenerator should keep raw cold-start evidence while compacting the LLM view below the standard budget")
    void generatePromptShouldCompactColdStartPromptWithoutLosingCriticalEvidence() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                null,
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                new PromptContextComposer());
        PromptGenerator promptGenerator = new PromptGenerator(List.of(template));
        promptGenerator.registerTemplate(SecurityDecisionRequest.TEMPLATE_TYPE.name(), template);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-generator-cold-start-001")
                .timestamp(LocalDateTime.of(2026, 4, 4, 19, 59))
                .userId("admin")
                .sessionId("session-cold-start")
                .sourceIp("0:0:0:0:0:0:0:1")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .description("AUTHORIZATION event: METHOD")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("previousPath", "/admin");
        event.addMetadata("lastRequestIntervalMs", 36172L);
        event.addMetadata("bridgeCoverageLevel", "AUTHORIZATION_CONTEXT");
        event.addMetadata("bridgeCoverageSummary", "Bridge completeness reached authentication and partial authorization context for the current request.");
        event.addMetadata("bridgeAuthenticationSource", "SECURITY_CONTEXT");
        event.addMetadata("bridgeAuthorizationSource", "SECURITY_CONTEXT");
        event.addMetadata("bridgeMissingContexts", List.of("AUTHORIZATION_EFFECT"));
        event.addMetadata("authorizationEffectProvenance", "METHOD_INVOCATION_RESULT");
        event.addMetadata("authorizationEffect", "ALLOW");
        event.addMetadata("effectiveRoles", List.of("DEVELOPER", "USER", "PENDING_ANALYSIS", "MANAGER", "ADMIN"));
        event.addMetadata("effectivePermissions", List.of("role.user", "role.developer", "role.manager", "role.pending.analysis", "role.admin"));
        event.addMetadata("mfaVerified", true);
        event.addMetadata("failedLoginAttempts", 0);
        event.addMetadata("recentRequestCount", 2);
        event.addMetadata("isNewSession", false);
        event.addMetadata("isNewDevice", true);
        event.addMetadata("isNewUser", false);
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("resourceLabel", "Sensitive Security Test Resource resource-001");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("admin");
        sessionContext.setSessionId("session-cold-start");
        sessionContext.setRequestCount(4);
        sessionContext.setRecentActions(List.of(
                "19:58 | MFA_COMPLETED (Zero Trust Challenge verified) | 0:0:0:0:0:0:0:1",
                "19:58 | GET /admin | 0:0:0:0:0:0:0:1",
                "19:59 | GET /admin/api/security-test/sensitive/resource-001 | 192.168.1.100",
                "19:59 | GET /admin/api/security-test/sensitive/resource-001 | 0:0:0:0:0:0:0:1"));

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(noDataBaselineEvidence());
        behaviorAnalysis.setBaselineEstablished(false);
        behaviorAnalysis.setIsNewSession(false);
        behaviorAnalysis.setIsNewDevice(true);
        behaviorAnalysis.setCurrentUserAgentOS("Windows");
        behaviorAnalysis.setCurrentUserAgentBrowser("Chrome/120");
        behaviorAnalysis.setLastRequestIntervalMs(36172L);
        behaviorAnalysis.setPreviousPath("/admin");
        behaviorAnalysis.setPersonalBaselineAvailable(false);
        behaviorAnalysis.setPersonalBaselineEstablished(false);
        behaviorAnalysis.setOrganizationBaselineAvailable(false);
        behaviorAnalysis.setOrganizationBaselineEstablished(false);

        PromptGenerationResult result = promptGenerator.generatePrompt(
                new SecurityDecisionRequest(
                        new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of())),
                "",
                "");

        PromptExecutionMetadata executionMetadata = result.getPromptExecutionMetadata();
        assertThat(result.getRawUserPrompt()).contains("AvailableFacts:");
        assertThat(result.getRawUserPrompt()).contains("RemediationHints:");
        assertThat(result.getUserPrompt()).contains("AuthorizationEffectProvenance: METHOD_INVOCATION_RESULT");
        assertThat(result.getUserPrompt()).contains("AuthorizationEffectStageNote: Bridge stamp omitted AuthorizationEffect; final AuthorizationEffect was resolved later from METHOD_INVOCATION_RESULT.");
        assertThat(result.getUserPrompt()).contains("RequestPath: /admin/api/security-test/sensitive/resource-001");
        assertThat(result.getUserPrompt()).contains("Sensitivity: HIGH");
        assertThat(result.getUserPrompt()).contains("AuthorizationEffect: ALLOW");
        assertThat(result.getUserPrompt()).contains("BaselineGapSupport:");
        assertThat(result.getUserPrompt()).contains("CoverageLevel: BUSINESS_AWARE");
        assertThat(result.getUserPrompt()).doesNotContain("AvailableFacts:\n-");
        assertThat(result.getUserPrompt()).doesNotContain("RemediationHints:\n-");
        assertThat(result.getUserPrompt()).doesNotContain("BridgeRemediationHints:");
        assertThat(executionMetadata.promptTokenEstimate().estimatedTotalTokens()).isPositive();
        assertThat(executionMetadata.promptCompressionLedger().records())
                .extracting(PromptCompressionRecord::scopeKey)
                .contains("CONTEXT_COVERAGE", "GLOBAL_REQUEST_FACTS");
    }

    @Test
    @DisplayName("PromptGenerator should carry explicit resource and official slot context into canonical prompt sections")
    void generatePromptShouldCarryExplicitResourceAndOfficialSlotContextIntoCanonicalPromptSections() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                null,
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                new PromptContextComposer());
        PromptGenerator promptGenerator = new PromptGenerator(List.of(template));
        promptGenerator.registerTemplate(SecurityDecisionRequest.TEMPLATE_TYPE.name(), template);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-generator-step3-self-001")
                .timestamp(LocalDateTime.of(2026, 4, 18, 10, 0))
                .userId("persona_fin")
                .sessionId("self-step3-session")
                .sourceIp("10.10.0.20")
                .userAgent("Mozilla/5.0 (Windows 11) Chrome/120")
                .description("GET /admin/api/security-test/sensitive/self-sensitive-1")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/self-sensitive-1");
        event.addMetadata("resourceId", "self-sensitive-1");
        event.addMetadata("requestedResourceId", "self-sensitive-1");
        event.addMetadata("protectedResourceId", "self-sensitive-1");
        event.addMetadata("resourceType", "sensitive");
        event.addMetadata("resourceCategory", "sensitive");
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("resourceLabel", "Sensitive Security Test Resource self-sensitive-1");
        event.addMetadata("country", "KR");
        event.addMetadata("city", "Seoul");
        event.addMetadata("ipBand", "10.10.0.0/24");
        event.addMetadata("asn", "AS9318");
        event.addMetadata("deviceOs", "Windows");
        event.addMetadata("deviceOsVersion", "11");
        event.addMetadata("deviceBrowser", "Chrome");
        event.addMetadata("deviceBrowserVersion", "120");
        event.addMetadata("deviceLanguage", "ko-KR");
        event.addMetadata("deviceFingerprintMatch", true);
        event.addMetadata("authenticationType", "PASSWORD");
        event.addMetadata("mfaVerified", true);
        event.addMetadata("currentAccessHour", 10);
        event.addMetadata("intentMissingReferer", false);

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("persona_fin");
        sessionContext.setSessionId("self-step3-session");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPersonalBaselineEvidence(noDataBaselineEvidence());

        PromptGenerationResult result = promptGenerator.generatePrompt(
                new SecurityDecisionRequest(
                        new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of())),
                "",
                "");

        assertThat(result.getUserPrompt()).contains("=== DEVICE CONTEXT ===");
        assertThat(result.getUserPrompt()).contains("=== LOCATION CONTEXT ===");
        assertThat(result.getUserPrompt()).contains("=== RESOURCE AND ACTION CONTEXT ===");
        assertThat(result.getUserPrompt()).contains("DeviceOs: WINDOWS");
        assertThat(result.getUserPrompt()).contains("DeviceBrowser: Chrome");
        assertThat(result.getUserPrompt()).contains("Country: KR");
        assertThat(result.getUserPrompt()).contains("City: Seoul");
        assertThat(result.getUserPrompt()).contains("IpBand: 10.10.0.0/24");
        assertThat(result.getUserPrompt()).contains("ResourceId: self-sensitive-1");
        assertThat(result.getUserPrompt()).contains("ResourceType: SENSITIVE");
        assertThat(result.getUserPrompt()).contains("Sensitivity: HIGH");
        assertThat(result.getPromptExecutionMetadata().sectionSet())
                .contains("DEVICE_CONTEXT", "LOCATION_CONTEXT", "RESOURCE_AND_ACTION");
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



