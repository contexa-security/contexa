package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.inference.ContextCoverageEvaluator;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.registry.InMemoryResourceContextRegistry;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
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
        behaviorAnalysis.setBaselineContext("=== PERSONAL BASELINE STATUS ===\n"
                + "PersonalBaselineStatus: NOT_ESTABLISHED\n"
                + "PersonalBaselineSummary: No verified personal behavior baseline is available for this subject yet.\n"
                + "BaselineInterpretation: Missing personal history is uncertainty, not proof of compromise or legitimacy.\n"
                + "BaselineComparisonStatus: No verified personal history is available for direct comparison.\n"
                + "BaselineCollectorGuidance: Use only current request facts and any separately retrieved evidence.\n\n"
                + "Current Request Context:\n"
                + "  IP: 0:0:0:0:0:0:0:1 (range loopback)\n"
                + "  Hour: 19\n"
                + "  UA: Chrome/120\n\n"
                + "=== BASELINE COMPARISON NOTES ===\n"
                + "- RELATED CONTEXT may contain verified historical evidence if retrieval returns matching records.\n"
                + "- If RELATED CONTEXT is EMPTY, there is no verified personal comparison evidence for this request.\n"
                + "- Do not infer subject legitimacy or compromise solely from the absence of personal baseline data.\n");
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
        assertThat(executionMetadata.promptTokenEstimate().estimatedTotalTokens())
                .isLessThanOrEqualTo(executionMetadata.budgetProfile().maxInputTokens());
        assertThat(executionMetadata.promptTokenEstimate().budgetExceeded()).isFalse();
        assertThat(executionMetadata.promptCompressionLedger().records())
                .extracting(PromptCompressionRecord::scopeKey)
                .contains("CONTEXT_COVERAGE", "CONTEXT_COVERAGE_BUDGET", "GLOBAL_REQUEST_FACTS");
    }
}



