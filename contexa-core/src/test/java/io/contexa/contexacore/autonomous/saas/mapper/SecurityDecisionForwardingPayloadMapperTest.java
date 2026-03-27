package io.contexa.contexacore.autonomous.saas.mapper;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.saas.dto.SecurityDecisionForwardingPayload;
import io.contexa.contexacore.autonomous.saas.security.TenantScopedPseudonymizationService;
import io.contexa.contexacore.autonomous.saas.threat.ThreatSignalNormalizationService;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityDecisionForwardingPayloadMapperTest {

    @Test
    void mapExcludesReasoningByDefault() {
        SaasForwardingProperties properties = properties(false);
        SecurityDecisionForwardingPayloadMapper mapper = new SecurityDecisionForwardingPayloadMapper(
                new TenantScopedPseudonymizationService(properties),
                new ThreatSignalNormalizationService(),
                properties,
                canonicalSecurityContextProvider());

        SecurityDecisionForwardingPayload payload = mapper.map(context());

        assertThat(payload.getDecision()).isEqualTo("BLOCK");
        assertThat(payload.getLlmProposedAction()).isEqualTo("ALLOW");
        assertThat(payload.getAutonomousEnforcementAction()).isEqualTo("BLOCK");
        assertThat(payload.getLlmAuditRiskScore()).isEqualTo(0.93);
        assertThat(payload.getEffectiveConfidence()).isEqualTo(0.54);
        assertThat(payload.getLlmAuditConfidence()).isEqualTo(0.88);
        assertThat(payload.getAutonomyConstraintApplied()).isTrue();
        assertThat(payload.getAutonomyConstraintSummary()).contains("approval lineage");
        assertThat(payload.getReasoning()).isNull();
        assertThat(payload.getWorkProfileSummary()).contains("Frequent protectable resources");
        assertThat(payload.getRoleDriftSummary()).contains("Current resource family: ACCOUNT");
        assertThat(payload.getRoleDriftSummary()).contains("Current action family: READ");
        assertThat(payload.getApprovalSummary()).contains("Approval status: PENDING");
        assertThat(payload.getObjectiveDriftSummary()).contains("Delegated objective comparison is incomplete");
        assertThat(payload.getPromptKey()).isEqualTo("security-decision-standard");
        assertThat(payload.getPromptTemplateKey()).isEqualTo("SecurityDecisionStandard");
        assertThat(payload.getPromptVersion()).isEqualTo("2026.03.27-e0.2");
        assertThat(payload.getPromptContractVersion()).isEqualTo("CORTEX_PROMPT_CONTRACT_V2");
        assertThat(payload.getPromptReleaseStatus()).isEqualTo("PRODUCTION");
        assertThat(payload.getPromptHash()).isEqualTo("sha256:prompt");
        assertThat(payload.getSystemPromptHash()).isEqualTo("sha256:system");
        assertThat(payload.getUserPromptHash()).isEqualTo("sha256:user");
        assertThat(payload.getBudgetProfile()).isEqualTo("CORTEX_L2_STANDARD");
        assertThat(payload.getPromptEvidenceCompleteness()).isEqualTo("SUFFICIENT");
        assertThat(payload.getPromptSectionSet()).containsExactly("CURRENT_REQUEST", "ROLE_SCOPE", "EXPLICIT_MISSING_KNOWLEDGE");
        assertThat(payload.getOmittedSections()).containsExactly("RAG_CONTEXT");
        assertThat(payload.getPromptOmissionCount()).isEqualTo(1);
        assertThat(payload.getPromptGeneratedAtEpochMs()).isEqualTo(1711111111111L);
        assertThat(payload.getBehaviorPatterns()).containsExactly("IMPOSSIBLE_TRAVEL", "NEW_DEVICE");
        assertThat(payload.getEvidenceList()).containsExactly(
                "geo_velocity_anomaly",
                "new_browser_fingerprint",
                "token_replay");
        assertThat(payload.getRequestPath()).isEqualTo("/api/account/profile");
        assertThat(payload.getHashedUserId()).isNotBlank();
        assertThat(payload.getGlobalSourceKey()).isNotBlank();
        assertThat(payload.getCanonicalThreatClass()).isEqualTo("account_takeover");
        assertThat(payload.getMitreTacticHints()).contains("Initial Access", "Credential Access");
        assertThat(payload.getTargetSurfaceCategory()).isEqualTo("application");
        assertThat(payload.getSignalTags()).contains("new_device", "impossible_travel", "geo_velocity", "session_takeover_risk");
        assertThat(payload.getAttributes())
                .containsEntry("threatKnowledgeApplied", true)
                .containsEntry("threatKnowledgeExperimentGroup", "KNOWLEDGE_ASSISTED")
                .containsEntry("threatKnowledgePrimaryKey", "case-primary-1")
                .containsEntry("reasoningMemoryApplied", true)
                .containsEntry("baselineSeedApplied", true)
                .containsEntry("personalBaselineEstablished", true)
                                .containsEntry("organizationBaselineEstablished", true)
                .containsEntry("operationalEvidenceSource", "THREAT_INDICATORS")
                .containsEntry("llmAuditRiskScore", 0.93)
                .containsEntry("bridgeCoverageLevel", "AUTHORIZATION_CONTEXT")
                .containsEntry("bridgeCoverageScore", 75)
                .containsEntry("bridgeCoverageSummary", "Bridge resolved authentication and authorization context for the current request.")
                .containsEntry("bridgeAuthenticationSource", "SECURITY_CONTEXT")
                .containsEntry("bridgeAuthorizationSource", "HEADER")
                .containsEntry("bridgeDelegationSource", "NONE")
                .containsEntry("llmAuditConfidence", 0.88)
                .containsEntry("effectiveConfidence", 0.54)
                .containsEntry("workProfileSummary", payload.getWorkProfileSummary())
                .containsEntry("roleDriftSummary", payload.getRoleDriftSummary())
                .containsEntry("approvalSummary", payload.getApprovalSummary())
                .containsEntry("objectiveDriftSummary", payload.getObjectiveDriftSummary())
                .containsEntry("promptVersion", payload.getPromptVersion())
                .containsEntry("promptHash", payload.getPromptHash())
                .containsEntry("budgetProfile", payload.getBudgetProfile())
                .containsEntry("promptEvidenceCompleteness", payload.getPromptEvidenceCompleteness())
                .containsEntry("promptRuntimeTelemetryLinked", true)
                .containsEntry("promptRuntimeTelemetryLayer", "Layer2");
    }

    @Test
    void mapIncludesReasoningWhenEnabled() {
        SaasForwardingProperties properties = properties(true);
        SecurityDecisionForwardingPayloadMapper mapper = new SecurityDecisionForwardingPayloadMapper(
                new TenantScopedPseudonymizationService(properties),
                new ThreatSignalNormalizationService(),
                properties,
                canonicalSecurityContextProvider());

        SecurityDecisionForwardingPayload payload = mapper.map(context());

        assertThat(payload.getReasoning()).isEqualTo("Suspicious impossible-travel pattern detected");
    }

    private SaasForwardingProperties properties(boolean includeReasoning) {
        return SaasForwardingProperties.builder()
                .enabled(true)
                .endpoint("https://saas.example.com")
                .pseudonymizationSecret("top-secret-key")
                .globalCorrelationSecret("global-correlation-secret")
                .includeReasoning(includeReasoning)
                .oauth2(SaasForwardingProperties.OAuth2.builder()
                        .enabled(true)
                        .registrationId("reg")
                        .tokenUri("https://auth.example.com/oauth2/token")
                        .clientId("client")
                        .clientSecret("secret")
                        .scope("saas.xai.decision.ingest")
                        .expirySkewSeconds(30)
                        .build())
                .build();
    }

    private CanonicalSecurityContextProvider canonicalSecurityContextProvider() {
        CanonicalSecurityContext canonicalSecurityContext = CanonicalSecurityContext.builder()
                .workProfile(CanonicalSecurityContext.WorkProfile.builder()
                        .summary("Frequent protectable resources: /api/account/profile | Frequent action families: READ | Protectable invocation density: 0.67")
                        .build())
                .roleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                        .currentResourceFamily("ACCOUNT")
                        .currentActionFamily("READ")
                        .resourceFamilyDrift(true)
                        .actionFamilyDrift(false)
                        .summary("Current resource family: ACCOUNT | Current action family: READ")
                        .build())
                .frictionProfile(CanonicalSecurityContext.FrictionProfile.builder()
                        .approvalRequired(true)
                        .approvalStatus("PENDING")
                        .approvalMissing(true)
                        .approvalLineage(List.of("manager-approval"))
                        .summary("Approval required: true | Approval status: PENDING | Approval missing: true | Approval lineage: manager-approval")
                        .build())
                .delegation(CanonicalSecurityContext.Delegation.builder()
                        .delegated(true)
                        .objectiveFamily("ACCOUNT_SUPPORT")
                        .objectiveDrift(null)
                        .objectiveDriftSummary("Delegated objective comparison is incomplete because comparable delegated action/resource family inputs are missing.")
                        .build())
                .build();
        return event -> java.util.Optional.of(canonicalSecurityContext);
    }

    private SecurityEventContext context() {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-001")
                .timestamp(LocalDateTime.of(2026, 3, 16, 13, 30))
                .source(SecurityEvent.EventSource.IAM)
                .severity(SecurityEvent.Severity.HIGH)
                .userId("user-1")
                .sessionId("sess-1")
                .sourceIp("10.10.10.10")
                .metadata(Map.ofEntries(
                        Map.entry("tenantId", "tenant-acme"),
                        Map.entry("requestPath", "/api/account/profile"),
                        Map.entry("geoCountry", "US"),
                        Map.entry("isNewDevice", true),
                        Map.entry("isImpossibleTravel", true),
                        Map.entry("travelDistanceKm", 9234.2),
                        Map.entry("failedLoginAttempts", 4),
                        Map.entry("threatKnowledgeApplied", true),
                        Map.entry("threatKnowledgeExperimentGroup", "KNOWLEDGE_ASSISTED"),
                        Map.entry("threatKnowledgeCaseCount", 2),
                        Map.entry("threatKnowledgePrimaryKey", "case-primary-1"),
                        Map.entry("threatKnowledgeKeys", List.of("case-primary-1", "case-secondary-2")),
                        Map.entry("bridgeCoverageLevel", "AUTHORIZATION_CONTEXT"),
                        Map.entry("bridgeCoverageScore", 75),
                        Map.entry("bridgeCoverageSummary", "Bridge resolved authentication and authorization context for the current request."),
                        Map.entry("bridgeMissingContexts", List.of("DELEGATION")),
                        Map.entry("bridgeRemediationHints", List.of("If delegated agents are used, propagate delegation metadata for the current request. Otherwise this gap can be ignored.")),
                        Map.entry("bridgeAuthenticationSource", "SECURITY_CONTEXT"),
                        Map.entry("bridgeAuthorizationSource", "HEADER"),
                        Map.entry("bridgeDelegationSource", "NONE"),
                        Map.entry("threatKnowledgeSignalKeys", List.of("signal-1")),
                        Map.entry("threatKnowledgeMatchedFacts", List.of("shared_geo_country", "shared_surface")),
                        Map.entry("reasoningMemoryApplied", true),
                        Map.entry("baselineSeedApplied", true),
                        Map.entry("personalBaselineEstablished", true),
                        Map.entry("organizationBaselineEstablished", true),
                        Map.entry("promptKey", "security-decision-standard"),
                        Map.entry("templateKey", "SecurityDecisionStandard"),
                        Map.entry("promptVersion", "2026.03.27-e0.2"),
                        Map.entry("contractVersion", "CORTEX_PROMPT_CONTRACT_V2"),
                        Map.entry("promptReleaseStatus", "PRODUCTION"),
                        Map.entry("promptHash", "sha256:prompt"),
                        Map.entry("systemPromptHash", "sha256:system"),
                        Map.entry("userPromptHash", "sha256:user"),
                        Map.entry("budgetProfile", "CORTEX_L2_STANDARD"),
                        Map.entry("promptEvidenceCompleteness", "SUFFICIENT"),
                        Map.entry("promptSectionSet", List.of("CURRENT_REQUEST", "ROLE_SCOPE", "EXPLICIT_MISSING_KNOWLEDGE")),
                        Map.entry("omittedSections", List.of("RAG_CONTEXT")),
                        Map.entry("promptOmissionCount", 1),
                        Map.entry("promptGeneratedAtEpochMs", 1711111111111L),
                        Map.entry("promptRuntimeTelemetryLinked", true),
                        Map.entry("promptRuntimeTelemetryLayer", "Layer2")))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action("BLOCK")
                .proposedAction("ALLOW")
                .riskScore(null)
                .confidence(0.54)
                .llmAuditRiskScore(0.93)
                .llmAuditConfidence(0.88)
                .aiAnalysisLevel(2)
                .processingTimeMs(1820L)
                .reasoning("Suspicious impossible-travel pattern detected")
                .autonomyConstraintApplied(true)
                .autonomyConstraintSummary("Autonomous allow is not permitted until approval lineage is explicit.")
                .threatIndicators(List.of("geo_velocity_anomaly", "new_browser_fingerprint", "token_replay"))
                .analysisData(Map.of(
                        "behaviorPatterns", List.of("IMPOSSIBLE_TRAVEL", "NEW_DEVICE"),
                        "threatCategory", "ACCOUNT_TAKEOVER"))
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        context.addMetadata("processingResult", result);
        context.addMetadata("correlationId", "corr-001");
        return context;
    }
}


