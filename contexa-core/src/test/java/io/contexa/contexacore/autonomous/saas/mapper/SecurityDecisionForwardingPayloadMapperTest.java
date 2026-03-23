package io.contexa.contexacore.autonomous.saas.mapper;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.saas.dto.SecurityDecisionForwardingPayload;
import io.contexa.contexacore.autonomous.saas.security.TenantScopedPseudonymizationService;
import io.contexa.contexacore.autonomous.saas.threat.ThreatSignalNormalizationService;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
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
                properties);

        SecurityDecisionForwardingPayload payload = mapper.map(context());

        assertThat(payload.getDecision()).isEqualTo("BLOCK");
        assertThat(payload.getReasoning()).isNull();
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
                .containsEntry("llmAuditConfidence", 0.88);
    }

    @Test
    void mapIncludesReasoningWhenEnabled() {
        SaasForwardingProperties properties = properties(true);
        SecurityDecisionForwardingPayloadMapper mapper = new SecurityDecisionForwardingPayloadMapper(
                new TenantScopedPseudonymizationService(properties),
                new ThreatSignalNormalizationService(),
                properties);

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
                        Map.entry("threatKnowledgeSignalKeys", List.of("signal-1")),
                        Map.entry("threatKnowledgeMatchedFacts", List.of("shared_geo_country", "shared_surface")),
                        Map.entry("reasoningMemoryApplied", true),
                        Map.entry("baselineSeedApplied", true),
                        Map.entry("personalBaselineEstablished", true),
                        Map.entry("organizationBaselineEstablished", true)))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action("BLOCK")
                .riskScore(null)
                .confidence(null)
                .llmAuditRiskScore(0.93)
                .llmAuditConfidence(0.88)
                .aiAnalysisLevel(2)
                .processingTimeMs(1820L)
                .reasoning("Suspicious impossible-travel pattern detected")
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


