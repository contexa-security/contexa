package io.contexa.contexacore.autonomous.saas.mapper;

import io.contexa.contexacore.autonomous.domain.AdminOverride;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.ThreatOutcomePayload;
import io.contexa.contexacore.autonomous.saas.security.TenantScopedPseudonymizationService;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

class ThreatOutcomePayloadMapperTest {

    @Test
    void mapCarriesThreatKnowledgeTraceIntoOutcomeAttributes() {
        SaasForwardingProperties properties = SaasForwardingProperties.builder()
                .enabled(true)
                .endpoint("https://saas.example.com")
                .pseudonymizationSecret("top-secret-key")
                .globalCorrelationSecret("global-correlation-secret")
                .build();
        ThreatOutcomePayloadMapper mapper = new ThreatOutcomePayloadMapper(new TenantScopedPseudonymizationService(properties));

        ThreatOutcomePayload payload = mapper.map(adminOverride(), originalEvent());

        assertThat(payload.getOutcomeType()).isEqualTo("FALSE_POSITIVE");
        assertThat(payload.getFinalDisposition()).isEqualTo("BENIGN");
        assertThat(payload.getOutcomeTimestamp()).isEqualTo(LocalDateTime.ofInstant(Instant.parse("2026-03-16T08:30:00Z"), ZoneOffset.UTC));
        assertThat(payload.getAttributes())
                .containsEntry("threatKnowledgeApplied", true)
                .containsEntry("threatKnowledgeExperimentGroup", "KNOWLEDGE_ASSISTED")
                .containsEntry("threatKnowledgeCaseCount", 2)
                .containsEntry("threatKnowledgePrimaryKey", "case-primary-1")
                .containsEntry("threatKnowledgeSignalKeys", List.of("signal-1"))
                .containsEntry("reasoningMemoryApplied", true)
                .containsEntry("baselineSeedApplied", true)
                .containsEntry("personalBaselineEstablished", true)
                .containsEntry("organizationBaselineEstablished", true);
    }

    private AdminOverride adminOverride() {
        return AdminOverride.builder()
                .overrideId("override-1")
                .requestId("corr-001")
                .userId("user-1")
                .adminId("admin-1")
                .timestamp(Instant.parse("2026-03-16T08:30:00Z"))
                .originalAction("BLOCK")
                .overriddenAction("ALLOW")
                .reason("Admin confirmed legitimate device context")
                .approved(true)
                .originalRiskScore(0.9)
                .originalConfidence(0.7)
                .build();
    }

    private SecurityEvent originalEvent() {
        return SecurityEvent.builder()
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
    }
}
