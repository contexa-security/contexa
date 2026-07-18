package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.verification.runtime.OfficialVerificationAnalysisEventStore.AnalysisEvent;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationEirExecutionService.EndpointDefinition;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OfficialVerificationEirEvidenceFactoryTest {

    @Test
    void normalRequestKeepsAllExistingRequestEventAndDecisionChecksAligned() {
        OfficialVerificationEirEvidenceFactory factory = new OfficialVerificationEirEvidenceFactory();
        EndpointDefinition endpoint = new EndpointDefinition("normal", "Normal Resource", "/probe/normal", "resource-1");
        Map<String, Object> invocation = Map.of(
                "requestId", "request-1",
                "requestedResourceId", "resource-1",
                "contaminationSeed", false,
                "baselineSeedRequested", false,
                "requestPath", "/probe/normal");
        Map<String, Object> metadata = Map.ofEntries(
                Map.entry("clientIp", OfficialVerificationEirExecutionService.EIR_CLIENT_IP),
                Map.entry("requestId", "request-1"),
                Map.entry("requestPath", "/probe/normal"),
                Map.entry("mfaVerified", true),
                Map.entry("resourceSensitivity", "STANDARD"),
                Map.entry("isSensitiveResource", false),
                Map.entry("authMethod", "PASSWORD"),
                Map.entry("authorizationEffect", "ALLOW"),
                Map.entry("effectiveRoles", List.of("USER")),
                Map.entry("effectivePermissions", List.of("READ")));
        AnalysisEvent event = new AnalysisEvent(
                "verification-user", "request-1", "correlation-1", "DECISION", "SECURITY", "COMPLETED",
                "ALLOW", "/probe/normal", "verified", 1L, Instant.parse("2026-07-16T00:00:00Z"), metadata);

        var checks = factory.buildChecks(
                "request-1", endpoint, invocation, List.of(event), false, false);

        assertThat(checks).hasSize(15).allMatch(OfficialVerificationEirExecutionService.EirCheckResult::pass);
    }
}