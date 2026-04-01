package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxDecisionAdjudicationServiceTest {

    private final SandboxDecisionAdjudicationService adjudicationService = new SandboxDecisionAdjudicationService();

    @Test
    @DisplayName("fallback signal and evidence limitation reasoning should be grounded when prompt exposes the same constraints")
    void shouldGroundFallbackSignalAndEvidenceLimitationClaims() {
        SecurityEvent event = SecurityEvent.builder()
                .metadata(Map.of(
                        "resourceSensitivity", "HIGH",
                        "mfaVerified", true,
                        "isNewUser", false,
                        "isNewSession", false,
                        "isNewDevice", false))
                .build();

        String userPrompt = """
                Sensitivity: HIGH
                === BASELINE EVIDENCE CONSTRAINTS ===
                ConfidenceWarning: Role scope field roleScope.expectedActionFamilies has thin or fallback-heavy evidence.
                ContextFieldLimitation: roleScope.expectedActionFamilies | value derivation depends on fallback signals
                WorkProfileSummary: Window 7d | Observations 2
                """;

        SandboxPromptTraceSnapshot snapshot = new SandboxPromptTraceSnapshot(
                "request-001",
                Instant.parse("2026-04-01T00:00:00Z"),
                event,
                null,
                null,
                List.of(),
                null,
                "system",
                userPrompt,
                Map.of(),
                null);

        SandboxPromptReplayRound round = new SandboxPromptReplayRound(
                "FOLLOW_UP",
                3,
                null,
                "request-001",
                "/admin/api/security-test/sensitive/resource-001",
                "192.168.1.100",
                "Chrome 120 / Windows 11",
                "device-001",
                Map.of(),
                snapshot);

        SandboxDecisionGoldCase goldCase = new SandboxDecisionGoldCase(
                "ADMIN_SPARSE_HISTORY_THEN_HIGH_VALUE_REENTRY",
                "R03",
                "SPARSE_EVIDENCE",
                "FOLLOW_UP",
                "SPARSE_HISTORY",
                List.of("CHALLENGE", "ESCALATE"),
                List.of("ALLOW", "BLOCK"),
                new SandboxDecisionConfidenceBand(0.35d, 0.75d),
                true,
                List.of("baseline", "sensitivity"),
                List.of(),
                "test");

        SandboxDecisionAdjudication adjudication = adjudicationService.adjudicate(
                round,
                goldCase,
                "The decision lacks sufficient evidence for sensitive access and relies on fallback signals.");

        assertThat(adjudication.groundedClaimPrecision()).isEqualTo(100.0d);
        assertThat(adjudication.unsupportedClaimRate()).isEqualTo(0.0d);
        assertThat(adjudication.contradictedClaimRate()).isEqualTo(0.0d);
        assertThat(adjudication.uncertaintyLanguagePresent()).isTrue();
        assertThat(adjudication.requiredEvidenceCovered()).isTrue();
    }

    @Test
    @DisplayName("baseline evidence and provisional role profile reasoning should be grounded when compact prompt retains those anchors")
    void shouldGroundBaselineAndProvisionalRoleProfileClaims() {
        SecurityEvent event = SecurityEvent.builder()
                .metadata(Map.of("mfaVerified", true))
                .build();

        String userPrompt = """
                Sensitivity: HIGH
                WorkProfileSummary: Window 7d | Observations 2
                ConfidenceWarning: Role scope baseline is thin; treat expected scope as provisional until more authorized observations accumulate.
                ContextTrustWarning: ROLE_SCOPE_PROFILE | thin role scope evidence
                """;

        SandboxPromptTraceSnapshot snapshot = new SandboxPromptTraceSnapshot(
                "request-002",
                Instant.parse("2026-04-01T00:00:00Z"),
                event,
                null,
                null,
                List.of(),
                null,
                "system",
                userPrompt,
                Map.of(),
                null);

        SandboxPromptReplayRound round = new SandboxPromptReplayRound(
                "FOLLOW_UP",
                3,
                null,
                "request-002",
                "/admin/api/security-test/sensitive/resource-001",
                "192.168.1.100",
                "Chrome 120 / Windows 11",
                "device-001",
                Map.of(),
                snapshot);

        SandboxDecisionGoldCase goldCase = new SandboxDecisionGoldCase(
                "ADMIN_MIXED_SCOPE_THEN_APPROVAL_AMBIGUITY",
                "R01",
                "APPROVAL_AMBIGUITY",
                "FOLLOW_UP",
                "APPROVAL_AMBIGUITY",
                List.of("CHALLENGE", "ESCALATE"),
                List.of("ALLOW", "BLOCK"),
                new SandboxDecisionConfidenceBand(0.35d, 0.75d),
                true,
                List.of("baseline", "sensitivity"),
                List.of(),
                "test");

        SandboxDecisionAdjudication adjudication = adjudicationService.adjudicate(
                round,
                goldCase,
                "The request lacks trusted scope evidence for sensitive access and shows provisional role profiles.");

        assertThat(adjudication.groundedClaimPrecision()).isEqualTo(100.0d);
        assertThat(adjudication.unsupportedClaimRate()).isEqualTo(0.0d);
        assertThat(adjudication.contradictedClaimRate()).isEqualTo(0.0d);
        assertThat(adjudication.uncertaintyLanguagePresent()).isTrue();
        assertThat(adjudication.requiredEvidenceCovered()).isTrue();
    }
}
