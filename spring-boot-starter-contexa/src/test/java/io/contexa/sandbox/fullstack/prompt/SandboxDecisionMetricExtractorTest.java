package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxDecisionMetricExtractorTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    @DisplayName("SandboxDecisionGoldCaseCatalog는 baseline 초기 라운드를 uncertainty-required gold case로 정규화해야 한다")
    void goldCaseCatalogShouldNormalizeInitialBaselineRound() {
        SandboxPromptReplayScenario scenario = SandboxPromptReplayScenarioCatalog
                .resizeScenario(SandboxPromptReplayScenarioCatalog.ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE, 3);
        SandboxPromptReplayRound round = round(
                scenario,
                1,
                "ALLOW",
                0.62d,
                "High sensitivity access with provisional baseline evidence and limited history.");

        SandboxDecisionGoldCase goldCase = SandboxDecisionGoldCaseCatalog.resolve(scenario, round);

        assertThat(goldCase.safeActions()).contains("ALLOW", "CHALLENGE", "ESCALATE");
        assertThat(goldCase.uncertaintyRequired()).isTrue();
        assertThat(goldCase.confidenceBand().contains(0.62d)).isTrue();
        assertThat(goldCase.goldVersion()).isEqualTo(SandboxDecisionBenchmarkSettings.goldVersion());
    }

    @Test
    @DisplayName("SandboxDecisionAdjudicationService는 evidence와 모순되는 reasoning claim을 CONTRADICTED로 표시해야 한다")
    void adjudicationServiceShouldMarkContradictedClaims() {
        SandboxPromptReplayScenario scenario = SandboxPromptReplayScenarioCatalog
                .resizeScenario(SandboxPromptReplayScenarioCatalog.ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE, 3);
        SandboxPromptReplayRound round = round(
                scenario,
                2,
                "ALLOW",
                0.70d,
                "New user requested high sensitivity access and MFA verified.");

        SandboxDecisionAdjudication adjudication = new SandboxDecisionAdjudicationService().adjudicate(
                round,
                SandboxDecisionGoldCaseCatalog.resolve(scenario, round),
                "New user requested high sensitivity access and MFA verified.");

        assertThat(adjudication.contradictedClaimCount()).isGreaterThanOrEqualTo(1);
        assertThat(adjudication.claimAssessments())
                .extracting(SandboxDecisionClaimAssessment::verdict)
                .contains(SandboxDecisionClaimVerdict.CONTRADICTED);
    }

    @Test
    @DisplayName("ambiguity family gold case는 uncertainty-required와 보수적 safe action 집합을 유지해야 한다")
    void goldCaseCatalogShouldRequireUncertaintyForAmbiguityFamilies() {
        SandboxPromptReplayScenario sparseScenario = SandboxPromptReplayScenarioCatalog
                .resizeScenario(SandboxPromptReplayScenarioCatalog.ADMIN_SPARSE_HISTORY_THEN_HIGH_VALUE_REENTRY, 20);
        SandboxPromptReplayRound sparseRound = round(
                sparseScenario,
                19,
                "CHALLENGE",
                0.61d,
                "Sparse baseline and limited history keep the current high-value access uncertain.");

        SandboxDecisionGoldCase sparseGoldCase = SandboxDecisionGoldCaseCatalog.resolve(sparseScenario, sparseRound);

        assertThat(sparseGoldCase.uncertaintyRequired()).isTrue();
        assertThat(sparseGoldCase.safeActions()).contains("CHALLENGE", "ESCALATE");
        assertThat(sparseGoldCase.confidenceBand().contains(0.61d)).isTrue();

        SandboxPromptReplayScenario approvalScenario = SandboxPromptReplayScenarioCatalog
                .resizeScenario(SandboxPromptReplayScenarioCatalog.ADMIN_MIXED_SCOPE_THEN_APPROVAL_AMBIGUITY, 20);
        SandboxPromptReplayRound approvalRound = round(
                approvalScenario,
                19,
                "ESCALATE",
                0.70d,
                "Critical scope appears with limited scope history and ambiguous approval evidence.");

        SandboxDecisionGoldCase approvalGoldCase = SandboxDecisionGoldCaseCatalog.resolve(approvalScenario, approvalRound);

        assertThat(approvalGoldCase.uncertaintyRequired()).isTrue();
        assertThat(approvalGoldCase.safeActions()).contains("CHALLENGE", "ESCALATE");
        assertThat(approvalGoldCase.requiredEvidenceTokens()).contains("scope", "baseline", "history");
    }

    @Test
    @DisplayName("SandboxDecisionMetricExtractor는 grounded reasoning과 safe uncertainty를 포함한 decision trace를 지표로 환산해야 한다")
    void metricExtractorShouldProduceDecisionMetrics() throws Exception {
        SandboxPromptReplayScenario scenario = SandboxPromptReplayScenarioCatalog
                .resizeScenario(SandboxPromptReplayScenarioCatalog.ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE, 3);
        SandboxPromptReplayRun replayRun = new SandboxPromptReplayRun(
                "decision-run-001",
                "decision-user@example.com",
                scenario.scenarioKey(),
                scenario.experimentGroup(),
                scenario,
                List.of(
                        round(
                                scenario,
                                1,
                                "ALLOW",
                                0.62d,
                                "High sensitivity access with provisional baseline evidence and limited history."),
                        round(
                                scenario,
                                2,
                                "ESCALATE",
                                0.71d,
                                "High sensitivity surge with limited baseline and previous path deviation."),
                        round(
                                scenario,
                                3,
                                "CHALLENGE",
                                0.68d,
                                "High sensitivity surge with provisional baseline, previous path mismatch and limited history.")));

        SandboxDecisionBenchmarkRunResult runResult = SandboxDecisionMetricExtractor.evaluateRun(objectMapper, replayRun);

        assertThat(runResult.metrics()).containsKeys("CDC", "ERA", "SUHR");
        assertThat(runResult.roundResults()).hasSize(3);
        assertThat(runResult.metrics().get("CDC")).isGreaterThan(0.0d);
        assertThat(runResult.metrics().get("ERA")).isGreaterThan(0.0d);
        assertThat(runResult.metrics().get("SUHR")).isGreaterThan(0.0d);

        Path tempDirectory = Files.createTempDirectory("sandbox-decision-metric-writer");
        new SandboxDecisionMetricReportWriter(objectMapper, tempDirectory)
                .write(SandboxDecisionMetric.CDC, List.of(runResult));

        assertThat(tempDirectory.resolve("CDC").resolve("CDC-summary.json")).exists();
        assertThat(tempDirectory.resolve("CDC").resolve("CDC-summary.html")).exists();
        assertThat(tempDirectory.resolve("CDC").resolve("CDC-calibration.json")).exists();
        assertThat(tempDirectory.resolve("CDC").resolve("CDC-calibration.html")).exists();
        assertThat(tempDirectory.resolve("CDC").resolve("CDC-runs.ndjson")).exists();
        assertThat(tempDirectory.resolve("CDC").resolve("CDC-rounds.ndjson")).exists();
        assertThat(tempDirectory.resolve("CDC").resolve("CDC-defects.ndjson")).exists();
        assertThat(tempDirectory.resolve("CDC").resolve("CDC-adjudication.ndjson")).exists();
        assertThat(tempDirectory.resolve("CDC").resolve("CDC-reviewer-agreement.ndjson")).exists();
        assertThat(tempDirectory.resolve("decision-index.html")).exists();
    }

    @Test
    @DisplayName("CDC는 action과 confidence만 맞아도 통과하면 안 되고 contradicted reasoning과 uncertainty 실패를 함께 감점해야 한다")
    void cdcShouldPenalizeContradictedReasoningAndMissingUncertainty() {
        SandboxPromptReplayScenario scenario = SandboxPromptReplayScenarioCatalog
                .resizeScenario(SandboxPromptReplayScenarioCatalog.ADMIN_SPARSE_HISTORY_THEN_HIGH_VALUE_REENTRY, 3);
        SandboxPromptReplayRun replayRun = new SandboxPromptReplayRun(
                "decision-run-004",
                "decision-user@example.com",
                scenario.scenarioKey(),
                scenario.experimentGroup(),
                scenario,
                List.of(
                        round(scenario, 1, "CHALLENGE", 0.45d, "New user, new device, new session, and lack of role-scope evidence."),
                        round(scenario, 2, "CHALLENGE", 0.75d, "New user lacks established baseline and historical context for sensitive access."),
                        round(scenario, 3, "CHALLENGE", 0.75d, "New user lacks established baseline and historical context for sensitive access.")));

        SandboxDecisionBenchmarkRunResult runResult = SandboxDecisionMetricExtractor.evaluateRun(objectMapper, replayRun);

        assertThat(runResult.roundResults().get(0).cdcScore()).isEqualTo(100.0d);
        assertThat(runResult.roundResults().get(1).cdcScore()).isLessThan(95.0d);
        assertThat(runResult.roundResults().get(2).cdcScore()).isLessThan(95.0d);
        assertThat(runResult.roundResults().get(1).safeUncertaintyPass()).isFalse();
        assertThat(runResult.roundResults().get(1).adjudication().contradictedClaimRate()).isEqualTo(100.0d);
        assertThat(runResult.metrics().get("CDC")).isLessThan(95.0d);
    }

    @Test
    @DisplayName("같은 replay run을 두 번 평가하면 CDC ERA SUHR와 round metric이 동일해야 한다")
    void metricExtractorShouldBeDeterministicForSameReplayRun() {
        SandboxPromptReplayScenario scenario = SandboxPromptReplayScenarioCatalog
                .resizeScenario(SandboxPromptReplayScenarioCatalog.ADMIN_STEADY_BASELINE_THEN_CONFLICTING_CONTEXT, 3);
        SandboxPromptReplayRun replayRun = new SandboxPromptReplayRun(
                "decision-run-002",
                "decision-user@example.com",
                scenario.scenarioKey(),
                scenario.experimentGroup(),
                scenario,
                List.of(
                        round(scenario, 1, "ALLOW", 0.61d, "Baseline and previous path align with the current session."),
                        round(scenario, 2, "CHALLENGE", 0.59d, "Previous path and session context diverge from the established baseline with limited scope evidence."),
                        round(scenario, 3, "ALLOW", 0.64d, "Previous path and session history align with the restored baseline.")));

        SandboxDecisionBenchmarkRunResult first = SandboxDecisionMetricExtractor.evaluateRun(objectMapper, replayRun);
        SandboxDecisionBenchmarkRunResult second = SandboxDecisionMetricExtractor.evaluateRun(objectMapper, replayRun);

        assertThat(first.metrics()).isEqualTo(second.metrics());
        assertThat(first.roundResults())
                .extracting(SandboxDecisionRoundResult::cdcScore, SandboxDecisionRoundResult::eraScore, SandboxDecisionRoundResult::suhrScore)
                .containsExactlyElementsOf(second.roundResults().stream()
                        .map(round -> org.assertj.core.groups.Tuple.tuple(round.cdcScore(), round.eraScore(), round.suhrScore()))
                        .toList());
    }

    @Test
    @DisplayName("실패 round는 defects와 reviewer-agreement에 누락 없이 남아야 한다")
    void reportWriterShouldIncludeDefectiveRoundsWithoutFiltering() throws Exception {
        SandboxPromptReplayScenario scenario = SandboxPromptReplayScenarioCatalog
                .resizeScenario(SandboxPromptReplayScenarioCatalog.ADMIN_MIXED_SCOPE_THEN_APPROVAL_AMBIGUITY, 3);
        SandboxPromptReplayRun replayRun = new SandboxPromptReplayRun(
                "decision-run-003",
                "decision-user@example.com",
                scenario.scenarioKey(),
                scenario.experimentGroup(),
                scenario,
                List.of(
                        round(scenario, 1, "ALLOW", 0.62d, "High sensitivity access with provisional baseline evidence and limited history."),
                        round(scenario, 2, "ALLOW", 0.93d, "Guaranteed safe approval exists for this critical scope."),
                        round(scenario, 3, "ALLOW", 0.60d, "Previous path and session history align with the restored baseline.")));

        SandboxDecisionBenchmarkRunResult runResult = SandboxDecisionMetricExtractor.evaluateRun(objectMapper, replayRun);

        Path tempDirectory = Files.createTempDirectory("sandbox-decision-defects");
        new SandboxDecisionMetricReportWriter(objectMapper, tempDirectory)
                .write(SandboxDecisionMetric.SUHR, List.of(runResult));

        String defects = Files.readString(tempDirectory.resolve("SUHR").resolve("SUHR-defects.ndjson"));
        String reviewerAgreement = Files.readString(tempDirectory.resolve("SUHR").resolve("SUHR-reviewer-agreement.ndjson"));

        assertThat(defects).contains("decision-run-003");
        assertThat(defects).contains("\"metricKey\":\"SUHR\"");
        assertThat(reviewerAgreement).contains("REVIEW_REQUIRED");
        assertThat(reviewerAgreement).contains("manualReviewRequired");
    }

    private SandboxPromptReplayRound round(
            SandboxPromptReplayScenario scenario,
            int roundNumber,
            String action,
            double confidence,
            String reasoning) {
        SandboxPromptRoundPlan roundPlan = scenario.roundPlanForRound(roundNumber);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-" + roundPlan.roundKey())
                .timestamp(LocalDateTime.of(2026, 3, 31, 10, roundNumber))
                .userId("decision-user")
                .sessionId("session-001")
                .sourceIp(roundPlan.clientIp())
                .description("AUTHORIZATION_METHOD")
                .build();
        event.addMetadata("requestId", "request-" + roundPlan.roundKey());
        event.addMetadata("correlationId", "request-" + roundPlan.roundKey());
        event.addMetadata("isNewUser", roundNumber == 1);
        event.addMetadata("isNewSession", roundNumber == 1);
        event.addMetadata("isNewDevice", roundNumber == 1);
        event.addMetadata("mfaVerified", true);
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("authorizationEffect", "ALLOW");
        event.addMetadata("requestPath", roundPlan.requestPath());

        String userPrompt = String.join("\n",
                "=== CURRENT REQUEST AND EVENT ===",
                "RequestPath: " + roundPlan.requestPath(),
                "ClientIp: " + roundPlan.clientIp(),
                "MfaVerified: true",
                "Sensitivity: HIGH",
                "=== SESSION NARRATIVE CONTEXT ===",
                "PreviousPath: /admin/api/security-test/sensitive/resource-000",
                "=== PERSONAL WORK PROFILE ===",
                "WorkProfileEvidenceState: PROVISIONAL",
                "WorkProfileSummary: Window 7d | Observations 24",
                "=== ROLE SCOPE ===",
                "ScopeSummary: provisional scope evidence");

        SandboxPromptTraceSnapshot promptSnapshot = new SandboxPromptTraceSnapshot(
                "request-" + roundPlan.roundKey(),
                Instant.now(),
                event,
                null,
                null,
                List.of(),
                null,
                "system prompt",
                userPrompt,
                Map.of(
                        "promptVersion", "2026.03.31",
                        "promptHash", "sha256:test-" + roundPlan.roundKey(),
                        "systemPromptHash", "sha256:system",
                        "userPromptHash", "sha256:user",
                        "promptSectionSet", List.of("CURRENT_REQUEST_AND_EVENT", "SESSION_NARRATIVE_CONTEXT", "PERSONAL_WORK_PROFILE")),
                null);

        SandboxDecisionTraceSnapshot decisionSnapshot = new SandboxDecisionTraceSnapshot(
                "request-" + roundPlan.roundKey(),
                Instant.now(),
                "STABLE_MOCK",
                "SANDBOX_STABLE",
                "io.contexa.SecurityDecisionResponseLite",
                "io.contexa.SecurityDecisionResponseLite",
                true,
                Map.of("promptHash", "sha256:test-" + roundPlan.roundKey()),
                Map.of("action", action, "confidence", confidence, "reasoning", reasoning, "riskScore", 0.2d, "mitre", "UNKNOWN"),
                Map.of("action", action, "confidence", confidence, "reasoning", reasoning, "riskScore", 0.2d, "mitre", "UNKNOWN"),
                Map.of("action", action, "confidence", confidence, "reasoning", reasoning, "riskScore", 0.2d, "mitre", "UNKNOWN"),
                Map.of("action", action, "confidence", confidence, "reasoning", reasoning, "riskScore", 0.2d, "mitre", "UNKNOWN"),
                "raw system prompt",
                "raw user prompt",
                "system prompt",
                userPrompt,
                Map.of("promptVersion", "2026.03.31"),
                null,
                Map.of("boundaryMode", "STABLE_MOCK", "modelId", "SANDBOX_STABLE"));

        return new SandboxPromptReplayRound(
                roundNumber == 1 ? "INITIAL" : "FOLLOW_UP",
                roundNumber,
                roundPlan,
                "request-" + roundPlan.roundKey(),
                roundPlan.requestPath(),
                roundPlan.clientIp(),
                roundPlan.simulatedUserAgentLabel(),
                "device-" + roundPlan.deviceAlias(),
                Map.of("requestId", "request-" + roundPlan.roundKey()),
                promptSnapshot,
                decisionSnapshot);
    }
}
