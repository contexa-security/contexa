package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxDecisionAggregateReportWriterTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("aggregate decision report writer는 CDC ERA SUHR 통합 제출 산출물을 생성해야 한다")
    void shouldWriteAggregateDecisionSubmissionArtifacts() throws Exception {
        SandboxPromptReplayScenario scenario = SandboxPromptReplayScenarioCatalog
                .resizeScenario(SandboxPromptReplayScenarioCatalog.ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE, 3);
        SandboxPromptReplayRun replayRun = new SandboxPromptReplayRun(
                "decision-suite-run-001",
                "decision-suite-user@example.com",
                scenario.scenarioKey(),
                scenario.experimentGroup(),
                scenario,
                List.of(
                        round(scenario, 1, "ALLOW", 0.62d, "High sensitivity access with provisional baseline evidence and limited history."),
                        round(scenario, 2, "ESCALATE", 0.71d, "High sensitivity surge with limited baseline and previous path deviation."),
                        round(scenario, 3, "CHALLENGE", 0.68d, "High sensitivity surge with provisional baseline, previous path mismatch and limited history.")));

        SandboxDecisionBenchmarkRunResult runResult = SandboxDecisionMetricExtractor.evaluateRun(objectMapper, replayRun);
        SandboxDecisionMetricReportWriter metricReportWriter = new SandboxDecisionMetricReportWriter(objectMapper, tempDir);
        metricReportWriter.writeAll(List.of(runResult));
        new SandboxDecisionAggregateReportWriter(objectMapper, tempDir).write(List.of(runResult));

        assertThat(tempDir.resolve("decision-summary.json")).exists();
        assertThat(tempDir.resolve("decision-summary.html")).exists();
        assertThat(tempDir.resolve("decision-performance-summary.json")).exists();
        assertThat(tempDir.resolve("decision-performance-summary.html")).exists();
        assertThat(tempDir.resolve("decision-metrics.ndjson")).exists();
        assertThat(tempDir.resolve("decision-runs.ndjson")).exists();
        assertThat(tempDir.resolve("decision-rounds.ndjson")).exists();
        assertThat(tempDir.resolve("decision-defects.ndjson")).exists();
        assertThat(tempDir.resolve("decision-performance-rounds.ndjson")).exists();

        String summaryJson = Files.readString(tempDir.resolve("decision-summary.json"));
        String summaryHtml = Files.readString(tempDir.resolve("decision-summary.html"));
        String performanceSummaryJson = Files.readString(tempDir.resolve("decision-performance-summary.json"));

        assertThat(summaryJson)
                .contains("Context-to-Decision Calibration")
                .contains("Evidence-Reason Alignment")
                .contains("Safe-Uncertainty Handling Rate")
                .contains("\"runCount\"")
                .contains("\"roundCount\"")
                .contains("decision-performance-summary.json");
        assertThat(performanceSummaryJson)
                .contains("\"promptPrefillLatencyMs\"")
                .contains("\"promptEndToEndLatencyMs\"")
                .contains("\"estimatedVendorCostSavings\"");
        assertThat(summaryHtml)
                .contains("CDC/CDC-summary.html")
                .contains("ERA/ERA-summary.html")
                .contains("SUHR/SUHR-summary.html")
                .contains("decision-performance-summary.html")
                .contains("decision-index.html");
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
                Map.of(
                        "boundaryMode", "STABLE_MOCK",
                        "modelId", "SANDBOX_STABLE",
                        "llmStartedAtEpochMs", 1711940400000L,
                        "llmFirstResponseAtEpochMs", 1711940400125L,
                        "llmCompletedAtEpochMs", 1711940400480L,
                        "llmLatencyMs", 480.0d,
                        "estimatedOutputTokens", 28,
                        "tokensPerSecond", 58.333d));

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
