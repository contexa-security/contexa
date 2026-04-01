package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptCompressionAction;
import io.contexa.contexacore.std.components.prompt.PromptCompressionLedger;
import io.contexa.contexacore.std.components.prompt.PromptCompressionRecord;
import io.contexa.contexacore.std.components.prompt.PromptEvidenceCompleteness;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.PromptReleaseStatus;
import io.contexa.contexacore.std.components.prompt.PromptTokenEstimate;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxPromptCompressionImpactReportWriterTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("compression impact report should include latency and cost deltas alongside decision regression status")
    void shouldWriteCompressionImpactWithLatencyAndCostDeltas() throws Exception {
        SandboxPromptCompressionImpactComparison expanded = comparison(
                "CORTEX_L1_EXPANDED",
                3000,
                2600,
                120,
                420.0d,
                780.0d,
                18.0d,
                0.014d,
                0.012d,
                0.002d);
        SandboxPromptCompressionImpactComparison compact = comparison(
                "CORTEX_L1_COMPACT",
                3000,
                2100,
                260,
                260.0d,
                510.0d,
                24.0d,
                0.014d,
                0.010d,
                0.004d);

        new SandboxPromptCompressionImpactReportWriter(objectMapper, tempDir)
                .write("expanded-vs-compact", expanded, compact);

        Path summaryJsonPath = tempDir.resolve("compression-impact-summary.json");
        Path summaryHtmlPath = tempDir.resolve("compression-impact-summary.html");
        Path profilesNdjsonPath = tempDir.resolve("compression-impact-profiles.ndjson");
        Path runsNdjsonPath = tempDir.resolve("compression-impact-runs.ndjson");
        Path roundsNdjsonPath = tempDir.resolve("compression-impact-rounds.ndjson");

        assertThat(summaryJsonPath).exists();
        assertThat(summaryHtmlPath).exists();
        assertThat(profilesNdjsonPath).exists();
        assertThat(runsNdjsonPath).exists();
        assertThat(roundsNdjsonPath).exists();

        String summaryJson = Files.readString(summaryJsonPath);
        String summaryHtml = Files.readString(summaryHtmlPath);

        assertThat(summaryJson)
                .contains("promptPrefillLatencyDelta")
                .contains("promptEndToEndLatencyDelta")
                .contains("estimatedVendorCostLlmDelta")
                .contains("latencyGainPass")
                .contains("costGainPass")
                .contains("\"decisionRegressionPass\" : true")
                .contains("profileReportDirectory");
        assertThat(summaryHtml)
                .contains("Prefill ms")
                .contains("End-to-End ms")
                .contains("Cost Raw")
                .contains("Cost LLM")
                .contains("latencyGainPass=true")
                .contains("costGainPass=true")
                .contains("compression-impact-runs.ndjson")
                .contains("decision-summary.html");
    }

    private SandboxPromptCompressionImpactComparison comparison(
            String budgetProfile,
            int rawTotalLength,
            int llmTotalLength,
            int savedEstimatedTokens,
            double prefillLatencyMs,
            double endToEndLatencyMs,
            double tokensPerSecond,
            double rawCost,
            double llmCost,
            double savings) {
        SandboxPromptReplayScenario scenario = SandboxPromptReplayScenarioCatalog.resizeScenario(
                SandboxPromptReplayScenarioCatalog.ADMIN_SPARSE_HISTORY_THEN_HIGH_VALUE_REENTRY,
                3);
        SandboxPromptReplayRun replayRun = new SandboxPromptReplayRun(
                budgetProfile + "-run",
                "compression-user@example.com",
                scenario.scenarioKey(),
                scenario.experimentGroup(),
                scenario,
                List.of(
                        promptRound(scenario, 1, rawTotalLength, llmTotalLength, savedEstimatedTokens),
                        promptRound(scenario, 2, rawTotalLength, llmTotalLength, savedEstimatedTokens),
                        promptRound(scenario, 3, rawTotalLength, llmTotalLength, savedEstimatedTokens)));

        SandboxPromptBenchmarkRunResult promptRunResult = new SandboxPromptBenchmarkRunResult(
                budgetProfile + "-run",
                "compression-user@example.com",
                replayRun,
                List.of(
                        SandboxPromptQualityScorecard.of("R1", List.of(new SandboxPromptQualityScorecard.CheckResult("ok", true, "ok"))),
                        SandboxPromptQualityScorecard.of("R2", List.of(new SandboxPromptQualityScorecard.CheckResult("ok", true, "ok"))),
                        SandboxPromptQualityScorecard.of("R3", List.of(new SandboxPromptQualityScorecard.CheckResult("ok", true, "ok")))),
                SandboxPromptQualityScorecard.of("progression", List.of(new SandboxPromptQualityScorecard.CheckResult("ok", true, "ok"))),
                List.of(
                        new SandboxPromptTraceContractAssessment("R1", 100.0d, List.of()),
                        new SandboxPromptTraceContractAssessment("R2", 100.0d, List.of()),
                        new SandboxPromptTraceContractAssessment("R3", 100.0d, List.of())),
                List.of(
                        new SandboxPromptFidelityAssessment("R1", 100.0d, List.of(), List.of(), List.of(), 0, List.of()),
                        new SandboxPromptFidelityAssessment("R2", 100.0d, List.of(), List.of(), List.of(), 0, List.of()),
                        new SandboxPromptFidelityAssessment("R3", 100.0d, List.of(), List.of(), List.of(), 0, List.of())),
                List.of(
                        new SandboxPromptArtifactIntegrityAssessment(100.0d, List.of()),
                        new SandboxPromptArtifactIntegrityAssessment(100.0d, List.of()),
                        new SandboxPromptArtifactIntegrityAssessment(100.0d, List.of())),
                Map.of("Context Completeness Rate", 100.0d),
                List.of());

        SandboxDecisionPerformanceTelemetry telemetry = new SandboxDecisionPerformanceTelemetry(
                1711950000000L,
                1711950000000L + Math.round(prefillLatencyMs),
                1711950000000L + Math.round(endToEndLatencyMs),
                prefillLatencyMs,
                endToEndLatencyMs,
                Math.max(1, rawTotalLength / 4),
                Math.max(1, llmTotalLength / 4),
                42,
                tokensPerSecond,
                new SandboxDecisionCostEstimate(
                        new SandboxDecisionCostProfile("TEST_VENDOR", "Test vendor pricing", "USD", 0.01d, 0.02d, true),
                        Math.max(1, rawTotalLength / 4),
                        Math.max(1, llmTotalLength / 4),
                        42,
                        rawCost,
                        llmCost,
                        savings));

        SandboxDecisionBenchmarkRunResult decisionRunResult = new SandboxDecisionBenchmarkRunResult(
                budgetProfile + "-decision-run",
                "compression-user@example.com",
                replayRun,
                List.of(
                        decisionRoundResult(replayRun, 1, telemetry),
                        decisionRoundResult(replayRun, 2, telemetry),
                        decisionRoundResult(replayRun, 3, telemetry)),
                Map.of(
                        SandboxDecisionMetric.CDC.key(), 100.0d,
                        SandboxDecisionMetric.ERA.key(), 100.0d,
                        SandboxDecisionMetric.SUHR.key(), 100.0d));

        return new SandboxPromptCompressionImpactComparison(
                budgetProfile,
                "DECISION_AMBIGUITY",
                3,
                List.of(promptRunResult),
                List.of(decisionRunResult));
    }

    private SandboxPromptReplayRound promptRound(
            SandboxPromptReplayScenario scenario,
            int roundNumber,
            int rawTotalLength,
            int llmTotalLength,
            int savedEstimatedTokens) {
        SandboxPromptRoundPlan roundPlan = scenario.roundPlanForRound(roundNumber);
        SandboxPromptTraceSnapshot snapshot = new SandboxPromptTraceSnapshot(
                "request-" + roundNumber,
                Instant.now(),
                null,
                null,
                null,
                List.of(),
                null,
                "raw-system-" + roundNumber,
                "raw-user-" + roundNumber,
                "system-" + roundNumber,
                "user-" + roundNumber,
                new LinkedHashMap<>(Map.of(
                        "promptVersion", "2026.04.01",
                        "promptHash", "sha256:prompt-" + roundNumber,
                        "systemPromptHash", "sha256:system-" + roundNumber,
                        "userPromptHash", "sha256:user-" + roundNumber)),
                promptExecutionMetadata(rawTotalLength, llmTotalLength, savedEstimatedTokens, budgetProfileForKey(rawTotalLength, llmTotalLength)));

        return new SandboxPromptReplayRound(
                roundNumber == 1 ? "INITIAL" : "FOLLOW_UP",
                roundNumber,
                roundPlan,
                "request-" + roundNumber,
                roundPlan.requestPath(),
                roundPlan.clientIp(),
                roundPlan.simulatedUserAgentLabel(),
                "device-" + roundNumber,
                Map.of("demoPhase", roundNumber == 1 ? "INITIAL" : "FOLLOW_UP"),
                snapshot);
    }

    private SandboxDecisionRoundResult decisionRoundResult(
            SandboxPromptReplayRun replayRun,
            int roundNumber,
            SandboxDecisionPerformanceTelemetry telemetry) {
        SandboxPromptReplayRound replayRound = replayRun.round(roundNumber);
        return new SandboxDecisionRoundResult(
                replayRun.benchmarkRunId(),
                replayRun.username(),
                replayRun.scenarioKey(),
                replayRun.scenario().scenarioFamily(),
                roundNumber,
                replayRound.roundPlan().roundKey(),
                "CHALLENGE",
                0.45d,
                "Sparse history supports a cautious challenge.",
                new SandboxDecisionGoldCase(
                        replayRun.scenarioKey(),
                        replayRound.roundPlan().roundKey(),
                        replayRun.scenario().scenarioFamily(),
                        replayRound.roundPlan().behaviorPhase(),
                        replayRound.roundPlan().anomalySignal(),
                        List.of("CHALLENGE"),
                        List.of("ALLOW"),
                        new SandboxDecisionConfidenceBand(0.30d, 0.55d),
                        true,
                        List.of("SPARSE_HISTORY"),
                        List.of(),
                        "2026.04.01"),
                new SandboxDecisionAdjudication(
                        List.of(new SandboxDecisionClaimAssessment(
                                "Sparse history supports a cautious challenge.",
                                SandboxDecisionClaimVerdict.GROUNDED,
                                "Grounded in sparse baseline evidence.")),
                        1,
                        0,
                        0,
                        100.0d,
                        0.0d,
                        0.0d,
                        true,
                        true,
                        "2026.04.01"),
                true,
                true,
                false,
                true,
                100.0d,
                100.0d,
                100.0d,
                telemetry,
                replayRound);
    }

    private PromptExecutionMetadata promptExecutionMetadata(
            int rawTotalLength,
            int llmTotalLength,
            int savedEstimatedTokens,
            PromptBudgetProfile budgetProfile) {
        int rawSystemLength = Math.max(1, rawTotalLength / 3);
        int rawUserLength = Math.max(1, rawTotalLength - rawSystemLength);
        int llmSystemLength = Math.max(1, llmTotalLength / 3);
        int llmUserLength = Math.max(1, llmTotalLength - llmSystemLength);
        return new PromptExecutionMetadata(
                new PromptGovernanceDescriptor(
                        "cortex.security-decision",
                        "SecurityDecisionStandard",
                        "2026.04.01",
                        "1.0",
                        PromptReleaseStatus.PRODUCTION,
                        "contexa",
                        "APPROVAL-001",
                        "BASELINE-001",
                        "2026.03.31",
                        "Compression impact fixture",
                        List.of("qwen3:8b"),
                        "io.contexa.SecurityDecisionPromptTemplate"),
                budgetProfile,
                new PromptTokenEstimate(
                        "heuristic-char-div4-v1",
                        Math.max(1, llmSystemLength / 4),
                        Math.max(1, llmUserLength / 4),
                        Math.max(1, llmTotalLength / 4),
                        Math.max(0, budgetProfile.maxInputTokens() - Math.max(1, llmTotalLength / 4)),
                        0.50d,
                        false,
                        "OBSERVE_ONLY",
                        savedEstimatedTokens > 0),
                new PromptCompressionLedger(
                        "NORMALIZE_AND_COMPACT",
                        savedEstimatedTokens <= 0,
                        rawSystemLength,
                        rawUserLength,
                        llmSystemLength,
                        llmUserLength,
                        Math.max(0, rawTotalLength - llmTotalLength),
                        Math.max(0, savedEstimatedTokens),
                        savedEstimatedTokens > 0
                                ? List.of(new PromptCompressionRecord(
                                "SIMILAR_PAST_EVENTS",
                                PromptCompressionAction.FUSED,
                                rawUserLength,
                                llmUserLength,
                                savedEstimatedTokens,
                                "Fused comparable events for compact view"))
                                : List.of()),
                List.of("CURRENT_REQUEST_AND_EVENT", "SIMILAR_PAST_EVENTS"),
                List.of(),
                List.of(),
                PromptEvidenceCompleteness.SUFFICIENT,
                "sha256:prompt",
                "sha256:system",
                "sha256:user",
                "sha256:raw-prompt",
                "sha256:raw-system",
                "sha256:raw-user",
                llmSystemLength,
                llmUserLength,
                llmTotalLength,
                rawSystemLength,
                rawUserLength,
                rawTotalLength,
                1711950000000L);
    }

    private PromptBudgetProfile budgetProfileForKey(int rawTotalLength, int llmTotalLength) {
        return llmTotalLength < rawTotalLength
                ? PromptBudgetProfile.CORTEX_L1_COMPACT
                : PromptBudgetProfile.CORTEX_L1_EXPANDED;
    }
}
