package io.contexa.sandbox.fullstack.prompt;

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

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxDecisionPerformanceTelemetryExtractorTest {

    @Test
    @DisplayName("performance telemetry extractor should derive latency tokens and reference cost from decision trace")
    void shouldExtractLatencyTokensAndReferenceCostFromDecisionTrace() {
        System.setProperty("sandbox.decision.cost.profile", "TEST_VENDOR");
        System.setProperty("sandbox.decision.cost.currency", "USD");
        System.setProperty("sandbox.decision.cost.input-per-1k", "0.01");
        System.setProperty("sandbox.decision.cost.output-per-1k", "0.02");
        try {
            SandboxDecisionTraceSnapshot snapshot = new SandboxDecisionTraceSnapshot(
                    "request-001",
                    Instant.now(),
                    "REAL_LLM_PROMPT_REPLAY",
                    "qwen3:8b",
                    "io.contexa.SecurityDecisionResponseLite",
                    "io.contexa.SecurityDecisionResponseLite",
                    true,
                    Map.of(),
                    "12345678",
                    Map.of(),
                    Map.of(),
                    Map.of(),
                    "raw system",
                    "raw user",
                    "system",
                    "user",
                    Map.of(),
                    promptExecutionMetadata(),
                    Map.of(
                            "llmStartedAtEpochMs", 1000L,
                            "llmFirstResponseAtEpochMs", 1125L,
                            "llmCompletedAtEpochMs", 1500L,
                            "llmLatencyMs", 500.0d));

            SandboxDecisionPerformanceTelemetry telemetry =
                    SandboxDecisionPerformanceTelemetryExtractor.extract(snapshot);

            assertThat(telemetry.promptPrefillLatencyMs()).isEqualTo(125.0d);
            assertThat(telemetry.promptEndToEndLatencyMs()).isEqualTo(500.0d);
            assertThat(telemetry.estimatedRawInputTokens()).isEqualTo(620);
            assertThat(telemetry.estimatedLlmInputTokens()).isEqualTo(500);
            assertThat(telemetry.estimatedOutputTokens()).isEqualTo(2);
            assertThat(telemetry.tokensPerSecond()).isEqualTo(4.0d);
            assertThat(telemetry.costEstimate().costProfile().profileKey()).isEqualTo("TEST_VENDOR");
            assertThat(telemetry.costEstimate().estimatedVendorCostRaw()).isEqualTo(0.006d);
            assertThat(telemetry.costEstimate().estimatedVendorCostLlm()).isEqualTo(0.005d);
            assertThat(telemetry.costEstimate().estimatedVendorCostSavings()).isEqualTo(0.001d);
        } finally {
            System.clearProperty("sandbox.decision.cost.profile");
            System.clearProperty("sandbox.decision.cost.currency");
            System.clearProperty("sandbox.decision.cost.input-per-1k");
            System.clearProperty("sandbox.decision.cost.output-per-1k");
        }
    }

    private PromptExecutionMetadata promptExecutionMetadata() {
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
                        "Telemetry test descriptor",
                        List.of("qwen3:8b"),
                        "io.contexa.SecurityDecisionPromptTemplate"),
                PromptBudgetProfile.CORTEX_L1_COMPACT,
                new PromptTokenEstimate(
                        "heuristic-char-div4-v1",
                        120,
                        380,
                        500,
                        1050,
                        0.322d,
                        false,
                        "OBSERVE_ONLY",
                        true),
                new PromptCompressionLedger(
                        "NORMALIZE_AND_COMPACT",
                        false,
                        1800,
                        800,
                        1600,
                        520,
                        480,
                        120,
                        List.of(new PromptCompressionRecord(
                                "SIMILAR_PAST_EVENTS",
                                PromptCompressionAction.FUSED,
                                640,
                                220,
                                120,
                                "Fused comparable evidence for compact view"))),
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
                600,
                1400,
                2000,
                700,
                1800,
                2500,
                1711940400000L);
    }
}
