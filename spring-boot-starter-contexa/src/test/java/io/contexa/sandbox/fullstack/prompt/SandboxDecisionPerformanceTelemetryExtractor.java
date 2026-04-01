package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacore.std.components.prompt.PromptCompressionLedger;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptTokenEstimate;

import java.util.Map;

final class SandboxDecisionPerformanceTelemetryExtractor {

    private SandboxDecisionPerformanceTelemetryExtractor() {
    }

    static SandboxDecisionPerformanceTelemetry extract(SandboxDecisionTraceSnapshot decisionSnapshot) {
        if (decisionSnapshot == null) {
            return emptyTelemetry();
        }

        PromptExecutionMetadata metadata = decisionSnapshot.promptExecutionMetadata();
        PromptTokenEstimate tokenEstimate = metadata != null ? metadata.promptTokenEstimate() : null;
        PromptCompressionLedger compressionLedger = metadata != null ? metadata.promptCompressionLedger() : null;

        int estimatedLlmInputTokens = tokenEstimate != null ? tokenEstimate.estimatedTotalTokens() : 0;
        int estimatedRawInputTokens = estimatedLlmInputTokens + (compressionLedger != null ? compressionLedger.savedEstimatedTokens() : 0);
        int estimatedOutputTokens = estimateTokens(stringValue(decisionSnapshot.llmRawResponse()));

        Map<String, Object> pipelineMetadata = decisionSnapshot.pipelineMetadata();
        long promptStartAtEpochMs = longValue(pipelineMetadata.get("llmStartedAtEpochMs"));
        long firstResponseAtEpochMs = longValue(pipelineMetadata.get("llmFirstResponseAtEpochMs"));
        long completedAtEpochMs = longValue(pipelineMetadata.get("llmCompletedAtEpochMs"));
        boolean prefillMeasured = promptStartAtEpochMs > 0L
                && firstResponseAtEpochMs > 0L
                && firstResponseAtEpochMs >= promptStartAtEpochMs;
        int llmInvocationCount = intValue(pipelineMetadata.get("llmInvocationCount"));
        boolean structuredAttempted = booleanValue(pipelineMetadata.get("structuredAttempted"));
        boolean structuredSucceeded = booleanValue(pipelineMetadata.get("structuredSucceeded"));
        boolean repairAttempted = booleanValue(pipelineMetadata.get("repairAttempted"));
        boolean repairSucceeded = booleanValue(pipelineMetadata.get("repairSucceeded"));

        double promptPrefillLatencyMs = prefillMeasured
                ? durationValue(promptStartAtEpochMs, firstResponseAtEpochMs)
                : 0.0d;
        double promptEndToEndLatencyMs = durationValue(promptStartAtEpochMs, completedAtEpochMs);
        if (promptEndToEndLatencyMs <= 0.0d) {
            promptEndToEndLatencyMs = numericValue(pipelineMetadata.get("llmLatencyMs"));
        }
        if (completedAtEpochMs <= 0L && promptStartAtEpochMs > 0L && promptEndToEndLatencyMs > 0.0d) {
            completedAtEpochMs = promptStartAtEpochMs + Math.round(promptEndToEndLatencyMs);
        }

        double tokensPerSecond = promptEndToEndLatencyMs > 0.0d
                ? round((estimatedOutputTokens * 1000.0d) / promptEndToEndLatencyMs)
                : 0.0d;

        SandboxDecisionCostEstimate costEstimate = estimateCosts(
                estimatedRawInputTokens,
                estimatedLlmInputTokens,
                estimatedOutputTokens,
                promptEndToEndLatencyMs);

        return new SandboxDecisionPerformanceTelemetry(
                promptStartAtEpochMs,
                firstResponseAtEpochMs,
                completedAtEpochMs,
                round(promptPrefillLatencyMs),
                round(promptEndToEndLatencyMs),
                estimatedRawInputTokens,
                estimatedLlmInputTokens,
                estimatedOutputTokens,
                tokensPerSecond,
                prefillMeasured,
                Math.max(1, llmInvocationCount),
                structuredAttempted,
                structuredSucceeded,
                repairAttempted,
                repairSucceeded,
                costEstimate);
    }

    private static SandboxDecisionPerformanceTelemetry emptyTelemetry() {
        SandboxDecisionCostEstimate costEstimate = estimateCosts(0, 0, 0, 0.0d);
        return new SandboxDecisionPerformanceTelemetry(
                0L,
                0L,
                0L,
                0.0d,
                0.0d,
                0,
                0,
                0,
                0.0d,
                false,
                0,
                false,
                false,
                false,
                false,
                costEstimate);
    }

    private static SandboxDecisionCostEstimate estimateCosts(
            int estimatedRawInputTokens,
            int estimatedLlmInputTokens,
            int estimatedOutputTokens,
            double promptEndToEndLatencyMs) {
        SandboxDecisionCostProfile costProfile = SandboxDecisionCostCatalog.resolve();
        double estimatedVendorCostRaw = roundCost(costOf(costProfile, estimatedRawInputTokens, estimatedOutputTokens));
        double estimatedVendorCostLlm = roundCost(costOf(costProfile, estimatedLlmInputTokens, estimatedOutputTokens));
        double estimatedInfrastructureCostLlm = roundCost(infrastructureCostOf(costProfile, promptEndToEndLatencyMs));
        double scale = estimatedLlmInputTokens > 0
                ? Math.max(1.0d, estimatedRawInputTokens / (double) estimatedLlmInputTokens)
                : 1.0d;
        double estimatedInfrastructureCostRaw = roundCost(estimatedInfrastructureCostLlm * scale);
        return new SandboxDecisionCostEstimate(
                costProfile,
                estimatedRawInputTokens,
                estimatedLlmInputTokens,
                estimatedOutputTokens,
                estimatedVendorCostRaw,
                estimatedVendorCostLlm,
                roundCost(estimatedVendorCostRaw - estimatedVendorCostLlm),
                estimatedInfrastructureCostRaw,
                estimatedInfrastructureCostLlm,
                roundCost(estimatedInfrastructureCostRaw - estimatedInfrastructureCostLlm));
    }

    private static double costOf(SandboxDecisionCostProfile costProfile, int inputTokens, int outputTokens) {
        if (costProfile == null) {
            return 0.0d;
        }
        return ((inputTokens / 1000.0d) * costProfile.inputCostPer1kTokens())
                + ((outputTokens / 1000.0d) * costProfile.outputCostPer1kTokens());
    }

    private static double infrastructureCostOf(SandboxDecisionCostProfile costProfile, double promptEndToEndLatencyMs) {
        if (costProfile == null || costProfile.infrastructureCostPerHour() <= 0.0d || promptEndToEndLatencyMs <= 0.0d) {
            return 0.0d;
        }
        return costProfile.infrastructureCostPerHour() * (promptEndToEndLatencyMs / 3_600_000.0d);
    }

    private static long longValue(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Long.parseLong(text.trim());
            } catch (NumberFormatException ignored) {
                return 0L;
            }
        }
        return 0L;
    }

    private static int intValue(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Integer.parseInt(text.trim());
            } catch (NumberFormatException ignored) {
                return 0;
            }
        }
        return 0;
    }

    private static double numericValue(Object value) {
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Double.parseDouble(text.trim());
            } catch (NumberFormatException ignored) {
                return 0.0d;
            }
        }
        return 0.0d;
    }

    private static double durationValue(long startedAt, long completedAt) {
        if (startedAt <= 0L || completedAt <= 0L || completedAt < startedAt) {
            return 0.0d;
        }
        return completedAt - startedAt;
    }

    private static int estimateTokens(String text) {
        if (text == null || text.isBlank()) {
            return 0;
        }
        return Math.max(1, (int) Math.ceil(text.length() / 4.0d));
    }

    private static String stringValue(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private static boolean booleanValue(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof String text && !text.isBlank()) {
            return Boolean.parseBoolean(text.trim());
        }
        return false;
    }

    private static double round(double value) {
        return Math.round(value * 1000.0d) / 1000.0d;
    }

    private static double roundCost(double value) {
        return Math.round(value * 1_000_000.0d) / 1_000_000.0d;
    }
}
