package io.contexa.sandbox.fullstack.prompt;

public record SandboxDecisionPerformanceTelemetry(
        long promptStartAtEpochMs,
        long firstResponseAtEpochMs,
        long completedAtEpochMs,
        double promptPrefillLatencyMs,
        double promptEndToEndLatencyMs,
        int estimatedRawInputTokens,
        int estimatedLlmInputTokens,
        int estimatedOutputTokens,
        double tokensPerSecond,
        SandboxDecisionCostEstimate costEstimate) {
}
