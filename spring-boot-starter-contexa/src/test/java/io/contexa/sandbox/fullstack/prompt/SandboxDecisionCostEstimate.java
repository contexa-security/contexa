package io.contexa.sandbox.fullstack.prompt;

public record SandboxDecisionCostEstimate(
        SandboxDecisionCostProfile costProfile,
        int estimatedRawInputTokens,
        int estimatedLlmInputTokens,
        int estimatedOutputTokens,
        double estimatedVendorCostRaw,
        double estimatedVendorCostLlm,
        double estimatedVendorCostSavings) {
}
