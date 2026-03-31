package io.contexa.contexacore.std.components.prompt;

/**
 * Conservative prompt-token estimator used for runtime telemetry.
 *
 * This is not a tokenizer-backed hard limit. It is a stable heuristic so the platform can
 * quantify prompt pressure before introducing any loss-aware compression step.
 */
public final class HeuristicPromptTokenEstimator implements PromptTokenEstimator {

    static final String ESTIMATOR_KEY = "heuristic-char-div4-v1";
    static final String ENFORCEMENT_MODE = "OBSERVE_ONLY";

    @Override
    public PromptTokenEstimate estimate(String systemPrompt, String userPrompt, PromptBudgetProfile budgetProfile) {
        String normalizedSystemPrompt = normalize(systemPrompt);
        String normalizedUserPrompt = normalize(userPrompt);
        int estimatedSystemTokens = estimateTextTokens(normalizedSystemPrompt);
        int estimatedUserTokens = estimateTextTokens(normalizedUserPrompt);
        int estimatedTotalTokens = estimateTextTokens(normalizedSystemPrompt + "\n---\n" + normalizedUserPrompt);
        int maxInputTokens = budgetProfile != null ? budgetProfile.maxInputTokens() : 0;
        int remaining = maxInputTokens - estimatedTotalTokens;
        double utilizationRate = maxInputTokens > 0 ? (estimatedTotalTokens * 1.0d) / maxInputTokens : 0.0d;
        return new PromptTokenEstimate(
                ESTIMATOR_KEY,
                estimatedSystemTokens,
                estimatedUserTokens,
                estimatedTotalTokens,
                remaining,
                utilizationRate,
                maxInputTokens > 0 && estimatedTotalTokens > maxInputTokens,
                ENFORCEMENT_MODE,
                false);
    }

    private int estimateTextTokens(String text) {
        if (text == null || text.isBlank()) {
            return 0;
        }
        int codePointCount = text.codePointCount(0, text.length());
        return Math.max(1, (int) Math.ceil(codePointCount / 4.0d));
    }

    private String normalize(String text) {
        return text == null ? "" : text;
    }
}
