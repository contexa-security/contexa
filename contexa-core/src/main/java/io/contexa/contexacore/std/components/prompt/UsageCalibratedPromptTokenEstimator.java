package io.contexa.contexacore.std.components.prompt;

public final class UsageCalibratedPromptTokenEstimator implements PromptTokenEstimator {

    static final String ESTIMATOR_KEY = ModelAwarePromptTokenEstimator.ESTIMATOR_KEY;
    static final String ENFORCEMENT_MODE = "OBSERVE_ONLY";

    @Override
    public PromptTokenEstimate estimate(
            String modelHint,
            String systemPrompt,
            String userPrompt,
            PromptBudgetProfile budgetProfile) {
        ObservedPromptTokenUsageRegistry.CalibrationSnapshot calibration =
                ObservedPromptTokenUsageRegistry.find(modelHint);
        if (calibration == null) {
            return new ModelAwarePromptTokenEstimator().estimate(modelHint, systemPrompt, userPrompt, budgetProfile);
        }

        String normalizedSystemPrompt = normalize(systemPrompt);
        String normalizedUserPrompt = normalize(userPrompt);
        int systemCharacters = normalizedSystemPrompt.length();
        int userCharacters = normalizedUserPrompt.length();
        int totalCharacters = systemCharacters + userCharacters + 5;

        int estimatedTotalTokens = estimateTokens(totalCharacters, calibration.charactersPerToken());
        int estimatedSystemTokens = totalCharacters <= 0
                ? 0
                : Math.max(0, (int) Math.round(estimatedTotalTokens * (systemCharacters / (double) totalCharacters)));
        int estimatedUserTokens = Math.max(0, estimatedTotalTokens - estimatedSystemTokens);
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

    @Override
    public boolean supports(String modelHint) {
        return ObservedPromptTokenUsageRegistry.hasCalibration(modelHint);
    }

    private int estimateTokens(int characters, double charactersPerToken) {
        if (characters <= 0 || !Double.isFinite(charactersPerToken) || charactersPerToken <= 0.0d) {
            return 0;
        }
        return Math.max(1, (int) Math.ceil(characters / charactersPerToken));
    }

    private String normalize(String value) {
        return value != null ? value : "";
    }
}
