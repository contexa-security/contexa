package io.contexa.contexacore.std.components.prompt;

import java.util.Locale;

/**
 * Model-aware fallback estimator used when provider token usage has not yet been observed.
 * It stays vendor-neutral while avoiding the previous fixed char/4 heuristic as the active path.
 */
public final class ModelAwarePromptTokenEstimator implements PromptTokenEstimator {

    public static final String ESTIMATOR_KEY = "MODEL_AWARE_TOKEN_COUNTING_V1";
    static final String ENFORCEMENT_MODE = "OBSERVE_ONLY";

    @Override
    public PromptTokenEstimate estimate(
            String modelHint,
            String systemPrompt,
            String userPrompt,
            PromptBudgetProfile budgetProfile) {
        String normalizedSystemPrompt = normalize(systemPrompt);
        String normalizedUserPrompt = normalize(userPrompt);
        int estimatedSystemTokens = estimateTextTokens(normalizedSystemPrompt, modelHint);
        int estimatedUserTokens = estimateTextTokens(normalizedUserPrompt, modelHint);
        int estimatedTotalTokens = estimateTextTokens(normalizedSystemPrompt + "\n---\n" + normalizedUserPrompt, modelHint);
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
        return true;
    }

    private int estimateTextTokens(String text, String modelHint) {
        if (text == null || text.isBlank()) {
            return 0;
        }
        double weightedCharacterCount = 0.0d;
        int codePointCount = text.codePointCount(0, text.length());
        for (int offset = 0; offset < text.length(); ) {
            int codePoint = text.codePointAt(offset);
            weightedCharacterCount += codePointWeight(codePoint);
            offset += Character.charCount(codePoint);
        }
        double charactersPerToken = resolveCharactersPerToken(modelHint);
        int estimated = (int) Math.ceil(weightedCharacterCount / charactersPerToken);
        return Math.max(1, Math.max(estimated, (int) Math.ceil(codePointCount / 8.0d)));
    }

    private double resolveCharactersPerToken(String modelHint) {
        String normalized = modelHint == null ? "" : modelHint.trim().toLowerCase(Locale.ROOT);
        if (normalized.contains("gpt-5") || normalized.contains("gpt-4o")) {
            return 3.55d;
        }
        if (normalized.contains("claude")) {
            return 3.65d;
        }
        if (normalized.contains("gemini")) {
            return 3.50d;
        }
        if (normalized.contains("qwen") || normalized.contains("llama") || normalized.contains("mistral")) {
            return 3.35d;
        }
        return 3.45d;
    }

    private double codePointWeight(int codePoint) {
        if (Character.isWhitespace(codePoint)) {
            return 0.35d;
        }
        if (Character.isDigit(codePoint)) {
            return 0.80d;
        }
        if (Character.UnicodeScript.of(codePoint) == Character.UnicodeScript.HANGUL
                || Character.UnicodeScript.of(codePoint) == Character.UnicodeScript.HAN
                || Character.UnicodeScript.of(codePoint) == Character.UnicodeScript.HIRAGANA
                || Character.UnicodeScript.of(codePoint) == Character.UnicodeScript.KATAKANA) {
            return 1.30d;
        }
        if (Character.isUpperCase(codePoint)) {
            return 1.05d;
        }
        return 1.0d;
    }

    private String normalize(String value) {
        return value == null ? "" : value;
    }
}
