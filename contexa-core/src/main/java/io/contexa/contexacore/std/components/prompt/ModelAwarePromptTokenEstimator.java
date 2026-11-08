/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.std.components.prompt;

import java.util.Locale;

/**
 * Model-aware fallback estimator used when provider token usage has not yet been observed.
 * It stays vendor-neutral while avoiding the previous fixed char/4 heuristic as the active path.
 */
public final class ModelAwarePromptTokenEstimator implements PromptTokenEstimator {

    public static final String ESTIMATOR_KEY = "MODEL_AWARE_TOKEN_COUNTING_V1";
    static final String ENFORCEMENT_MODE = "OBSERVE_ONLY";
    private static final String SEPARATOR = "\n---\n";
    private static final int SEPARATOR_CODE_POINTS = SEPARATOR.codePointCount(0, SEPARATOR.length());

    @Override
    public PromptTokenEstimate estimate(
            String modelHint,
            String systemPrompt,
            String userPrompt,
            PromptBudgetProfile budgetProfile) {
        String normalizedSystemPrompt = normalize(systemPrompt);
        String normalizedUserPrompt = normalize(userPrompt);
        double charactersPerToken = resolveCharactersPerToken(modelHint);
        double systemWeight = weigh(normalizedSystemPrompt, 0.0d);
        double userWeight = weigh(normalizedUserPrompt, 0.0d);
        int systemCodePoints = normalizedSystemPrompt.codePointCount(0, normalizedSystemPrompt.length());
        int userCodePoints = normalizedUserPrompt.codePointCount(0, normalizedUserPrompt.length());
        int estimatedSystemTokens = estimateTextTokens(normalizedSystemPrompt, systemWeight, systemCodePoints, charactersPerToken);
        int estimatedUserTokens = estimateTextTokens(normalizedUserPrompt, userWeight, userCodePoints, charactersPerToken);
        // Both together are counted as one text would be, the sum carried on from the system prompt through the
        // separator into the user prompt: the order of the additions is the one a count over the joined text makes, and
        // a weight that lands on a whole number of tokens is rounded the same way.
        double totalWeight = weigh(normalizedUserPrompt, weigh(SEPARATOR, systemWeight));
        int estimatedTotalTokens = tokens(totalWeight, systemCodePoints + SEPARATOR_CODE_POINTS + userCodePoints, charactersPerToken);
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

    private int estimateTextTokens(String text, double weight, int codePointCount, double charactersPerToken) {
        if (text == null || text.isBlank()) {
            return 0;
        }
        return tokens(weight, codePointCount, charactersPerToken);
    }

    private static int tokens(double weight, int codePointCount, double charactersPerToken) {
        int estimated = (int) Math.ceil(weight / charactersPerToken);
        return Math.max(1, Math.max(estimated, (int) Math.ceil(codePointCount / 8.0d)));
    }

    /** The weights of the characters of the text added one after the other to the sum so far. */
    private static double weigh(String text, double sum) {
        for (int offset = 0; offset < text.length(); ) {
            int codePoint = text.codePointAt(offset);
            sum += codePointWeight(codePoint);
            offset += Character.charCount(codePoint);
        }
        return sum;
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

    private static double codePointWeight(int codePoint) {
        if (Character.isWhitespace(codePoint)) {
            return 0.35d;
        }
        if (Character.isDigit(codePoint)) {
            return 0.80d;
        }
        // A character of ASCII is of no script that weighs more, and the script is looked up once for the others.
        if (codePoint >= 0x80) {
            Character.UnicodeScript script = Character.UnicodeScript.of(codePoint);
            if (script == Character.UnicodeScript.HANGUL
                    || script == Character.UnicodeScript.HAN
                    || script == Character.UnicodeScript.HIRAGANA
                    || script == Character.UnicodeScript.KATAKANA) {
                return 1.30d;
            }
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
