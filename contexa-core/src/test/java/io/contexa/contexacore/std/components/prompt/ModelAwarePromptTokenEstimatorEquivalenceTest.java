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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Locale;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The estimate is computed once for each part of the prompt and not again for the two together, and a character that is
 * plain ASCII is weighed without looking up its script. The numbers must be the ones the plain way of counting gives:
 * this test keeps that way, a character at a time over the whole text, and compares.
 */
class ModelAwarePromptTokenEstimatorEquivalenceTest {

    private static final String[] HINTS = {null, "", "claude-haiku-5-5", "gpt-5", "gemini-2", "qwen3:8b", "llama3", "other-model"};
    private static final String[] ALPHABETS = {
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789",
            " \t\n\r  ",
            "{}[]:=,.;-_/\\\"'",
            "한글로쓴문장입니다사용자세션판정",
            "日本語漢字中文用户会话",
            "ひらがなカタカナ",
            "ÀÉÎÕÜßçñ",
            "😀🔒🌍",
            "\uD83D",
            "\uDE00",
            "  　"
    };

    /** The counting the estimator did before: every character of the whole text, three times over. */
    private static int reference(String text, String modelHint) {
        if (text == null || text.isBlank()) {
            return 0;
        }
        double weighted = 0.0d;
        int codePointCount = text.codePointCount(0, text.length());
        for (int offset = 0; offset < text.length(); ) {
            int codePoint = text.codePointAt(offset);
            weighted += weight(codePoint);
            offset += Character.charCount(codePoint);
        }
        double charactersPerToken = charactersPerToken(modelHint);
        int estimated = (int) Math.ceil(weighted / charactersPerToken);
        return Math.max(1, Math.max(estimated, (int) Math.ceil(codePointCount / 8.0d)));
    }

    private static double charactersPerToken(String modelHint) {
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

    private static double weight(int codePoint) {
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

    private static String random(Random random, int length) {
        StringBuilder text = new StringBuilder();
        String alphabet = ALPHABETS[random.nextInt(ALPHABETS.length)];
        for (int i = 0; i < length; i++) {
            if (random.nextInt(12) == 0) {
                alphabet = ALPHABETS[random.nextInt(ALPHABETS.length)];
            }
            int[] points = alphabet.codePoints().toArray();
            text.appendCodePoint(points[random.nextInt(points.length)]);
        }
        return text.toString();
    }

    @Test
    @DisplayName("the estimate of each part and of both together is the one the plain count gives, for texts of every script")
    void theEstimateIsTheOneThePlainCountGives() {
        ModelAwarePromptTokenEstimator estimator = new ModelAwarePromptTokenEstimator();
        Random random = new Random(20261108L);
        for (int round = 0; round < 3_000; round++) {
            String system = round % 17 == 0 ? (round % 34 == 0 ? null : "  \n ") : random(random, random.nextInt(400));
            String user = round % 23 == 0 ? "" : random(random, random.nextInt(900));
            String hint = HINTS[random.nextInt(HINTS.length)];

            PromptTokenEstimate estimate = estimator.estimate(hint, system, user, null);

            String systemText = system == null ? "" : system;
            String userText = user == null ? "" : user;
            assertThat(estimate.estimatedSystemTokens()).as("system, round %d", round).isEqualTo(reference(systemText, hint));
            assertThat(estimate.estimatedUserTokens()).as("user, round %d", round).isEqualTo(reference(userText, hint));
            assertThat(estimate.estimatedTotalTokens()).as("total, round %d", round)
                    .isEqualTo(reference(systemText + "\n---\n" + userText, hint));
        }
    }

    @Test
    @DisplayName("a part that is blank counts nothing by itself and its characters still count in the total")
    void aBlankPartCountsInTheTotal() {
        ModelAwarePromptTokenEstimator estimator = new ModelAwarePromptTokenEstimator();

        PromptTokenEstimate estimate = estimator.estimate("claude", "          ", "abc", null);

        assertThat(estimate.estimatedSystemTokens()).isZero();
        assertThat(estimate.estimatedTotalTokens()).isEqualTo(reference("          " + "\n---\n" + "abc", "claude"));
    }

    @Test
    @DisplayName("long prompts of the size an analysis sends give the same numbers")
    void longPromptsGiveTheSameNumbers() {
        ModelAwarePromptTokenEstimator estimator = new ModelAwarePromptTokenEstimator();
        Random random = new Random(7L);
        String system = random(random, 6_000);
        String user = random(random, 30_000);

        PromptTokenEstimate estimate = estimator.estimate("qwen3:8b", system, user, null);

        assertThat(estimate.estimatedSystemTokens()).isEqualTo(reference(system, "qwen3:8b"));
        assertThat(estimate.estimatedUserTokens()).isEqualTo(reference(user, "qwen3:8b"));
        assertThat(estimate.estimatedTotalTokens()).isEqualTo(reference(system + "\n---\n" + user, "qwen3:8b"));
    }
}
