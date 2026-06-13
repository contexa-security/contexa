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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stores provider-observed prompt token usage so prompt estimation can converge toward
 * model-specific real usage without coupling the engine core to a single tokenizer library.
 */
public final class ObservedPromptTokenUsageRegistry {

    private static final int MAX_EFFECTIVE_SAMPLES = 64;
    private static final Map<String, CalibrationEntry> CALIBRATIONS = new ConcurrentHashMap<>();

    private ObservedPromptTokenUsageRegistry() {
    }

    public static void recordObservation(String modelHint, int promptCharacters, int promptTokens) {
        String normalizedModelHint = normalizeModelHint(modelHint);
        if (normalizedModelHint == null || promptCharacters <= 0 || promptTokens <= 0) {
            return;
        }
        double observedCharactersPerToken = promptCharacters / (double) promptTokens;
        if (!Double.isFinite(observedCharactersPerToken) || observedCharactersPerToken <= 0.0d) {
            return;
        }
        CALIBRATIONS.compute(normalizedModelHint, (key, existing) ->
                existing == null
                        ? CalibrationEntry.initial(observedCharactersPerToken)
                        : existing.update(observedCharactersPerToken));
    }

    public static boolean hasCalibration(String modelHint) {
        return find(modelHint) != null;
    }

    public static CalibrationSnapshot find(String modelHint) {
        String normalizedModelHint = normalizeModelHint(modelHint);
        if (normalizedModelHint == null) {
            return null;
        }
        CalibrationEntry entry = CALIBRATIONS.get(normalizedModelHint);
        if (entry == null) {
            return null;
        }
        return new CalibrationSnapshot(
                normalizedModelHint,
                entry.charactersPerToken(),
                entry.sampleCount());
    }

    public static void clear() {
        CALIBRATIONS.clear();
    }

    static String normalizeModelHint(String modelHint) {
        if (modelHint == null) {
            return null;
        }
        String normalized = modelHint.trim().toLowerCase(Locale.ROOT);
        return normalized.isEmpty() ? null : normalized;
    }

    public record CalibrationSnapshot(
            String modelKey,
            double charactersPerToken,
            int sampleCount) {
    }

    private record CalibrationEntry(
            double charactersPerToken,
            int sampleCount) {

        static CalibrationEntry initial(double observedCharactersPerToken) {
            return new CalibrationEntry(observedCharactersPerToken, 1);
        }

        CalibrationEntry update(double observedCharactersPerToken) {
            int currentEffectiveSamples = Math.max(1, Math.min(sampleCount, MAX_EFFECTIVE_SAMPLES));
            double weightedAverage =
                    ((charactersPerToken * currentEffectiveSamples) + observedCharactersPerToken)
                            / (currentEffectiveSamples + 1.0d);
            return new CalibrationEntry(weightedAverage, sampleCount + 1);
        }
    }
}
