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

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Produces the LLM prompt view without truncating, summarizing, or omitting evidence.
 *
 * <p>The optimizer is intentionally limited to layout normalization, removal of one
 * contradictory stale bridge marker, and elimination of byte-identical repeated
 * sections. A complete copy of every distinct section remains in the final prompt.</p>
 */
public final class SafePromptNormalizationLLMViewComposer implements LLMViewComposer {

    private static final PromptTokenEstimatorRegistry TOKEN_ESTIMATORS =
            PromptTokenEstimatorRegistry.defaultRegistry();
    private static final String IDENTITY_MODE = "IDENTITY";
    private static final String NORMALIZE_ONLY_MODE = "NORMALIZE_ONLY";
    private static final String LOSSLESS_DEDUPLICATION_MODE = "NORMALIZE_AND_DEDUPLICATE";

    @Override
    public PromptViewComposition compose(
            String rawSystemPrompt,
            String rawUserPrompt,
            PromptBudgetProfile budgetProfile) {
        return compose(rawSystemPrompt, rawUserPrompt, budgetProfile, null);
    }

    @Override
    public PromptViewComposition compose(
            String rawSystemPrompt,
            String rawUserPrompt,
            PromptBudgetProfile budgetProfile,
            String modelHint) {
        String normalizedRawSystemPrompt = normalizeLineEndings(rawSystemPrompt);
        String normalizedRawUserPrompt = normalizeLineEndings(rawUserPrompt);
        String llmSystemPrompt = normalizedRawSystemPrompt;
        String normalizedUserPrompt = normalizedRawUserPrompt;

        List<PromptCompressionRecord> records = new ArrayList<>();
        PromptTransformResult authorizationConsistency =
                removeResolvedAuthorizationEffectMissingContext(
                        normalizedUserPrompt,
                        modelHint,
                        budgetProfile);
        records.addAll(authorizationConsistency.records());

        PromptTransformResult sectionDeduplication =
                deduplicateIdenticalSections(
                        authorizationConsistency.text(),
                        modelHint,
                        budgetProfile);
        records.addAll(sectionDeduplication.records());
        String llmUserPrompt = sectionDeduplication.text();

        PromptCompressionLedger ledger = buildLedger(
                normalizedRawSystemPrompt,
                normalizedRawUserPrompt,
                llmSystemPrompt,
                llmUserPrompt,
                records,
                modelHint,
                budgetProfile);
        return new PromptViewComposition(
                normalizedRawSystemPrompt,
                normalizedRawUserPrompt,
                llmSystemPrompt,
                llmUserPrompt,
                ledger);
    }

    private PromptTransformResult deduplicateIdenticalSections(
            String prompt,
            String modelHint,
            PromptBudgetProfile budgetProfile) {
        if (prompt == null || prompt.isBlank()) {
            return new PromptTransformResult("", List.of());
        }

        List<String> lines = List.of(prompt.split("\\n", -1));
        List<String> output = new ArrayList<>(lines.size());
        Set<String> seenSections = new LinkedHashSet<>();
        int removedSections = 0;
        int cursor = 0;
        while (cursor < lines.size()) {
            if (!isSectionHeader(lines.get(cursor))) {
                output.add(lines.get(cursor));
                cursor++;
                continue;
            }

            int sectionStart = cursor;
            cursor++;
            while (cursor < lines.size() && !isSectionHeader(lines.get(cursor))) {
                cursor++;
            }
            List<String> sectionLines = lines.subList(sectionStart, cursor);
            String fingerprint = String.join("\n", sectionLines).stripTrailing();
            if (seenSections.add(fingerprint)) {
                output.addAll(sectionLines);
            } else {
                removedSections++;
            }
        }

        if (removedSections == 0) {
            return new PromptTransformResult(prompt, List.of());
        }

        String optimized = String.join("\n", output);
        return new PromptTransformResult(
                optimized,
                List.of(new PromptCompressionRecord(
                        "IDENTICAL_PROMPT_SECTIONS",
                        PromptCompressionAction.DEDUPLICATED,
                        prompt.length(),
                        optimized.length(),
                        estimateSavedTokens(prompt, optimized, modelHint, budgetProfile),
                        "Removed " + removedSections
                                + " byte-identical repeated section(s); one complete canonical copy was retained.")));
    }

    private boolean isSectionHeader(String line) {
        if (line == null) {
            return false;
        }
        String trimmed = line.trim();
        return trimmed.length() > 6 && trimmed.startsWith("===") && trimmed.endsWith("===");
    }

    private PromptTransformResult removeResolvedAuthorizationEffectMissingContext(
            String prompt,
            String modelHint,
            PromptBudgetProfile budgetProfile) {
        if (prompt == null || prompt.isBlank()
                || !prompt.contains("Bridge missing context: AUTHORIZATION_EFFECT.")
                || !hasResolvedAuthorizationEffect(prompt)) {
            return new PromptTransformResult(prompt != null ? prompt : "", List.of());
        }

        List<String> lines = List.of(prompt.split("\\n", -1));
        List<String> output = new ArrayList<>(lines.size());
        for (String line : lines) {
            if (!"- Bridge missing context: AUTHORIZATION_EFFECT.".equals(line.trim())) {
                output.add(line);
            }
        }
        String optimized = String.join("\n", output);
        if (optimized.equals(prompt)) {
            return new PromptTransformResult(prompt, List.of());
        }
        return new PromptTransformResult(
                optimized,
                List.of(new PromptCompressionRecord(
                        "AUTHORIZATION_EFFECT_CONSISTENCY",
                        PromptCompressionAction.DEDUPLICATED,
                        prompt.length(),
                        optimized.length(),
                        estimateSavedTokens(prompt, optimized, modelHint, budgetProfile),
                        "Removed a stale missing-context statement because a resolved AuthorizationEffect is present.")));
    }

    private boolean hasResolvedAuthorizationEffect(String prompt) {
        for (String line : prompt.split("\\n")) {
            String trimmed = line.trim();
            if (!trimmed.startsWith("AuthorizationEffect:")) {
                continue;
            }
            String value = trimmed.substring("AuthorizationEffect:".length()).trim();
            return !value.isBlank()
                    && !"UNKNOWN".equalsIgnoreCase(value)
                    && !"UNRESOLVED".equalsIgnoreCase(value)
                    && !"MISSING".equalsIgnoreCase(value);
        }
        return false;
    }

    private PromptCompressionLedger buildLedger(
            String rawSystemPrompt,
            String rawUserPrompt,
            String llmSystemPrompt,
            String llmUserPrompt,
            List<PromptCompressionRecord> records,
            String modelHint,
            PromptBudgetProfile budgetProfile) {
        int rawTotal = rawSystemPrompt.length() + rawUserPrompt.length();
        int llmTotal = llmSystemPrompt.length() + llmUserPrompt.length();
        int savedCharacters = Math.max(0, rawTotal - llmTotal);
        int savedTokens = estimateSavedTokens(
                rawSystemPrompt + "\n---\n" + rawUserPrompt,
                llmSystemPrompt + "\n---\n" + llmUserPrompt,
                modelHint,
                budgetProfile);
        boolean exactParity = rawSystemPrompt.equals(llmSystemPrompt)
                && rawUserPrompt.equals(llmUserPrompt);
        return new PromptCompressionLedger(
                resolveTransformationMode(records, exactParity),
                exactParity,
                rawSystemPrompt.length(),
                rawUserPrompt.length(),
                llmSystemPrompt.length(),
                llmUserPrompt.length(),
                savedCharacters,
                savedTokens,
                records);
    }

    private String resolveTransformationMode(
            List<PromptCompressionRecord> records,
            boolean exactParity) {
        if (exactParity) {
            return IDENTITY_MODE;
        }
        for (PromptCompressionRecord record : records) {
            if (record.action() == PromptCompressionAction.DEDUPLICATED) {
                return LOSSLESS_DEDUPLICATION_MODE;
            }
        }
        return NORMALIZE_ONLY_MODE;
    }

    private int estimateSavedTokens(
            String rawText,
            String optimizedText,
            String modelHint,
            PromptBudgetProfile budgetProfile) {
        PromptTokenEstimator estimator = TOKEN_ESTIMATORS.resolve(modelHint);
        int rawTokens = estimator.estimate(modelHint, "", rawText, budgetProfile).estimatedTotalTokens();
        int optimizedTokens = estimator.estimate(modelHint, "", optimizedText, budgetProfile).estimatedTotalTokens();
        return Math.max(0, rawTokens - optimizedTokens);
    }

    private String normalizeLineEndings(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        return text.replace("\r\n", "\n").replace('\r', '\n');
    }

    private record PromptTransformResult(
            String text,
            List<PromptCompressionRecord> records) {

        private PromptTransformResult {
            text = text == null ? "" : text;
            records = records == null ? List.of() : List.copyOf(records);
        }
    }
}
