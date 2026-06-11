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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public record PromptCompressionLedger(
        String transformationMode,
        boolean rawPromptParity,
        int rawSystemPromptLength,
        int rawUserPromptLength,
        int llmSystemPromptLength,
        int llmUserPromptLength,
        int savedCharacters,
        int savedEstimatedTokens,
        List<PromptCompressionRecord> records) {

    public PromptCompressionLedger {
        transformationMode = requireText(transformationMode, "transformationMode");
        records = records == null ? List.of() : List.copyOf(records);
        if (rawSystemPromptLength < 0
                || rawUserPromptLength < 0
                || llmSystemPromptLength < 0
                || llmUserPromptLength < 0
                || savedCharacters < 0
                || savedEstimatedTokens < 0) {
            throw new IllegalArgumentException("Compression ledger counts must not be negative");
        }
    }

    public boolean compressionApplied() {
        return !rawPromptParity || !records.isEmpty() || savedCharacters > 0 || savedEstimatedTokens > 0;
    }

    public int rawTotalPromptLength() {
        return rawSystemPromptLength + rawUserPromptLength;
    }

    public int llmTotalPromptLength() {
        return llmSystemPromptLength + llmUserPromptLength;
    }

    public int operationCount() {
        return records.size();
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("promptTransformationMode", transformationMode);
        metadata.put("promptRawTruthParity", rawPromptParity);
        metadata.put("promptCompressionApplied", compressionApplied());
        metadata.put("promptCompressionOperationCount", operationCount());
        metadata.put("promptCompressionSavedCharacters", savedCharacters);
        metadata.put("promptCompressionSavedEstimatedTokens", savedEstimatedTokens);
        metadata.put("rawSystemPromptLength", rawSystemPromptLength);
        metadata.put("rawUserPromptLength", rawUserPromptLength);
        metadata.put("rawTotalPromptLength", rawTotalPromptLength());
        metadata.put("llmSystemPromptLength", llmSystemPromptLength);
        metadata.put("llmUserPromptLength", llmUserPromptLength);
        metadata.put("llmTotalPromptLength", llmTotalPromptLength());
        metadata.put("promptCompressionLedger", records.stream().map(PromptCompressionRecord::toMetadataMap).toList());
        return metadata;
    }

    public static PromptCompressionLedger identity(String systemPrompt, String userPrompt) {
        String normalizedSystemPrompt = Objects.requireNonNullElse(systemPrompt, "");
        String normalizedUserPrompt = Objects.requireNonNullElse(userPrompt, "");
        return new PromptCompressionLedger(
                "IDENTITY",
                true,
                normalizedSystemPrompt.length(),
                normalizedUserPrompt.length(),
                normalizedSystemPrompt.length(),
                normalizedUserPrompt.length(),
                0,
                0,
                List.of());
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}