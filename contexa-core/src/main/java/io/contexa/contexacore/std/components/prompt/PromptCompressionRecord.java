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
import java.util.Map;
import java.util.Objects;

public record PromptCompressionRecord(
        String scopeKey,
        PromptCompressionAction action,
        int rawCharacterCount,
        int compactCharacterCount,
        int savedEstimatedTokens,
        String reason) {

    public PromptCompressionRecord {
        scopeKey = requireText(scopeKey, "scopeKey");
        action = Objects.requireNonNull(action, "action");
        reason = requireText(reason, "reason");
        if (rawCharacterCount < 0 || compactCharacterCount < 0 || savedEstimatedTokens < 0) {
            throw new IllegalArgumentException("Compression counts must not be negative");
        }
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("scopeKey", scopeKey);
        metadata.put("action", action.name());
        metadata.put("rawCharacterCount", rawCharacterCount);
        metadata.put("compactCharacterCount", compactCharacterCount);
        metadata.put("savedEstimatedTokens", savedEstimatedTokens);
        metadata.put("reason", reason);
        return metadata;
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}