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

public record PromptOmissionRecord(
        String sectionKey,
        PromptOmissionType omissionType,
        int omittedItemCount,
        int omittedEstimatedTokens,
        String reason,
        PromptSemanticRisk semanticRisk) {

    public PromptOmissionRecord {
        sectionKey = requireText(sectionKey, "sectionKey");
        omissionType = Objects.requireNonNull(omissionType, "omissionType");
        semanticRisk = Objects.requireNonNull(semanticRisk, "semanticRisk");
        reason = requireText(reason, "reason");
        if (omittedItemCount < 0 || omittedEstimatedTokens < 0) {
            throw new IllegalArgumentException("Omission counts must not be negative");
        }
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("sectionKey", sectionKey);
        metadata.put("omissionType", omissionType.name());
        metadata.put("omittedItemCount", omittedItemCount);
        metadata.put("omittedEstimatedTokens", omittedEstimatedTokens);
        metadata.put("reason", reason);
        metadata.put("semanticRisk", semanticRisk.name());
        return metadata;
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}
