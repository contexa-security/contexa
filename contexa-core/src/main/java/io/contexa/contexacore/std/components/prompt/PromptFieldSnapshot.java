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

public record PromptFieldSnapshot(
        String fieldKey,
        String sectionKey,
        String sectionTitle,
        String label,
        String valueHash,
        int valueLength,
        int lineNumber,
        String valuePreview,
        boolean compactedMarker,
        boolean truncatedMarker,
        String qualityRelevance,
        List<String> metricCodes,
        String remediationOwner,
        String requiredPolicy,
        String projectionPolicy) {

    public PromptFieldSnapshot {
        metricCodes = metricCodes == null ? List.of() : List.copyOf(metricCodes);
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("fieldKey", fieldKey);
        metadata.put("sectionKey", sectionKey);
        metadata.put("sectionTitle", sectionTitle);
        metadata.put("label", label);
        metadata.put("valueHash", valueHash);
        metadata.put("valueLength", valueLength);
        metadata.put("lineNumber", lineNumber);
        metadata.put("valuePreview", valuePreview);
        metadata.put("compactedMarker", compactedMarker);
        metadata.put("truncatedMarker", truncatedMarker);
        metadata.put("qualityRelevance", qualityRelevance);
        metadata.put("metricCodes", metricCodes);
        metadata.put("remediationOwner", remediationOwner);
        metadata.put("requiredPolicy", requiredPolicy);
        metadata.put("projectionPolicy", projectionPolicy);
        return metadata;
    }
}
