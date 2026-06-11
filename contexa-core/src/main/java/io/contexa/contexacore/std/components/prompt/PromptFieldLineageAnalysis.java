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

public record PromptFieldLineageAnalysis(
        List<PromptFieldSnapshot> rawUserFields,
        List<PromptFieldSnapshot> finalUserFields,
        List<PromptFieldDiffRecord> fieldDiffs,
        int missingInFinalCount,
        int changedCount,
        int addedInFinalCount,
        int compactedMarkerCount,
        int truncatedMarkerCount) {

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("promptRawUserFieldCount", rawUserFields.size());
        metadata.put("promptFinalUserFieldCount", finalUserFields.size());
        metadata.put("promptUserFieldDiffCount", fieldDiffs.size());
        metadata.put("promptUserFieldLossCount", missingInFinalCount);
        metadata.put("promptUserFieldChangedCount", changedCount);
        metadata.put("promptUserFieldAddedCount", addedInFinalCount);
        metadata.put("promptUserFieldCompactedMarkerCount", compactedMarkerCount);
        metadata.put("promptUserFieldTruncatedMarkerCount", truncatedMarkerCount);
        metadata.put("promptRawUserFieldLedger", rawUserFields.stream()
                .map(PromptFieldSnapshot::toMetadataMap)
                .toList());
        metadata.put("promptFinalUserFieldLedger", finalUserFields.stream()
                .map(PromptFieldSnapshot::toMetadataMap)
                .toList());
        metadata.put("promptUserFieldDiffLedger", fieldDiffs.stream()
                .map(PromptFieldDiffRecord::toMetadataMap)
                .toList());
        metadata.put("promptUserFieldLineageSummary", summary());
        return metadata;
    }

    private Map<String, Object> summary() {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("rawUserFieldCount", rawUserFields.size());
        summary.put("finalUserFieldCount", finalUserFields.size());
        summary.put("diffCount", fieldDiffs.size());
        summary.put("missingInFinalCount", missingInFinalCount);
        summary.put("changedCount", changedCount);
        summary.put("addedInFinalCount", addedInFinalCount);
        summary.put("compactedMarkerCount", compactedMarkerCount);
        summary.put("truncatedMarkerCount", truncatedMarkerCount);
        return summary;
    }
}
