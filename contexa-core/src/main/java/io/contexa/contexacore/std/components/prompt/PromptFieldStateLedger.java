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

import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record PromptFieldStateLedger(
        List<PromptFieldStateRecord> records,
        int sourceFieldCount,
        int rawUserFieldCount,
        int finalUserFieldCount,
        int projectionDiffCount,
        int blockingCandidateCount) {

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("promptFieldStateCount", records.size());
        metadata.put("promptBlockingFieldStateCount", blockingCandidateCount);
        metadata.put("promptFieldStateLedger", records.stream()
                .map(PromptFieldStateRecord::toMetadataMap)
                .toList());
        metadata.put("promptFieldStateSummary", summary());
        return metadata;
    }

    private Map<String, Object> summary() {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("fieldStateCount", records.size());
        summary.put("sourceFieldCount", sourceFieldCount);
        summary.put("rawUserFieldCount", rawUserFieldCount);
        summary.put("finalUserFieldCount", finalUserFieldCount);
        summary.put("projectionDiffCount", projectionDiffCount);
        summary.put("blockingCandidateCount", blockingCandidateCount);
        summary.put("stateCounts", stateCounts());
        return summary;
    }

    private Map<String, Integer> stateCounts() {
        Map<PromptFieldState, Integer> counts = new EnumMap<>(PromptFieldState.class);
        for (PromptFieldStateRecord record : records) {
            counts.merge(record.fieldState(), 1, Integer::sum);
        }
        Map<String, Integer> result = new LinkedHashMap<>();
        for (PromptFieldState state : PromptFieldState.values()) {
            result.put(state.name(), counts.getOrDefault(state, 0));
        }
        return result;
    }
}
