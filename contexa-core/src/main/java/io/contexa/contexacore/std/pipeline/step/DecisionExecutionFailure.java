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
package io.contexa.contexacore.std.pipeline.step;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public record DecisionExecutionFailure(
        DecisionFailureCategory category,
        String message,
        String technicalFallbackAction
) {

    public DecisionExecutionFailure {
        category = Objects.requireNonNull(category, "category");
        message = message != null ? message : "";
        technicalFallbackAction = normalize(technicalFallbackAction);
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("decisionFailureCategory", category.name());
        metadata.put("decisionFailureMessage", message);
        if (technicalFallbackAction != null) {
            metadata.put("decisionFailureTechnicalFallbackAction", technicalFallbackAction);
        }
        return metadata;
    }

    private static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim();
        return normalized.isEmpty() ? null : normalized;
    }
}
