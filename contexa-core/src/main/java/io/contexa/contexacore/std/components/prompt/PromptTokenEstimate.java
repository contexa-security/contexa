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

/**
 * Observational token telemetry for prompt inputs.
 *
 * This first phase does not mutate or compress prompt text. The goal is to expose
 * prompt token pressure without changing LLM judgment.
 */
public record PromptTokenEstimate(
        String estimatorKey,
        int estimatedSystemTokens,
        int estimatedUserTokens,
        int estimatedTotalTokens,
        int budgetRemainingTokens,
        double budgetUtilizationRate,
        boolean budgetExceeded,
        String budgetEnforcementMode,
        boolean compressionApplied) {

    public PromptTokenEstimate {
        estimatorKey = requireText(estimatorKey, "estimatorKey");
        budgetEnforcementMode = requireText(budgetEnforcementMode, "budgetEnforcementMode");
        if (estimatedSystemTokens < 0 || estimatedUserTokens < 0 || estimatedTotalTokens < 0) {
            throw new IllegalArgumentException("Estimated prompt tokens must not be negative");
        }
        if (Double.isNaN(budgetUtilizationRate) || Double.isInfinite(budgetUtilizationRate)) {
            throw new IllegalArgumentException("budgetUtilizationRate must be finite");
        }
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("promptTokenEstimator", estimatorKey);
        metadata.put("estimatedSystemTokens", estimatedSystemTokens);
        metadata.put("estimatedUserTokens", estimatedUserTokens);
        metadata.put("estimatedTotalTokens", estimatedTotalTokens);
        metadata.put("promptBudgetRemainingTokens", budgetRemainingTokens);
        metadata.put("promptBudgetUtilizationRate", budgetUtilizationRate);
        metadata.put("promptBudgetExceeded", budgetExceeded);
        metadata.put("promptBudgetEnforcementMode", budgetEnforcementMode);
        metadata.put("promptCompressionApplied", compressionApplied);
        return metadata;
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}
