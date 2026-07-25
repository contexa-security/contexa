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
import java.util.Locale;
import java.util.Map;

public enum PromptBudgetProfile {
    CORTEX_L1_INTERACTIVE_STRICT(
            "CORTEX_L1_INTERACTIVE_STRICT",
            "Security decision layer1 interactive strict profile",
            4200),
    CORTEX_L2_EXPERT_STRICT(
            "CORTEX_L2_EXPERT_STRICT",
            "Security decision layer2 expert strict profile",
            1850);

    private final String profileKey;
    private final String description;
    private final int maxInputTokens;

    PromptBudgetProfile(
            String profileKey,
            String description,
            int maxInputTokens) {
        this.profileKey = profileKey;
        this.description = description;
        this.maxInputTokens = maxInputTokens;
    }

    public String profileKey() {
        return profileKey;
    }

    public String description() {
        return description;
    }

    public int maxInputTokens() {
        return maxInputTokens;
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("budgetProfile", profileKey);
        metadata.put("budgetProfileDescription", description);
        metadata.put("budgetMaxInputTokens", maxInputTokens);
        return metadata;
    }

    public static PromptBudgetProfile fromKey(String value, PromptBudgetProfile fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        for (PromptBudgetProfile profile : values()) {
            if (profile.profileKey.equalsIgnoreCase(normalized) || profile.name().equals(normalized)) {
                return profile;
            }
        }
        return fallback;
    }
}
