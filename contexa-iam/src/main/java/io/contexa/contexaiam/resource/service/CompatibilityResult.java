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
package io.contexa.contexaiam.resource.service;

import io.contexa.contexaiam.domain.entity.ConditionTemplate;

import java.util.Collections;
import java.util.Set;

public class CompatibilityResult {
    private final boolean compatible;
    private final String reason;
    private final Set<String> missingVariables;
    private final Set<String> availableVariables;
    private final ConditionTemplate.ConditionClassification classification;
    private final boolean requiresAiValidation;

    public CompatibilityResult(boolean compatible, String reason, 
                             Set<String> missingVariables, Set<String> availableVariables,
                             ConditionTemplate.ConditionClassification classification,
                             boolean requiresAiValidation) {
        this.compatible = compatible;
        this.reason = reason;
        this.missingVariables = missingVariables != null ? missingVariables : Collections.emptySet();
        this.availableVariables = availableVariables != null ? availableVariables : Collections.emptySet();
        this.classification = classification;
        this.requiresAiValidation = requiresAiValidation;
    }

    public boolean isCompatible() { return compatible; }
    public String getReason() { return reason; }
    public Set<String> getMissingVariables() { return missingVariables; }
    public Set<String> getAvailableVariables() { return availableVariables; }
    public ConditionTemplate.ConditionClassification getClassification() { return classification; }
    public boolean requiresAiValidation() { return requiresAiValidation; }
} 