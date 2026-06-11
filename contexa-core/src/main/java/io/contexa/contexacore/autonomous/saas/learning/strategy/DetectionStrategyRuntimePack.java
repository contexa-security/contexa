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
package io.contexa.contexacore.autonomous.saas.learning.strategy;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Internal runtime DTO consumed by the strategy runtime integration path.
 */
public record DetectionStrategyRuntimePack(
        String tenantId,
        boolean runtimeReady,
        List<RuntimeStrategyItem> strategies,
        LocalDateTime generatedAt) {

    public DetectionStrategyRuntimePack {
        strategies = strategies == null ? List.of() : List.copyOf(strategies);
    }

    public static DetectionStrategyRuntimePack empty() {
        return new DetectionStrategyRuntimePack(null, false, List.of(), null);
    }

    public record RuntimeStrategyItem(
            String strategyKey,
            String strategyVersion,
            String strategyFamily,
            List<String> supportedThreatGoals,
            List<String> requiredSignals,
            List<String> recommendedSignals,
            List<String> applicableContextClasses,
            long minimumEvidenceCount,
            String confidenceBand,
            LearningArtifactMetadata metadata,
            List<String> evidenceFacts,
            List<String> policyFacts) {

        public RuntimeStrategyItem {
            supportedThreatGoals = supportedThreatGoals == null ? List.of() : List.copyOf(supportedThreatGoals);
            requiredSignals = requiredSignals == null ? List.of() : List.copyOf(requiredSignals);
            recommendedSignals = recommendedSignals == null ? List.of() : List.copyOf(recommendedSignals);
            applicableContextClasses = applicableContextClasses == null ? List.of() : List.copyOf(applicableContextClasses);
            metadata = metadata == null ? LearningArtifactMetadata.collecting() : metadata;
            evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
            policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
        }
    }
}
