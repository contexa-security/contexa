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
package io.contexa.contexacore.autonomous.saas.learning.quality;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;

import java.util.List;
import java.util.Objects;

/**
 * Assembly input that combines a scenario result with artifact metadata.
 */
public record DecisionQualityProfileCandidate(
        DecisionQualityScenarioResult scenarioResult,
        LearningArtifactMetadata metadata,
        List<String> policyFacts) {

    public DecisionQualityProfileCandidate {
        scenarioResult = Objects.requireNonNull(scenarioResult, "scenarioResult is required");
        metadata = metadata == null ? LearningArtifactMetadata.collecting() : metadata;
        policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
    }
}
