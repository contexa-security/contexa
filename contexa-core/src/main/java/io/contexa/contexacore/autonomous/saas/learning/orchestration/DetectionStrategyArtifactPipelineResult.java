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
package io.contexa.contexacore.autonomous.saas.learning.orchestration;

import io.contexa.contexacore.autonomous.saas.dto.DetectionStrategyPackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyLearningPortfolio;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyPackCandidate;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyRuntimePack;
import io.contexa.contexacore.autonomous.saas.learning.transfer.ArtifactTransferRiskAssessment;

import java.util.List;

/**
 * Final strategy pipeline output for orchestration and registry ingestion.
 */
public record DetectionStrategyArtifactPipelineResult(
        DetectionStrategyLearningPortfolio learningPortfolio,
        List<DetectionStrategyPackCandidate> candidates,
        ArtifactTransferRiskAssessment transferRiskAssessment,
        DetectionStrategyPackSnapshot snapshot,
        DetectionStrategyRuntimePack runtimePack) {

    public DetectionStrategyArtifactPipelineResult {
        learningPortfolio = learningPortfolio == null ? DetectionStrategyLearningPortfolio.empty() : learningPortfolio;
        candidates = candidates == null ? List.of() : List.copyOf(candidates);
    }
}