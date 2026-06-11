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

import io.contexa.contexacore.autonomous.saas.learning.quality.DecisionQualityLearningInput;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyLearningInput;

/**
 * Top-level orchestration facade for strategy and decision-quality artifact generation.
 */
public class LearningArtifactOrchestrationService {

    private final DetectionStrategyArtifactPipeline detectionStrategyArtifactPipeline;
    private final DecisionQualityArtifactPipeline decisionQualityArtifactPipeline;

    public LearningArtifactOrchestrationService(
            DetectionStrategyArtifactPipeline detectionStrategyArtifactPipeline,
            DecisionQualityArtifactPipeline decisionQualityArtifactPipeline) {
        this.detectionStrategyArtifactPipeline = detectionStrategyArtifactPipeline;
        this.decisionQualityArtifactPipeline = decisionQualityArtifactPipeline;
    }

    public DetectionStrategyArtifactPipelineResult orchestrateDetectionStrategies(
            String tenantId,
            DetectionStrategyLearningInput input) {
        return detectionStrategyArtifactPipeline.execute(tenantId, input);
    }

    public DecisionQualityArtifactPipelineResult orchestrateDecisionQualityProfiles(
            String tenantId,
            DecisionQualityLearningInput input) {
        return decisionQualityArtifactPipeline.execute(tenantId, input);
    }
}