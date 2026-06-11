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
package io.contexa.contexacore.autonomous.saas.learning.release;

import io.contexa.contexacore.autonomous.saas.SaasDetectionStrategyPackService;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactTypeNames;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Coordinates runtime cache invalidation and refresh for governed learning artifacts.
 */
public class LearningArtifactRuntimeRefreshService {

    private final SaasDetectionStrategyPackService detectionStrategyPackService;

    public LearningArtifactRuntimeRefreshService(SaasDetectionStrategyPackService detectionStrategyPackService) {
        this.detectionStrategyPackService = detectionStrategyPackService;
    }

    public LearningArtifactRuntimeRefreshResult refreshArtifact(String artifactType) {
        String safeArtifactType = artifactType == null ? "UNKNOWN" : artifactType.trim().toUpperCase(Locale.ROOT);
        return switch (safeArtifactType) {
            case LearningArtifactTypeNames.DETECTION_STRATEGY -> refreshDetectionStrategy();
            case LearningArtifactTypeNames.DECISION_QUALITY_PROFILE,
                    LearningArtifactTypeNames.PROMPT_PRESENTATION,
                    LearningArtifactTypeNames.COHORT_SEED ->
                    new LearningArtifactRuntimeRefreshResult(
                            safeArtifactType,
                            false,
                            false,
                            false,
                            List.of("Runtime refresh is not applicable to governance-only artifacts in P0."));
            default -> new LearningArtifactRuntimeRefreshResult(
                    safeArtifactType,
                    false,
                    false,
                    false,
                    List.of("Unknown learning artifact type; runtime refresh was skipped."));
        };
    }

    private LearningArtifactRuntimeRefreshResult refreshDetectionStrategy() {
        List<String> facts = new ArrayList<>();
        if (detectionStrategyPackService == null) {
            facts.add("Detection strategy runtime service is not configured.");
            return new LearningArtifactRuntimeRefreshResult(LearningArtifactTypeNames.DETECTION_STRATEGY, false, false, false, facts);
        }
        detectionStrategyPackService.invalidateAndRefresh();
        facts.add("Detection strategy runtime cache invalidated.");
        facts.add("Detection strategy runtime snapshot refreshed.");
        return new LearningArtifactRuntimeRefreshResult(LearningArtifactTypeNames.DETECTION_STRATEGY, true, true, true, facts);
    }
}
