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

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetrics;

import java.util.List;

/**
 * Strategy-family effectiveness result emitted by the learning engine.
 */
public record DetectionStrategyLearningFamilyResult(
        String strategyFamily,
        LearningArtifactMetrics metrics,
        long outcomeEvidenceCount,
        long hardNegativeCount,
        long confirmedAttackCount,
        long falsePositiveCount,
        long falseNegativeCount,
        long promptAuditLinkedCount,
        long telemetryLinkedCount,
        long campaignObservationCount,
        List<String> evidenceFacts) {

    public DetectionStrategyLearningFamilyResult {
        strategyFamily = strategyFamily == null ? "UNCLASSIFIED" : strategyFamily.trim();
        metrics = metrics == null ? LearningArtifactMetrics.empty() : metrics;
        evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
    }
}
