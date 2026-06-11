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
package io.contexa.contexacore.autonomous.saas.learning.sanitization;

import io.contexa.contexacore.autonomous.saas.learning.quality.DecisionQualityScenarioResult;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyLearningFamilyResult;

/**
 * Central sanitization facade for cross-tenant learning artifact evidence.
 */
public class LearningArtifactSanitizationService {

    private final DetectionStrategyEvidenceSanitizer strategyEvidenceSanitizer;
    private final DecisionQualityEvidenceSanitizer decisionQualityEvidenceSanitizer;

    public LearningArtifactSanitizationService(
            DetectionStrategyEvidenceSanitizer strategyEvidenceSanitizer,
            DecisionQualityEvidenceSanitizer decisionQualityEvidenceSanitizer) {
        this.strategyEvidenceSanitizer = strategyEvidenceSanitizer;
        this.decisionQualityEvidenceSanitizer = decisionQualityEvidenceSanitizer;
    }

    public DetectionStrategyLearningFamilyResult sanitize(DetectionStrategyLearningFamilyResult result) {
        if (result == null) {
            return null;
        }
        return new DetectionStrategyLearningFamilyResult(
                result.strategyFamily(),
                result.metrics(),
                result.outcomeEvidenceCount(),
                result.hardNegativeCount(),
                result.confirmedAttackCount(),
                result.falsePositiveCount(),
                result.falseNegativeCount(),
                result.promptAuditLinkedCount(),
                result.telemetryLinkedCount(),
                result.campaignObservationCount(),
                strategyEvidenceSanitizer.sanitize(result.evidenceFacts()));
    }

    public DecisionQualityScenarioResult sanitize(DecisionQualityScenarioResult result) {
        if (result == null) {
            return null;
        }
        return new DecisionQualityScenarioResult(
                result.scenarioClass(),
                result.biasAggregation(),
                decisionQualityEvidenceSanitizer.sanitize(result.evidenceFacts()));
    }
}
