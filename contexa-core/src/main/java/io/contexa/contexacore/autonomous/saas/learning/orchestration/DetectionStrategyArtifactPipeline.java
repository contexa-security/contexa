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
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyLearningFamilyResult;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyLearningInput;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyLearningPortfolio;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyLearningService;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyPackAssembler;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyPackCandidate;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyRuntimePack;
import io.contexa.contexacore.autonomous.saas.learning.strategy.StrategyEvidenceQualificationPolicy;
import io.contexa.contexacore.autonomous.saas.learning.strategy.StrategyEvidenceQualificationThresholds;
import io.contexa.contexacore.autonomous.saas.learning.sanitization.LearningArtifactSanitizationService;
import io.contexa.contexacore.autonomous.saas.learning.transfer.ArtifactTransferEligibilityInput;
import io.contexa.contexacore.autonomous.saas.learning.transfer.ArtifactTransferRiskAssessment;
import io.contexa.contexacore.autonomous.saas.learning.transfer.CrossTenantTransferEligibilityService;

import java.util.List;

/**
 * End-to-end pipeline that turns raw strategy learning inputs into transport and runtime artifacts.
 */
public class DetectionStrategyArtifactPipeline {

    private final DetectionStrategyLearningService learningService;
    private final StrategyEvidenceQualificationPolicy qualificationPolicy;
    private final StrategyEvidenceQualificationThresholds thresholds;
    private final DetectionStrategyPackAssembler packAssembler;
    private final LearningArtifactSanitizationService sanitizationService;
    private final CrossTenantTransferEligibilityService transferEligibilityService;

    public DetectionStrategyArtifactPipeline(
            DetectionStrategyLearningService learningService,
            StrategyEvidenceQualificationPolicy qualificationPolicy,
            StrategyEvidenceQualificationThresholds thresholds,
            DetectionStrategyPackAssembler packAssembler,
            LearningArtifactSanitizationService sanitizationService,
            CrossTenantTransferEligibilityService transferEligibilityService) {
        this.learningService = learningService;
        this.qualificationPolicy = qualificationPolicy;
        this.thresholds = thresholds;
        this.packAssembler = packAssembler;
        this.sanitizationService = sanitizationService;
        this.transferEligibilityService = transferEligibilityService;
    }

    public DetectionStrategyArtifactPipelineResult execute(String tenantId, DetectionStrategyLearningInput input) {
        DetectionStrategyLearningPortfolio portfolio = learningService.evaluate(input);
        List<DetectionStrategyPackCandidate> candidates = portfolio.families().stream()
                .map(sanitizationService::sanitize)
                .map(this::toCandidate)
                .toList();
        ArtifactTransferRiskAssessment transferRisk = transferEligibilityService.assess(toTransferInput(tenantId, portfolio));
        boolean featureEnabled = !portfolio.families().isEmpty();
        DetectionStrategyPackSnapshot snapshot = packAssembler.assembleSnapshot(
                tenantId,
                featureEnabled,
                transferRisk.sharingEnabled(),
                candidates);
        DetectionStrategyRuntimePack runtimePack = transferRisk.sharingEnabled()
                ? packAssembler.assembleRuntimePack(tenantId, candidates)
                : DetectionStrategyRuntimePack.empty();
        return new DetectionStrategyArtifactPipelineResult(portfolio, candidates, transferRisk, snapshot, runtimePack);
    }

    private DetectionStrategyPackCandidate toCandidate(DetectionStrategyLearningFamilyResult familyResult) {
        return new DetectionStrategyPackCandidate(
                familyResult,
                qualificationPolicy.evaluate(familyResult),
                thresholds);
    }

    private ArtifactTransferEligibilityInput toTransferInput(
            String tenantId,
            DetectionStrategyLearningPortfolio portfolio) {
        long candidateCount = portfolio.families().size();
        long sampleSize = portfolio.families().stream().mapToLong(item -> item.metrics().sampleSize()).sum();
        double outcomeCoverage = average(portfolio.families().stream().mapToDouble(item -> item.metrics().outcomeCoverageRate()).toArray());
        double hardNegativeCoverage = average(portfolio.families().stream().mapToDouble(item -> item.metrics().hardNegativeCoverage()).toArray());
        double localLiftRate = average(portfolio.families().stream().mapToDouble(item -> item.metrics().localLiftRate()).toArray());
        return ArtifactTransferEligibilityInput.permissive(
                tenantId,
                "DETECTION_STRATEGY",
                candidateCount,
                sampleSize,
                outcomeCoverage,
                hardNegativeCoverage,
                localLiftRate);
    }

    private double average(double[] values) {
        if (values == null || values.length == 0) {
            return 0.0d;
        }
        double sum = 0.0d;
        for (double value : values) {
            sum += value;
        }
        return sum / values.length;
    }
}