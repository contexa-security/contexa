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
package io.contexa.contexacore.autonomous.saas.learning.roi;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactReleaseLedgerService;
abstract class AbstractLearningRoiArtifactScorer implements LearningRoiArtifactScorer {
    private final String artifactType;
    private final LearningArtifactReleaseLedgerService ledgerService;
    protected AbstractLearningRoiArtifactScorer(String artifactType, LearningArtifactReleaseLedgerService ledgerService) {
        this.artifactType = artifactType;
        this.ledgerService = ledgerService;
    }
    protected LearningRoiArtifactScore scoreArtifact(
            String artifactKey,
            String artifactVersion,
            long evidenceSampleCount,
            double liftSignal,
            double falsePositiveSignal,
            LearningRoiCostModel costModel) {
        long adoptedTenantCount = ledgerService.countAdoptedTenants(artifactType, artifactKey);
        long rollbackCount = ledgerService.countRollbacks(artifactType, artifactKey);
        double operatingCost = adoptedTenantCount * costModel.operatingCostPerAdoptedTenant();
        double detectionLiftValue = Math.max(0.0d, liftSignal) * Math.max(0L, evidenceSampleCount) * costModel.detectionLiftValuePerUnit();
        double falsePositiveCost = Math.max(0.0d, falsePositiveSignal) * Math.max(0L, evidenceSampleCount) * costModel.falsePositiveCostPerUnit();
        double rollbackPenalty = rollbackCount * costModel.rollbackPenaltyPerEvent();
        double netScore = detectionLiftValue - falsePositiveCost - operatingCost - rollbackPenalty;
        return new LearningRoiArtifactScore(
                artifactType,
                artifactKey,
                artifactVersion,
                adoptedTenantCount,
                rollbackCount,
                operatingCost,
                detectionLiftValue,
                falsePositiveCost,
                rollbackPenalty,
                netScore,
                recommend(netScore));
    }
    private String recommend(double netScore) {
        if (netScore >= 500.0d) {
            return "PROMOTE_AND_EXPAND";
        }
        if (netScore >= 0.0d) {
            return "KEEP_UNDER_GOVERNANCE";
        }
        return "REVIEW_COST_AND_REGRESSION";
    }
}
