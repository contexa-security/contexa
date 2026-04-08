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
