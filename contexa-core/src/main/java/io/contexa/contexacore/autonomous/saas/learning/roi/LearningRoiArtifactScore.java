package io.contexa.contexacore.autonomous.saas.learning.roi;
/**
 * ROI score per learning artifact.
 */
public record LearningRoiArtifactScore(
        String artifactType,
        String artifactKey,
        String artifactVersion,
        long adoptedTenantCount,
        long rollbackCount,
        double operatingCost,
        double detectionLiftValue,
        double falsePositiveCost,
        double rollbackPenalty,
        double netScore,
        String recommendation) {
}
