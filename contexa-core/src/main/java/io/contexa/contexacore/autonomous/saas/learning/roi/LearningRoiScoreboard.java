package io.contexa.contexacore.autonomous.saas.learning.roi;
import java.time.LocalDateTime;
import java.util.List;
/**
 * Aggregate ROI scoreboard for learning artifacts.
 */
public record LearningRoiScoreboard(
        List<LearningRoiArtifactScore> artifactScores,
        double totalOperatingCost,
        double totalDetectionLiftValue,
        double totalFalsePositiveCost,
        double totalRollbackPenalty,
        double totalNetScore,
        LocalDateTime generatedAt) {
    public LearningRoiScoreboard {
        artifactScores = artifactScores == null ? List.of() : List.copyOf(artifactScores);
    }
}
