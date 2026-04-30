package io.contexa.contexacore.autonomous.saas.learning.roi;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactReleaseLedgerService;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
/**
 * Computes ROI scoreboard across promoted learning artifacts.
 */
@Service
public class LearningRoiScoreboardService {
    private final List<LearningRoiArtifactScorer> scorers;
    public LearningRoiScoreboardService(LearningArtifactReleaseLedgerService ledgerService) {
        this.scorers = List.of(
                new DetectionStrategyRoiScorer(ledgerService),
                new DecisionQualityRoiScorer(ledgerService),
                new PromptPresentationRoiScorer(ledgerService),
                new CohortSeedRoiScorer(ledgerService));
    }
    public LearningRoiScoreboard score(LearningRoiScoreboardInput input) {
        LearningRoiScoreboardInput normalized = input == null ? LearningRoiScoreboardInput.empty() : input;
        List<LearningRoiArtifactScore> scores = new ArrayList<>();
        for (LearningRoiArtifactScorer scorer : scorers) {
            scores.addAll(scorer.score(normalized));
        }
        scores.sort(Comparator.comparingDouble(LearningRoiArtifactScore::netScore).reversed());
        double totalOperatingCost = scores.stream().mapToDouble(LearningRoiArtifactScore::operatingCost).sum();
        double totalDetectionLiftValue = scores.stream().mapToDouble(LearningRoiArtifactScore::detectionLiftValue).sum();
        double totalFalsePositiveCost = scores.stream().mapToDouble(LearningRoiArtifactScore::falsePositiveCost).sum();
        double totalRollbackPenalty = scores.stream().mapToDouble(LearningRoiArtifactScore::rollbackPenalty).sum();
        double totalNetScore = scores.stream().mapToDouble(LearningRoiArtifactScore::netScore).sum();
        return new LearningRoiScoreboard(
                scores,
                totalOperatingCost,
                totalDetectionLiftValue,
                totalFalsePositiveCost,
                totalRollbackPenalty,
                totalNetScore,
                LocalDateTime.now());
    }
}
