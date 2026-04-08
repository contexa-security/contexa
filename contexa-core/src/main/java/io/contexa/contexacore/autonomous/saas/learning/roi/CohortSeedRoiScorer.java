package io.contexa.contexacore.autonomous.saas.learning.roi;
import io.contexa.contexacore.autonomous.saas.dto.CohortSeedPackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactTypeNames;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactReleaseLedgerService;
import java.util.List;
final class CohortSeedRoiScorer extends AbstractLearningRoiArtifactScorer {
    CohortSeedRoiScorer(LearningArtifactReleaseLedgerService ledgerService) {
        super(LearningArtifactTypeNames.COHORT_SEED, ledgerService);
    }
    @Override
    public List<LearningRoiArtifactScore> score(LearningRoiScoreboardInput input) {
        CohortSeedPackSnapshot snapshot = input == null ? null : input.cohortSeedPack();
        if (snapshot == null || !snapshot.seedAvailable() || !snapshot.seedQualified()) {
            return List.of();
        }
        return List.of(scoreArtifact(
                snapshot.cohortKey(),
                snapshot.promotionState(),
                snapshot.sampleUserBaselineCount(),
                snapshot.earlyQualityImprovementDelta(),
                0.0d,
                input.costModel()));
    }
}
