package io.contexa.contexacore.autonomous.saas.learning.roi;
import io.contexa.contexacore.autonomous.saas.dto.DetectionStrategyPackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactTypeNames;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactReleaseLedgerService;
import java.util.List;
import java.util.Locale;
final class DetectionStrategyRoiScorer extends AbstractLearningRoiArtifactScorer {
    DetectionStrategyRoiScorer(LearningArtifactReleaseLedgerService ledgerService) {
        super(LearningArtifactTypeNames.DETECTION_STRATEGY, ledgerService);
    }
    @Override
    public List<LearningRoiArtifactScore> score(LearningRoiScoreboardInput input) {
        DetectionStrategyPackSnapshot snapshot = input == null ? null : input.detectionStrategyPack();
        if (snapshot == null || !snapshot.runtimeReady()) {
            return List.of();
        }
        return snapshot.strategies().stream()
                .filter(item -> item.runtimeEligible() && isPromoted(item.promotionState()))
                .map(item -> scoreArtifact(
                        item.strategyKey(),
                        item.strategyVersion(),
                        item.sampleSize(),
                        item.localLiftRate(),
                        item.fpDelta(),
                        input.costModel()))
                .toList();
    }
    private boolean isPromoted(String releaseState) {
        try {
            return LearningArtifactReleaseState.valueOf(releaseState.trim().toUpperCase(Locale.ROOT))
                    == LearningArtifactReleaseState.PROMOTED;
        } catch (Exception ex) {
            return false;
        }
    }
}
