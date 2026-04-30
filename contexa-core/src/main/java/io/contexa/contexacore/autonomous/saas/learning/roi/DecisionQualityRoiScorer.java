package io.contexa.contexacore.autonomous.saas.learning.roi;
import io.contexa.contexacore.autonomous.saas.dto.DecisionQualityProfileSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactTypeNames;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactReleaseLedgerService;
import java.util.List;
import java.util.Locale;
final class DecisionQualityRoiScorer extends AbstractLearningRoiArtifactScorer {
    DecisionQualityRoiScorer(LearningArtifactReleaseLedgerService ledgerService) {
        super(LearningArtifactTypeNames.DECISION_QUALITY_PROFILE, ledgerService);
    }
    @Override
    public List<LearningRoiArtifactScore> score(LearningRoiScoreboardInput input) {
        DecisionQualityProfileSnapshot snapshot = input == null ? null : input.decisionQualityProfile();
        if (snapshot == null || !snapshot.runtimeReady()) {
            return List.of();
        }
        return snapshot.profiles().stream()
                .filter(item -> item.runtimeEligible() && isPromoted(item.promotionState()))
                .map(item -> scoreArtifact(
                        item.profileKey(),
                        item.profileVersion(),
                        item.operatorReviewedOutcomeCount(),
                        item.allowUnderfireRate(),
                        item.falsePositiveRate(),
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
