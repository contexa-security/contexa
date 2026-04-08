package io.contexa.contexacore.autonomous.saas.learning.roi;
import io.contexa.contexacore.autonomous.saas.dto.PromptPresentationPackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactTypeNames;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactReleaseLedgerService;
import java.util.List;
import java.util.Locale;
final class PromptPresentationRoiScorer extends AbstractLearningRoiArtifactScorer {
    PromptPresentationRoiScorer(LearningArtifactReleaseLedgerService ledgerService) {
        super(LearningArtifactTypeNames.PROMPT_PRESENTATION, ledgerService);
    }
    @Override
    public List<LearningRoiArtifactScore> score(LearningRoiScoreboardInput input) {
        PromptPresentationPackSnapshot snapshot = input == null ? null : input.promptPresentationPack();
        if (snapshot == null || !snapshot.runtimeReady()) {
            return List.of();
        }
        return snapshot.patterns().stream()
                .filter(item -> item.runtimeEligible() && isPromoted(item.promotionState()))
                .map(item -> scoreArtifact(
                        item.presentationPatternKey(),
                        item.presentationPatternVersion(),
                        item.measuredDelta().sampleSize(),
                        1.0d - item.measuredDelta().omissionLinkedRate(),
                        item.measuredDelta().falsePositiveRate(),
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
