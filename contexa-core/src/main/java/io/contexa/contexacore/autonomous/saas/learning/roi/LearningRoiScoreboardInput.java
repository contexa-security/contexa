package io.contexa.contexacore.autonomous.saas.learning.roi;
import io.contexa.contexacore.autonomous.saas.dto.DecisionQualityProfileSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.CohortSeedPackSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.DetectionStrategyPackSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.PromptPresentationPackSnapshot;
/**
 * Input payload for learning ROI scoring.
 */
public record LearningRoiScoreboardInput(
        DetectionStrategyPackSnapshot detectionStrategyPack,
        DecisionQualityProfileSnapshot decisionQualityProfile,
        PromptPresentationPackSnapshot promptPresentationPack,
        CohortSeedPackSnapshot cohortSeedPack,
        LearningRoiCostModel costModel) {
    public static LearningRoiScoreboardInput empty() {
        return new LearningRoiScoreboardInput(
                DetectionStrategyPackSnapshot.empty(),
                DecisionQualityProfileSnapshot.empty(),
                PromptPresentationPackSnapshot.empty(),
                CohortSeedPackSnapshot.empty(),
                LearningRoiCostModel.defaults());
    }
}
