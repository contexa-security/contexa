package io.contexa.contexacore.autonomous.saas.learning.portfolio;
import io.contexa.contexacore.autonomous.saas.dto.CalibrationProfilePackSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.CohortSeedPackSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.DetectionStrategyPackSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.PromptPresentationPackSnapshot;
/**
 * Portfolio optimization input across all learning artifact families.
 */
public record CrossArtifactPortfolioOptimizationInput(
        DetectionStrategyPackSnapshot detectionStrategyPack,
        CalibrationProfilePackSnapshot calibrationProfilePack,
        PromptPresentationPackSnapshot promptPresentationPack,
        CohortSeedPackSnapshot cohortSeedPack) {
    public static CrossArtifactPortfolioOptimizationInput empty() {
        return new CrossArtifactPortfolioOptimizationInput(
                DetectionStrategyPackSnapshot.empty(),
                CalibrationProfilePackSnapshot.empty(),
                PromptPresentationPackSnapshot.empty(),
                CohortSeedPackSnapshot.empty());
    }
}
