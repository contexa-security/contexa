package io.contexa.contexacore.autonomous.saas.learning.portfolio;
import java.util.List;
/**
 * Optimization recommendation for the learning artifact portfolio.
 */
public record CrossArtifactPortfolioRecommendation(
        String code,
        String summary,
        boolean blocking,
        List<String> artifactTypes,
        String recommendedAction) {
    public CrossArtifactPortfolioRecommendation {
        artifactTypes = artifactTypes == null ? List.of() : List.copyOf(artifactTypes);
    }
}
