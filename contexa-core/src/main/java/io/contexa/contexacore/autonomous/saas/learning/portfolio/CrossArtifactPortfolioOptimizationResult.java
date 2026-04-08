package io.contexa.contexacore.autonomous.saas.learning.portfolio;
import java.time.LocalDateTime;
import java.util.List;
/**
 * Result of optimizing the learning artifact portfolio.
 */
public record CrossArtifactPortfolioOptimizationResult(
        String tenantId,
        CrossArtifactPortfolioHealthState healthState,
        int portfolioScore,
        List<CrossArtifactPortfolioArtifactSummary> artifactSummaries,
        List<String> recommendedRuntimeOrder,
        List<CrossArtifactPortfolioRecommendation> recommendations,
        List<String> portfolioFacts,
        LocalDateTime evaluatedAt) {
    public CrossArtifactPortfolioOptimizationResult {
        artifactSummaries = artifactSummaries == null ? List.of() : List.copyOf(artifactSummaries);
        recommendedRuntimeOrder = recommendedRuntimeOrder == null ? List.of() : List.copyOf(recommendedRuntimeOrder);
        recommendations = recommendations == null ? List.of() : List.copyOf(recommendations);
        portfolioFacts = portfolioFacts == null ? List.of() : List.copyOf(portfolioFacts);
    }
}
