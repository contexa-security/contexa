package io.contexa.contexacore.autonomous.saas.learning.portfolio;
/**
 * Normalized artifact summary used by portfolio optimization.
 */
public record CrossArtifactPortfolioArtifactSummary(
        String artifactType,
        boolean runtimeReady,
        long promotedCount,
        long candidateCount,
        long collectingCount) {
}
