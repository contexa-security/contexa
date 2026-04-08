package io.contexa.contexacore.autonomous.saas.learning.portfolio;
import io.contexa.contexacore.autonomous.saas.dto.CalibrationProfilePackSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.CohortSeedPackSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.DetectionStrategyPackSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.PromptPresentationPackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactTypeNames;
import org.springframework.util.StringUtils;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
/**
 * Optimizes cross-artifact ordering and interaction guardrails.
 */
public class CrossArtifactPortfolioOptimizationService {
    public CrossArtifactPortfolioOptimizationResult optimize(CrossArtifactPortfolioOptimizationInput input) {
        CrossArtifactPortfolioOptimizationInput normalized = input == null
                ? CrossArtifactPortfolioOptimizationInput.empty()
                : input;
        DetectionStrategyPackSnapshot strategyPack = normalized.detectionStrategyPack();
        CalibrationProfilePackSnapshot calibrationPack = normalized.calibrationProfilePack();
        PromptPresentationPackSnapshot promptPack = normalized.promptPresentationPack();
        CohortSeedPackSnapshot cohortPack = normalized.cohortSeedPack();
        long promotedStrategies = countPromotedStrategies(strategyPack);
        long promotedCalibrations = countPromotedCalibrations(calibrationPack);
        long promotedPromptPatterns = countPromotedPromptPatterns(promptPack);
        long qualifiedCohortSeeds = countQualifiedCohortSeeds(cohortPack);
        List<CrossArtifactPortfolioArtifactSummary> summaries = List.of(
                new CrossArtifactPortfolioArtifactSummary(
                        LearningArtifactTypeNames.DETECTION_STRATEGY,
                        strategyPack != null && strategyPack.runtimeReady(),
                        promotedStrategies,
                        strategyPack != null ? strategyPack.candidateStrategyCount() : 0L,
                        strategyPack != null ? strategyPack.collectingStrategyCount() : 0L),
                new CrossArtifactPortfolioArtifactSummary(
                        LearningArtifactTypeNames.CALIBRATION_PROFILE,
                        calibrationPack != null && calibrationPack.runtimeReady(),
                        promotedCalibrations,
                        calibrationPack != null ? calibrationPack.candidateProfileCount() : 0L,
                        calibrationPack != null ? calibrationPack.collectingProfileCount() : 0L),
                new CrossArtifactPortfolioArtifactSummary(
                        LearningArtifactTypeNames.PROMPT_PRESENTATION,
                        promptPack != null && promptPack.runtimeReady(),
                        promotedPromptPatterns,
                        promptPack != null ? promptPack.candidatePatternCount() : 0L,
                        promptPack != null ? promptPack.blockedPatternCount() : 0L),
                new CrossArtifactPortfolioArtifactSummary(
                        LearningArtifactTypeNames.COHORT_SEED,
                        cohortPack != null && cohortPack.seedQualified(),
                        qualifiedCohortSeeds,
                        cohortPack != null && cohortPack.seedAvailable() ? 1L : 0L,
                        cohortPack != null && !cohortPack.seedQualified() ? 1L : 0L)
        );
        CrossArtifactPortfolioHealthState healthState = resolveHealthState(
                promotedStrategies,
                promotedCalibrations,
                promotedPromptPatterns,
                qualifiedCohortSeeds);
        List<CrossArtifactPortfolioRecommendation> recommendations = buildRecommendations(
                promotedStrategies,
                promotedCalibrations,
                promotedPromptPatterns,
                qualifiedCohortSeeds);
        List<String> runtimeOrder = buildRuntimeOrder(
                promotedStrategies,
                promotedCalibrations,
                promotedPromptPatterns,
                qualifiedCohortSeeds);
        int portfolioScore = score(
                promotedStrategies,
                promotedCalibrations,
                promotedPromptPatterns,
                qualifiedCohortSeeds,
                recommendations);
        List<String> portfolioFacts = List.of(
                String.format(Locale.ROOT,
                        "promotedCounts strategy=%d calibration=%d prompt=%d cohort=%d",
                        promotedStrategies,
                        promotedCalibrations,
                        promotedPromptPatterns,
                        qualifiedCohortSeeds),
                "recommendedRuntimeOrder=" + String.join(" > ", runtimeOrder),
                "healthState=" + healthState.name(),
                "portfolioScore=" + portfolioScore);
        return new CrossArtifactPortfolioOptimizationResult(
                resolveTenantId(strategyPack, calibrationPack, promptPack, cohortPack),
                healthState,
                portfolioScore,
                summaries,
                runtimeOrder,
                recommendations,
                portfolioFacts,
                LocalDateTime.now());
    }
    private CrossArtifactPortfolioHealthState resolveHealthState(
            long promotedStrategies,
            long promotedCalibrations,
            long promotedPromptPatterns,
            long qualifiedCohortSeeds) {
        if (promotedStrategies == 0L && promotedCalibrations == 0L && promotedPromptPatterns == 0L && qualifiedCohortSeeds == 0L) {
            return CrossArtifactPortfolioHealthState.EMPTY;
        }
        if (qualifiedCohortSeeds > 0L && promotedStrategies == 0L && promotedCalibrations == 0L && promotedPromptPatterns == 0L) {
            return CrossArtifactPortfolioHealthState.COHORT_ONLY;
        }
        if (promotedCalibrations > 0L && promotedStrategies == 0L) {
            return CrossArtifactPortfolioHealthState.CALIBRATION_WITHOUT_STRATEGY;
        }
        if (promotedPromptPatterns > 0L && promotedStrategies == 0L && promotedCalibrations == 0L) {
            return CrossArtifactPortfolioHealthState.PROMPT_WITHOUT_CORE;
        }
        if (promotedStrategies > 0L && promotedCalibrations == 0L) {
            return CrossArtifactPortfolioHealthState.STRATEGY_ONLY;
        }
        return CrossArtifactPortfolioHealthState.BALANCED;
    }
    private List<CrossArtifactPortfolioRecommendation> buildRecommendations(
            long promotedStrategies,
            long promotedCalibrations,
            long promotedPromptPatterns,
            long qualifiedCohortSeeds) {
        List<CrossArtifactPortfolioRecommendation> recommendations = new ArrayList<>();
        if (promotedStrategies == 0L && promotedCalibrations == 0L && promotedPromptPatterns == 0L && qualifiedCohortSeeds == 0L) {
            recommendations.add(new CrossArtifactPortfolioRecommendation(
                    "PORTFOLIO_EMPTY",
                    "No promoted or qualified learning artifact is available for runtime optimization.",
                    true,
                    List.of(),
                    "Keep runtime local-first and continue collecting evidence before promotion."));
            return recommendations;
        }
        if (promotedCalibrations > 0L && promotedStrategies == 0L) {
            recommendations.add(new CrossArtifactPortfolioRecommendation(
                    "CALIBRATION_WITHOUT_STRATEGY_SUPPORT",
                    "Calibration profiles are promoted without a promoted detection strategy foundation.",
                    true,
                    List.of(LearningArtifactTypeNames.CALIBRATION_PROFILE, LearningArtifactTypeNames.DETECTION_STRATEGY),
                    "Keep calibration profiles review-only until at least one promoted detection strategy exists."));
        }
        if (promotedPromptPatterns > 0L && promotedStrategies == 0L && promotedCalibrations == 0L) {
            recommendations.add(new CrossArtifactPortfolioRecommendation(
                    "PROMPT_WITHOUT_DECISION_CORE",
                    "Prompt presentation patterns are promoted without strategy or calibration support.",
                    true,
                    List.of(LearningArtifactTypeNames.PROMPT_PRESENTATION, LearningArtifactTypeNames.DETECTION_STRATEGY, LearningArtifactTypeNames.CALIBRATION_PROFILE),
                    "Limit prompt presentation packs to shadow or review-only until decision-core artifacts are promoted."));
        }
        if (qualifiedCohortSeeds > 0L && (promotedStrategies > 0L || promotedCalibrations > 0L || promotedPromptPatterns > 0L)) {
            recommendations.add(new CrossArtifactPortfolioRecommendation(
                    "DEGRADE_COHORT_PRIORITY_AFTER_ARTIFACT_MATURITY",
                    "Qualified cohort seeds should remain lower priority once promoted learning artifacts exist.",
                    false,
                    List.of(LearningArtifactTypeNames.COHORT_SEED),
                    "Apply cohort seeds only as cold-start support after strategy, calibration, and prompt artifacts."));
        }
        if (promotedStrategies > 0L && promotedCalibrations > 0L) {
            recommendations.add(new CrossArtifactPortfolioRecommendation(
                    "APPLY_STRATEGY_BEFORE_CALIBRATION",
                    "Detection strategies and calibration profiles are both available and should be applied in that order.",
                    false,
                    List.of(LearningArtifactTypeNames.DETECTION_STRATEGY, LearningArtifactTypeNames.CALIBRATION_PROFILE),
                    "Preserve runtime order: detection strategy, then calibration, then prompt presentation, then cohort support."));
        }
        return List.copyOf(recommendations);
    }
    private List<String> buildRuntimeOrder(
            long promotedStrategies,
            long promotedCalibrations,
            long promotedPromptPatterns,
            long qualifiedCohortSeeds) {
        Set<String> order = new LinkedHashSet<>();
        if (promotedStrategies > 0L) {
            order.add(LearningArtifactTypeNames.DETECTION_STRATEGY);
        }
        if (promotedCalibrations > 0L) {
            order.add(LearningArtifactTypeNames.CALIBRATION_PROFILE);
        }
        if (promotedPromptPatterns > 0L) {
            order.add(LearningArtifactTypeNames.PROMPT_PRESENTATION);
        }
        if (qualifiedCohortSeeds > 0L) {
            order.add(LearningArtifactTypeNames.COHORT_SEED);
        }
        return List.copyOf(order);
    }
    private int score(
            long promotedStrategies,
            long promotedCalibrations,
            long promotedPromptPatterns,
            long qualifiedCohortSeeds,
            List<CrossArtifactPortfolioRecommendation> recommendations) {
        int score = 0;
        if (promotedStrategies > 0L) {
            score += 45;
        }
        if (promotedCalibrations > 0L) {
            score += 25;
        }
        if (promotedPromptPatterns > 0L) {
            score += 10;
        }
        if (qualifiedCohortSeeds > 0L) {
            score += 10;
        }
        if (promotedStrategies > 0L && promotedCalibrations > 0L) {
            score += 10;
        }
        score -= (int) recommendations.stream()
                .filter(CrossArtifactPortfolioRecommendation::blocking)
                .count() * 20;
        return Math.max(0, Math.min(100, score));
    }
    private long countPromotedStrategies(DetectionStrategyPackSnapshot snapshot) {
        if (snapshot == null || !snapshot.runtimeReady()) {
            return 0L;
        }
        return snapshot.strategies().stream()
                .filter(item -> item.runtimeEligible() && isPromoted(item.promotionState()))
                .count();
    }
    private long countPromotedCalibrations(CalibrationProfilePackSnapshot snapshot) {
        if (snapshot == null || !snapshot.runtimeReady()) {
            return 0L;
        }
        return snapshot.profiles().stream()
                .filter(item -> item.runtimeEligible() && isPromoted(item.promotionState()))
                .count();
    }
    private long countPromotedPromptPatterns(PromptPresentationPackSnapshot snapshot) {
        if (snapshot == null || !snapshot.runtimeReady()) {
            return 0L;
        }
        return snapshot.patterns().stream()
                .filter(item -> item.runtimeEligible() && isPromoted(item.promotionState()))
                .count();
    }
    private long countQualifiedCohortSeeds(CohortSeedPackSnapshot snapshot) {
        if (snapshot == null) {
            return 0L;
        }
        return snapshot.seedAvailable() && snapshot.seedQualified() ? 1L : 0L;
    }
    private boolean isPromoted(String releaseState) {
        if (!StringUtils.hasText(releaseState)) {
            return false;
        }
        try {
            return LearningArtifactReleaseState.valueOf(releaseState.trim().toUpperCase(Locale.ROOT))
                    == LearningArtifactReleaseState.PROMOTED;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }
    private String resolveTenantId(
            DetectionStrategyPackSnapshot strategyPack,
            CalibrationProfilePackSnapshot calibrationPack,
            PromptPresentationPackSnapshot promptPack,
            CohortSeedPackSnapshot cohortPack) {
        if (strategyPack != null && StringUtils.hasText(strategyPack.tenantId())) {
            return strategyPack.tenantId();
        }
        if (calibrationPack != null && StringUtils.hasText(calibrationPack.tenantId())) {
            return calibrationPack.tenantId();
        }
        if (promptPack != null && StringUtils.hasText(promptPack.tenantId())) {
            return promptPack.tenantId();
        }
        if (cohortPack != null && StringUtils.hasText(cohortPack.tenantId())) {
            return cohortPack.tenantId();
        }
        return null;
    }
}
