/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.saas.learning.prompt;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Default bias-risk evaluator for prompt presentation experiments.
 */
public class DefaultPromptBiasRiskEvaluator implements PromptBiasRiskEvaluator {

    private final PromptBiasRiskThresholds thresholds;

    public DefaultPromptBiasRiskEvaluator() {
        this(PromptBiasRiskThresholds.defaults());
    }

    public DefaultPromptBiasRiskEvaluator(PromptBiasRiskThresholds thresholds) {
        this.thresholds = Objects.requireNonNull(thresholds, "thresholds is required");
    }

    @Override
    public PromptBiasRiskAssessment evaluate(PromptPresentationExperimentResult result) {
        PromptPresentationExperimentResult safeResult = result == null
                ? new PromptPresentationExperimentResult(null, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0.0d, 0.0d, 0.0d, List.of(), List.of())
                : result;

        long sampleSize = safeResult.sampleSize();
        long reviewedOutcomeCount = safeResult.operatorReviewedOutcomeCount();
        double reviewerDisagreementRate = ratio(safeResult.reviewerDisagreementCount(), sampleSize);
        double omissionLinkedRate = ratio(safeResult.omissionLinkedCount(), sampleSize);
        double falsePositiveRate = ratio(safeResult.falsePositiveOutcomeCount(), sampleSize);
        double falseNegativeRate = ratio(safeResult.falseNegativeOutcomeCount(), sampleSize);
        double normalizedDeniedContext = normalizeAverage(safeResult.averageDeniedContextCount(), thresholds.deniedContextNormalizationCap());
        double normalizedOmittedSections = normalizeAverage(safeResult.averageOmittedSectionCount(), thresholds.omittedSectionNormalizationCap());
        double promptBudgetPressure = pressureScore(safeResult.averagePromptBudgetUtilizationRate(), thresholds.promptBudgetPressureFloor());

        double cdcScore = clamp((reviewerDisagreementRate * 0.55d) + (falsePositiveRate * 0.25d) + (falseNegativeRate * 0.20d));
        double eraScore = clamp((omissionLinkedRate * 0.45d)
                + (normalizedDeniedContext * 0.20d)
                + (normalizedOmittedSections * 0.20d)
                + (promptBudgetPressure * 0.15d));
        double suhrScore = clamp((falseNegativeRate * 0.60d)
                + (omissionLinkedRate * 0.25d)
                + (promptBudgetPressure * 0.15d));
        double riskScore = clamp((cdcScore * 0.35d) + (eraScore * 0.35d) + (suhrScore * 0.30d));

        List<String> blockingReasons = new ArrayList<>();
        if (sampleSize < thresholds.minimumSampleSize()) {
            blockingReasons.add(String.format(Locale.ROOT,
                    "Sample size %d is below the minimum prompt experiment floor %d.",
                    sampleSize,
                    thresholds.minimumSampleSize()));
        }
        if (reviewedOutcomeCount < thresholds.minimumReviewedOutcomeCount()) {
            blockingReasons.add(String.format(Locale.ROOT,
                    "Reviewed outcome count %d is below the minimum bias-review floor %d.",
                    reviewedOutcomeCount,
                    thresholds.minimumReviewedOutcomeCount()));
        }
        if (cdcScore >= thresholds.highComponentThreshold()) {
            blockingReasons.add(String.format(Locale.ROOT,
                    "CDC proxy score %.4f exceeds the high-risk component threshold %.4f.",
                    cdcScore,
                    thresholds.highComponentThreshold()));
        }
        if (eraScore >= thresholds.highComponentThreshold()) {
            blockingReasons.add(String.format(Locale.ROOT,
                    "ERA proxy score %.4f exceeds the high-risk component threshold %.4f.",
                    eraScore,
                    thresholds.highComponentThreshold()));
        }
        if (suhrScore >= thresholds.highComponentThreshold()) {
            blockingReasons.add(String.format(Locale.ROOT,
                    "SUHR proxy score %.4f exceeds the high-risk component threshold %.4f.",
                    suhrScore,
                    thresholds.highComponentThreshold()));
        }
        if (riskScore >= thresholds.highRiskScoreThreshold()) {
            blockingReasons.add(String.format(Locale.ROOT,
                    "Overall prompt bias risk %.4f exceeds the high-risk threshold %.4f.",
                    riskScore,
                    thresholds.highRiskScoreThreshold()));
        }

        PromptBiasRiskState state = determineState(riskScore, cdcScore, eraScore, suhrScore, blockingReasons);
        return new PromptBiasRiskAssessment(
                state,
                riskScore,
                cdcScore,
                eraScore,
                suhrScore,
                reviewerDisagreementRate,
                omissionLinkedRate,
                falsePositiveRate,
                falseNegativeRate,
                List.copyOf(blockingReasons),
                buildPolicyFacts(safeResult, riskScore, cdcScore, eraScore, suhrScore,
                        reviewerDisagreementRate, omissionLinkedRate, falsePositiveRate, falseNegativeRate,
                        normalizedDeniedContext, normalizedOmittedSections, promptBudgetPressure));
    }

    private PromptBiasRiskState determineState(
            double riskScore,
            double cdcScore,
            double eraScore,
            double suhrScore,
            List<String> blockingReasons) {
        if (!blockingReasons.isEmpty()
                || cdcScore >= thresholds.highComponentThreshold()
                || eraScore >= thresholds.highComponentThreshold()
                || suhrScore >= thresholds.highComponentThreshold()
                || riskScore >= thresholds.highRiskScoreThreshold()) {
            return PromptBiasRiskState.HIGH;
        }
        if (riskScore >= thresholds.moderateRiskScoreThreshold()) {
            return PromptBiasRiskState.MODERATE;
        }
        return PromptBiasRiskState.LOW;
    }

    private List<String> buildPolicyFacts(
            PromptPresentationExperimentResult result,
            double riskScore,
            double cdcScore,
            double eraScore,
            double suhrScore,
            double reviewerDisagreementRate,
            double omissionLinkedRate,
            double falsePositiveRate,
            double falseNegativeRate,
            double normalizedDeniedContext,
            double normalizedOmittedSections,
            double promptBudgetPressure) {
        return List.of(
                String.format(Locale.ROOT,
                        "Prompt bias risk evaluates CDC/ERA/SUHR proxies from presentation-safe experiment outputs only; sample=%d, reviewedOutcomes=%d.",
                        result.sampleSize(),
                        result.operatorReviewedOutcomeCount()),
                String.format(Locale.ROOT,
                        "CDC proxy uses reviewer disagreement %.4f, false positive %.4f, false negative %.4f -> %.4f.",
                        reviewerDisagreementRate,
                        falsePositiveRate,
                        falseNegativeRate,
                        cdcScore),
                String.format(Locale.ROOT,
                        "ERA proxy uses omission-linked %.4f, denied-context pressure %.4f, omitted-section pressure %.4f, budget pressure %.4f -> %.4f.",
                        omissionLinkedRate,
                        normalizedDeniedContext,
                        normalizedOmittedSections,
                        promptBudgetPressure,
                        eraScore),
                String.format(Locale.ROOT,
                        "SUHR proxy uses false negative %.4f, omission-linked %.4f, budget pressure %.4f -> %.4f.",
                        falseNegativeRate,
                        omissionLinkedRate,
                        promptBudgetPressure,
                        suhrScore),
                String.format(Locale.ROOT,
                        "Overall bias risk score %.4f is evaluated against moderate %.4f and high %.4f thresholds.",
                        riskScore,
                        thresholds.moderateRiskScoreThreshold(),
                        thresholds.highRiskScoreThreshold()));
    }

    private double ratio(long numerator, long denominator) {
        if (denominator <= 0L) {
            return 0.0d;
        }
        return (double) numerator / (double) denominator;
    }

    private double normalizeAverage(double value, double cap) {
        if (!Double.isFinite(value) || value <= 0.0d) {
            return 0.0d;
        }
        return clamp(Math.min(value, cap) / cap);
    }

    private double pressureScore(double averageBudgetUtilizationRate, double floor) {
        if (!Double.isFinite(averageBudgetUtilizationRate) || averageBudgetUtilizationRate <= floor) {
            return 0.0d;
        }
        return clamp((averageBudgetUtilizationRate - floor) / Math.max(0.0001d, 1.0d - floor));
    }

    private double clamp(double value) {
        if (!Double.isFinite(value)) {
            return 0.0d;
        }
        return Math.max(0.0d, Math.min(1.0d, value));
    }
}