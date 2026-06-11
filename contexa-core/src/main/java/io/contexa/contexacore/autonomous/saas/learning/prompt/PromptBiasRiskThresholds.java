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

/**
 * Thresholds for prompt presentation bias risk evaluation.
 */
public record PromptBiasRiskThresholds(
        long minimumSampleSize,
        long minimumReviewedOutcomeCount,
        double moderateRiskScoreThreshold,
        double highRiskScoreThreshold,
        double highComponentThreshold,
        double deniedContextNormalizationCap,
        double omittedSectionNormalizationCap,
        double promptBudgetPressureFloor) {

    public PromptBiasRiskThresholds {
        if (minimumSampleSize < 0L) {
            throw new IllegalArgumentException("minimumSampleSize must be >= 0");
        }
        if (minimumReviewedOutcomeCount < 0L) {
            throw new IllegalArgumentException("minimumReviewedOutcomeCount must be >= 0");
        }
        validateUnitInterval("moderateRiskScoreThreshold", moderateRiskScoreThreshold);
        validateUnitInterval("highRiskScoreThreshold", highRiskScoreThreshold);
        validateUnitInterval("highComponentThreshold", highComponentThreshold);
        validatePositive("deniedContextNormalizationCap", deniedContextNormalizationCap);
        validatePositive("omittedSectionNormalizationCap", omittedSectionNormalizationCap);
        validateUnitInterval("promptBudgetPressureFloor", promptBudgetPressureFloor);
        if (highRiskScoreThreshold < moderateRiskScoreThreshold) {
            throw new IllegalArgumentException("highRiskScoreThreshold must be >= moderateRiskScoreThreshold");
        }
        if (highComponentThreshold < moderateRiskScoreThreshold) {
            throw new IllegalArgumentException("highComponentThreshold must be >= moderateRiskScoreThreshold");
        }
    }

    public static PromptBiasRiskThresholds defaults() {
        return new PromptBiasRiskThresholds(4L, 2L, 0.35d, 0.60d, 0.70d, 3.0d, 2.0d, 0.70d);
    }

    private static void validateUnitInterval(String name, double value) {
        if (!Double.isFinite(value) || value < 0.0d || value > 1.0d) {
            throw new IllegalArgumentException(name + " must be a finite value between 0.0 and 1.0");
        }
    }

    private static void validatePositive(String name, double value) {
        if (!Double.isFinite(value) || value <= 0.0d) {
            throw new IllegalArgumentException(name + " must be a finite value > 0.0");
        }
    }
}