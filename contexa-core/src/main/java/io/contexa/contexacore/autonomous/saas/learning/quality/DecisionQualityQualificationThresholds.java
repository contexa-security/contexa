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
package io.contexa.contexacore.autonomous.saas.learning.quality;

/**
 * Default evidence floors for decision-quality profile artifact qualification.
 */
public record DecisionQualityQualificationThresholds(
        long minimumSampleSize,
        long minimumReviewedOutcomeCount,
        double maximumFalsePositiveRate,
        double maximumFalseNegativeRate) {

    public DecisionQualityQualificationThresholds {
        if (minimumSampleSize < 0L) {
            throw new IllegalArgumentException("minimumSampleSize must be >= 0");
        }
        if (minimumReviewedOutcomeCount < 0L) {
            throw new IllegalArgumentException("minimumReviewedOutcomeCount must be >= 0");
        }
        maximumFalsePositiveRate = requireFinite(maximumFalsePositiveRate, "maximumFalsePositiveRate");
        maximumFalseNegativeRate = requireFinite(maximumFalseNegativeRate, "maximumFalseNegativeRate");
    }

    public static DecisionQualityQualificationThresholds defaults() {
        return new DecisionQualityQualificationThresholds(25L, 10L, 0.35d, 0.35d);
    }

    private static double requireFinite(double value, String fieldName) {
        if (!Double.isFinite(value)) {
            throw new IllegalArgumentException(fieldName + " must be finite");
        }
        return value;
    }
}