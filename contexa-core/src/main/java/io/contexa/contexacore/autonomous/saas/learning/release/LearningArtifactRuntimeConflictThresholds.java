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
package io.contexa.contexacore.autonomous.saas.learning.release;
/**
 * Thresholds used by runtime conflict remediation policy.
 */
public record LearningArtifactRuntimeConflictThresholds(
        double reviewOnlyEvidenceCoverageFloor,
        double withdrawFalsePositiveRateThreshold,
        int withdrawRepeatedConflictCount,
        int withdrawOperatorRegressionCount) {
    public LearningArtifactRuntimeConflictThresholds {
        if (!Double.isFinite(reviewOnlyEvidenceCoverageFloor) || reviewOnlyEvidenceCoverageFloor < 0.0d || reviewOnlyEvidenceCoverageFloor > 1.0d) {
            throw new IllegalArgumentException("reviewOnlyEvidenceCoverageFloor must be between 0.0 and 1.0");
        }
        if (!Double.isFinite(withdrawFalsePositiveRateThreshold) || withdrawFalsePositiveRateThreshold < 0.0d || withdrawFalsePositiveRateThreshold > 1.0d) {
            throw new IllegalArgumentException("withdrawFalsePositiveRateThreshold must be between 0.0 and 1.0");
        }
        if (withdrawRepeatedConflictCount < 1) {
            throw new IllegalArgumentException("withdrawRepeatedConflictCount must be at least 1");
        }
        if (withdrawOperatorRegressionCount < 1) {
            throw new IllegalArgumentException("withdrawOperatorRegressionCount must be at least 1");
        }
    }
    public static LearningArtifactRuntimeConflictThresholds defaults() {
        return new LearningArtifactRuntimeConflictThresholds(0.50d, 0.20d, 3, 3);
    }
}
