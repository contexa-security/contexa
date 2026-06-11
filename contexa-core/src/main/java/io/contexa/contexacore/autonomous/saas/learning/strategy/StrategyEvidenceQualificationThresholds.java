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
package io.contexa.contexacore.autonomous.saas.learning.strategy;

import java.util.Objects;

/**
 * Qualification floors that a detection strategy family must satisfy before artifact promotion.
 */
public record StrategyEvidenceQualificationThresholds(
        long minimumEvidenceCount,
        double minimumOutcomeCoverageRate,
        double minimumHardNegativeCoverageRate,
        double minimumLocalLiftRate) {

    public StrategyEvidenceQualificationThresholds {
        if (minimumEvidenceCount < 0L) {
            throw new IllegalArgumentException("minimumEvidenceCount must be >= 0");
        }
        validateRate("minimumOutcomeCoverageRate", minimumOutcomeCoverageRate);
        validateRate("minimumHardNegativeCoverageRate", minimumHardNegativeCoverageRate);
        if (!Double.isFinite(minimumLocalLiftRate)) {
            throw new IllegalArgumentException("minimumLocalLiftRate must be finite");
        }
    }

    public static StrategyEvidenceQualificationThresholds defaults() {
        return new StrategyEvidenceQualificationThresholds(25L, 0.60d, 0.05d, 0.03d);
    }

    private static void validateRate(String fieldName, double value) {
        if (!Double.isFinite(value) || value < 0.0d || value > 1.0d) {
            throw new IllegalArgumentException(fieldName + " must be between 0.0 and 1.0");
        }
    }
}
