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
package io.contexa.contexacore.autonomous.saas.learning.cohort;

/**
 * Thresholds for cohort seed qualification.
 */
public record CohortSeedQualificationThresholds(
        int minimumCohortTenantCount,
        long minimumSampleUserBaselineCount,
        long minimumEarlyAssessmentSampleCount,
        double minimumEarlyQualityImprovementDelta,
        int strongCohortTenantCount,
        long strongSampleUserBaselineCount,
        double strongEarlyQualityImprovementDelta) {

    public CohortSeedQualificationThresholds {
        if (minimumCohortTenantCount < 0) {
            throw new IllegalArgumentException("minimumCohortTenantCount must be >= 0");
        }
        if (minimumSampleUserBaselineCount < 0L) {
            throw new IllegalArgumentException("minimumSampleUserBaselineCount must be >= 0");
        }
        if (minimumEarlyAssessmentSampleCount < 0L) {
            throw new IllegalArgumentException("minimumEarlyAssessmentSampleCount must be >= 0");
        }
        if (!Double.isFinite(minimumEarlyQualityImprovementDelta)) {
            throw new IllegalArgumentException("minimumEarlyQualityImprovementDelta must be finite");
        }
        if (strongCohortTenantCount < minimumCohortTenantCount) {
            throw new IllegalArgumentException("strongCohortTenantCount must be >= minimumCohortTenantCount");
        }
        if (strongSampleUserBaselineCount < minimumSampleUserBaselineCount) {
            throw new IllegalArgumentException("strongSampleUserBaselineCount must be >= minimumSampleUserBaselineCount");
        }
        if (!Double.isFinite(strongEarlyQualityImprovementDelta)
                || strongEarlyQualityImprovementDelta < minimumEarlyQualityImprovementDelta) {
            throw new IllegalArgumentException("strongEarlyQualityImprovementDelta must be finite and >= minimumEarlyQualityImprovementDelta");
        }
    }

    public static CohortSeedQualificationThresholds defaults() {
        return new CohortSeedQualificationThresholds(5, 100L, 20L, 5.0d, 12, 250L, 10.0d);
    }
}