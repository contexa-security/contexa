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
package io.contexa.contexacore.autonomous.saas.learning.roi;
/**
 * Cost model used to estimate artifact ROI.
 */
public record LearningRoiCostModel(
        double operatingCostPerAdoptedTenant,
        double detectionLiftValuePerUnit,
        double falsePositiveCostPerUnit,
        double rollbackPenaltyPerEvent) {
    public LearningRoiCostModel {
        validateFinite(operatingCostPerAdoptedTenant, "operatingCostPerAdoptedTenant");
        validateFinite(detectionLiftValuePerUnit, "detectionLiftValuePerUnit");
        validateFinite(falsePositiveCostPerUnit, "falsePositiveCostPerUnit");
        validateFinite(rollbackPenaltyPerEvent, "rollbackPenaltyPerEvent");
    }
    public static LearningRoiCostModel defaults() {
        return new LearningRoiCostModel(5.0d, 100.0d, 80.0d, 50.0d);
    }
    private void validateFinite(double value, String fieldName) {
        if (!Double.isFinite(value) || value < 0.0d) {
            throw new IllegalArgumentException(fieldName + " must be finite and non-negative");
        }
    }
}
