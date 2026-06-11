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
package io.contexa.contexacore.autonomous.saas.learning.transfer;

/**
 * Evidence and environment summary used to decide whether cross-tenant sharing is safe.
 */
public record ArtifactTransferEligibilityInput(
        String tenantId,
        String artifactType,
        long candidateCount,
        long sampleSize,
        double outcomeCoverageRate,
        double hardNegativeCoverage,
        double localLiftRate,
        double similarityScore,
        boolean capabilityAligned,
        int rollbackCount,
        int runtimeConflictCount) {

    public ArtifactTransferEligibilityInput {
        tenantId = tenantId == null ? null : tenantId.trim();
        artifactType = artifactType == null ? null : artifactType.trim();
        candidateCount = Math.max(candidateCount, 0L);
        sampleSize = Math.max(sampleSize, 0L);
        outcomeCoverageRate = requireFinite(outcomeCoverageRate, "outcomeCoverageRate");
        hardNegativeCoverage = requireFinite(hardNegativeCoverage, "hardNegativeCoverage");
        localLiftRate = requireFinite(localLiftRate, "localLiftRate");
        similarityScore = requireFinite(similarityScore, "similarityScore");
        rollbackCount = Math.max(rollbackCount, 0);
        runtimeConflictCount = Math.max(runtimeConflictCount, 0);
    }

    public static ArtifactTransferEligibilityInput permissive(
            String tenantId,
            String artifactType,
            long candidateCount,
            long sampleSize,
            double outcomeCoverageRate,
            double hardNegativeCoverage,
            double localLiftRate) {
        return new ArtifactTransferEligibilityInput(
                tenantId,
                artifactType,
                candidateCount,
                sampleSize,
                outcomeCoverageRate,
                hardNegativeCoverage,
                localLiftRate,
                1.0d,
                true,
                0,
                0);
    }

    private static double requireFinite(double value, String fieldName) {
        if (!Double.isFinite(value)) {
            throw new IllegalArgumentException(fieldName + " must be finite");
        }
        return value;
    }
}