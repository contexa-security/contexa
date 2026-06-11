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

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Conservative transfer gate that blocks unsafe cross-tenant artifact sharing.
 */
public class CrossTenantTransferEligibilityService {

    public ArtifactTransferRiskAssessment assess(ArtifactTransferEligibilityInput input) {
        ArtifactTransferEligibilityInput safeInput = input == null
                ? ArtifactTransferEligibilityInput.permissive(null, null, 0L, 0L, 0.0d, 0.0d, 0.0d)
                : input;
        List<String> policyFacts = new ArrayList<>();
        policyFacts.add(String.format(
                Locale.ROOT,
                "candidateCount=%d sampleSize=%d outcomeCoverage=%.4f hardNegativeCoverage=%.4f localLift=%.4f similarityScore=%.4f rollbackCount=%d runtimeConflictCount=%d.",
                safeInput.candidateCount(),
                safeInput.sampleSize(),
                safeInput.outcomeCoverageRate(),
                safeInput.hardNegativeCoverage(),
                safeInput.localLiftRate(),
                safeInput.similarityScore(),
                safeInput.rollbackCount(),
                safeInput.runtimeConflictCount()));
        if (!safeInput.capabilityAligned() || safeInput.similarityScore() < 0.45d) {
            policyFacts.add("Cross-tenant capability alignment or similarity floor failed.");
            return new ArtifactTransferRiskAssessment(false, ArtifactTransferRiskLevel.HIGH, true, policyFacts);
        }
        if (safeInput.rollbackCount() > 0 || safeInput.runtimeConflictCount() > 1) {
            policyFacts.add("Prior rollback or repeated runtime conflict requires transfer quarantine.");
            return new ArtifactTransferRiskAssessment(false, ArtifactTransferRiskLevel.HIGH, true, policyFacts);
        }
        if (safeInput.sampleSize() < 20L
                || safeInput.outcomeCoverageRate() < 0.60d
                || safeInput.localLiftRate() < 0.03d) {
            policyFacts.add("Evidence floor is not strong enough for safe cross-tenant sharing.");
            return new ArtifactTransferRiskAssessment(false, ArtifactTransferRiskLevel.MODERATE, false, policyFacts);
        }
        if (safeInput.hardNegativeCoverage() < 0.05d || safeInput.similarityScore() < 0.65d) {
            policyFacts.add("Evidence is usable but still below the low-risk transfer band.");
            return new ArtifactTransferRiskAssessment(false, ArtifactTransferRiskLevel.MODERATE, false, policyFacts);
        }
        policyFacts.add("Cross-tenant transfer gate passed with low observed transfer risk.");
        return new ArtifactTransferRiskAssessment(true, ArtifactTransferRiskLevel.LOW, false, policyFacts);
    }
}