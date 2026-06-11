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
import java.util.List;
/**
 * Input signal set for resolving a runtime artifact conflict.
 */
public record LearningArtifactRuntimeConflictInput(
        boolean localTruthOverrode,
        boolean localBaselineEstablished,
        boolean promptBiasRiskHigh,
        double evidenceCoverageRate,
        double falsePositiveRegressionRate,
        int repeatedConflictCount,
        int operatorRegressionCount,
        String reason,
        List<String> facts) {
    public LearningArtifactRuntimeConflictInput {
        evidenceCoverageRate = Double.isFinite(evidenceCoverageRate)
                ? Math.max(0.0d, Math.min(1.0d, evidenceCoverageRate))
                : 0.0d;
        falsePositiveRegressionRate = Double.isFinite(falsePositiveRegressionRate)
                ? Math.max(0.0d, Math.min(1.0d, falsePositiveRegressionRate))
                : 0.0d;
        repeatedConflictCount = Math.max(0, repeatedConflictCount);
        operatorRegressionCount = Math.max(0, operatorRegressionCount);
        facts = facts == null ? List.of() : List.copyOf(facts);
    }
}
