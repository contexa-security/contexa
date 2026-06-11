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

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetrics;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultStrategyEvidenceQualificationPolicyTest {

    private final DefaultStrategyEvidenceQualificationPolicy policy = new DefaultStrategyEvidenceQualificationPolicy(
            new StrategyEvidenceQualificationThresholds(8L, 0.60d, 0.10d, 0.05d));

    @Test
    void qualifiesFamilyWhenAllEvidenceFloorsAreSatisfied() {
        StrategyEvidenceQualificationDecision decision = policy.evaluate(familyResult(10L, 0.70d, 0.20d, 0.11d));

        assertThat(decision.qualified()).isTrue();
        assertThat(decision.recommendedReleaseState()).isEqualTo(LearningArtifactReleaseState.SHADOW_READY);
        assertThat(decision.blockingReasons()).isEmpty();
        assertThat(decision.policyFacts()).isNotEmpty();
    }

    @Test
    void keepsFamilyCollectingWhenOutcomeEvidenceCountIsTooLow() {
        StrategyEvidenceQualificationDecision decision = policy.evaluate(familyResult(7L, 0.70d, 0.20d, 0.11d));

        assertThat(decision.qualified()).isFalse();
        assertThat(decision.recommendedReleaseState()).isEqualTo(LearningArtifactReleaseState.COLLECTING);
        assertThat(decision.blockingReasons()).anyMatch(reason -> reason.contains("Outcome evidence count"));
    }

    @Test
    void keepsFamilyCollectingWhenOutcomeCoverageIsTooLow() {
        StrategyEvidenceQualificationDecision decision = policy.evaluate(familyResult(10L, 0.40d, 0.20d, 0.11d));

        assertThat(decision.qualified()).isFalse();
        assertThat(decision.blockingReasons()).anyMatch(reason -> reason.contains("Outcome coverage"));
    }

    @Test
    void keepsFamilyCollectingWhenHardNegativeCoverageIsTooLow() {
        StrategyEvidenceQualificationDecision decision = policy.evaluate(familyResult(10L, 0.70d, 0.05d, 0.11d));

        assertThat(decision.qualified()).isFalse();
        assertThat(decision.blockingReasons()).anyMatch(reason -> reason.contains("Hard-negative coverage"));
    }

    @Test
    void keepsFamilyCollectingWhenLocalLiftIsBelowFloor() {
        StrategyEvidenceQualificationDecision decision = policy.evaluate(familyResult(10L, 0.70d, 0.20d, 0.01d));

        assertThat(decision.qualified()).isFalse();
        assertThat(decision.blockingReasons()).anyMatch(reason -> reason.contains("Local lift"));
    }

    @Test
    void returnsCollectingDecisionWhenFamilyResultIsMissing() {
        StrategyEvidenceQualificationDecision decision = policy.evaluate(null);

        assertThat(decision.qualified()).isFalse();
        assertThat(decision.recommendedReleaseState()).isEqualTo(LearningArtifactReleaseState.COLLECTING);
        assertThat(decision.blockingReasons()).containsExactly("Strategy family result is required.");
    }

    private DetectionStrategyLearningFamilyResult familyResult(
            long outcomeEvidenceCount,
            double outcomeCoverageRate,
            double hardNegativeCoverage,
            double localLiftRate) {
        return new DetectionStrategyLearningFamilyResult(
                "PATH_SEQUENCE_DIVERGENCE",
                new LearningArtifactMetrics(12L, outcomeCoverageRate, hardNegativeCoverage, localLiftRate, 0.02d, -0.04d),
                outcomeEvidenceCount,
                2L,
                4L,
                1L,
                0L,
                5L,
                6L,
                1L,
                List.of("test evidence"));
    }
}
