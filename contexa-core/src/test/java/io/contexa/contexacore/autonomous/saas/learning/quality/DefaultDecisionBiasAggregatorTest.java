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

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultDecisionBiasAggregatorTest {

    private final DefaultDecisionBiasAggregator aggregator = new DefaultDecisionBiasAggregator();

    @Test
    void calculatesChallengeOverfireBias() {
        DecisionBiasAggregationResult result = aggregator.aggregate("LOW_DIVERSITY_EXPORT_APPROACH", List.of(
                observation("CHALLENGE", "FALSE_POSITIVE", 0.91d),
                observation("CHALLENGE", "BENIGN", 0.88d),
                observation("ALLOW", "ALLOW", 0.73d)));

        assertThat(result.sampleSize()).isEqualTo(3L);
        assertThat(result.operatorReviewedOutcomeCount()).isEqualTo(3L);
        assertThat(result.falsePositiveCount()).isEqualTo(2L);
        assertThat(result.falseNegativeCount()).isZero();
        assertThat(result.challengeOverfireRate()).isEqualTo(1.0d);
        assertThat(result.allowUnderfireRate()).isZero();
        assertThat(result.aggregationFacts()).anyMatch(fact -> fact.contains("Challenge overfire=1.00"));
    }

    @Test
    void calculatesAllowUnderfireBias() {
        DecisionBiasAggregationResult result = aggregator.aggregate("SESSION_PATH_SIMILARITY_BREAK", List.of(
                observation("ALLOW", "CONFIRMED_ATTACK", 0.92d),
                observation("ALLOW", "FALSE_NEGATIVE", 0.84d),
                observation("CHALLENGE", "ALLOW", 0.69d)));

        assertThat(result.falsePositiveCount()).isEqualTo(1L);
        assertThat(result.falseNegativeCount()).isEqualTo(2L);
        assertThat(result.challengeOverfireRate()).isEqualTo(1.0d);
        assertThat(result.allowUnderfireRate()).isEqualTo(1.0d);
        assertThat(result.aggregationFacts()).anyMatch(fact -> fact.contains("Reviewed outcome distribution"));
    }

    private DecisionQualityObservation observation(String action, String reviewedOutcome, double confidence) {
        return new DecisionQualityObservation(
                "corr",
                action,
                action,
                reviewedOutcome,
                reviewedOutcome,
                reviewedOutcome,
                reviewedOutcome,
                confidence,
                2,
                true,
                1,
                true,
                List.of("signal"),
                Map.of(),
                List.of("evidence"));
    }
}
