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
package io.contexa.contexacore.autonomous.saas.learning.prompt;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultPromptBiasRiskEvaluatorTest {

    private final DefaultPromptBiasRiskEvaluator evaluator = new DefaultPromptBiasRiskEvaluator();

    @Test
    void returnsHighRiskWhenPromptPatternShowsStrongBiasSignals() {
        PromptPresentationExperimentResult result = new PromptPresentationExperimentResult(
                new PromptPresentationPatternProfile(
                        "pattern-a",
                        "security-decision",
                        "standard",
                        "v1",
                        "CONDENSED",
                        true,
                        "PARTIAL",
                        List.of("summary", "evidence"),
                        List.of("narrative")),
                10L,
                6L,
                5L,
                1L,
                4L,
                8L,
                10L,
                2.6d,
                1.8d,
                0.94d,
                List.of("experiment fact"),
                List.of("policy fact"));

        PromptBiasRiskAssessment assessment = evaluator.evaluate(result);

        assertThat(assessment.biasRiskState()).isEqualTo(PromptBiasRiskState.HIGH);
        assertThat(assessment.blocksPromotion()).isTrue();
        assertThat(assessment.cdcScore()).isGreaterThanOrEqualTo(0.30d);
        assertThat(assessment.eraScore()).isGreaterThanOrEqualTo(0.70d);
        assertThat(assessment.suhrScore()).isGreaterThanOrEqualTo(0.30d);
        assertThat(assessment.blockingReasons()).isNotEmpty();
        assertThat(assessment.policyFacts()).anyMatch(text -> text.contains("CDC proxy"));
        assertThat(assessment.policyFacts()).anyMatch(text -> text.contains("ERA proxy"));
        assertThat(assessment.policyFacts()).anyMatch(text -> text.contains("SUHR proxy"));
    }

    @Test
    void returnsLowRiskWhenPresentationPatternHasLowDisagreementAndLowOmissionPressure() {
        PromptPresentationExperimentResult result = new PromptPresentationExperimentResult(
                new PromptPresentationPatternProfile(
                        "pattern-b",
                        "security-decision",
                        "standard",
                        "v2",
                        "STRUCTURED",
                        false,
                        "COMPLETE",
                        List.of("summary", "evidence", "policy"),
                        List.of()),
                12L,
                6L,
                0L,
                0L,
                0L,
                1L,
                12L,
                0.2d,
                0.0d,
                0.48d,
                List.of("experiment fact"),
                List.of("policy fact"));

        PromptBiasRiskAssessment assessment = evaluator.evaluate(result);

        assertThat(assessment.biasRiskState()).isEqualTo(PromptBiasRiskState.LOW);
        assertThat(assessment.blocksPromotion()).isFalse();
        assertThat(assessment.riskScore()).isLessThan(0.35d);
        assertThat(assessment.blockingReasons()).isEmpty();
    }

    @Test
    void returnsHighRiskWhenReviewedOutcomesAreInsufficient() {
        PromptPresentationExperimentResult result = new PromptPresentationExperimentResult(
                PromptPresentationPatternProfile.unclassified(),
                5L,
                1L,
                0L,
                0L,
                0L,
                0L,
                0L,
                0.0d,
                0.0d,
                0.30d,
                List.of(),
                List.of());

        PromptBiasRiskAssessment assessment = evaluator.evaluate(result);

        assertThat(assessment.biasRiskState()).isEqualTo(PromptBiasRiskState.HIGH);
        assertThat(assessment.blockingReasons()).anyMatch(text -> text.contains("Reviewed outcome count 1 is below the minimum bias-review floor 2."));
    }
}