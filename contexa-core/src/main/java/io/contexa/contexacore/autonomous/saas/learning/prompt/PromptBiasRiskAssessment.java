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

import java.util.List;

/**
 * Bias risk assessment for a single prompt presentation pattern.
 */
public record PromptBiasRiskAssessment(
        PromptBiasRiskState biasRiskState,
        double riskScore,
        double cdcScore,
        double eraScore,
        double suhrScore,
        double reviewerDisagreementRate,
        double omissionLinkedRate,
        double falsePositiveRate,
        double falseNegativeRate,
        List<String> blockingReasons,
        List<String> policyFacts) {

    public PromptBiasRiskAssessment {
        biasRiskState = biasRiskState == null ? PromptBiasRiskState.HIGH : biasRiskState;
        riskScore = finiteOrZero(riskScore);
        cdcScore = finiteOrZero(cdcScore);
        eraScore = finiteOrZero(eraScore);
        suhrScore = finiteOrZero(suhrScore);
        reviewerDisagreementRate = finiteOrZero(reviewerDisagreementRate);
        omissionLinkedRate = finiteOrZero(omissionLinkedRate);
        falsePositiveRate = finiteOrZero(falsePositiveRate);
        falseNegativeRate = finiteOrZero(falseNegativeRate);
        blockingReasons = blockingReasons == null ? List.of() : List.copyOf(blockingReasons);
        policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
    }

    public boolean blocksPromotion() {
        return biasRiskState == PromptBiasRiskState.HIGH;
    }

    private static double finiteOrZero(double value) {
        return Double.isFinite(value) ? value : 0.0d;
    }
}