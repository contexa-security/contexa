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
package io.contexa.contexacore.autonomous.saas.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.LocalDateTime;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record PromptPresentationPackSnapshot(
        String tenantId,
        boolean featureEnabled,
        boolean sharingEnabled,
        boolean runtimeReady,
        String promotionState,
        long promotedPatternCount,
        long candidatePatternCount,
        long blockedPatternCount,
        List<PatternItem> patterns,
        LocalDateTime generatedAt) {

    public PromptPresentationPackSnapshot {
        patterns = patterns == null ? List.of() : List.copyOf(patterns);
    }

    public static PromptPresentationPackSnapshot empty() {
        return new PromptPresentationPackSnapshot(null, false, false, false, "DISABLED", 0L, 0L, 0L, List.of(), null);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record PatternItem(
            String presentationPatternKey,
            String presentationPatternVersion,
            List<String> supportedPromptFamilies,
            List<String> supportedModelFamilies,
            MeasuredDelta measuredDelta,
            String biasRiskState,
            String supportedContextCoverageBand,
            boolean runtimeEligible,
            String promotionState,
            List<String> guardrails,
            List<String> evidenceFacts,
            List<String> policyFacts) {

        public PatternItem {
            supportedPromptFamilies = supportedPromptFamilies == null ? List.of() : List.copyOf(supportedPromptFamilies);
            supportedModelFamilies = supportedModelFamilies == null ? List.of() : List.copyOf(supportedModelFamilies);
            guardrails = guardrails == null ? List.of() : List.copyOf(guardrails);
            evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
            policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record MeasuredDelta(
            long sampleSize,
            long operatorReviewedOutcomeCount,
            double reviewerDisagreementRate,
            double falsePositiveRate,
            double falseNegativeRate,
            double omissionLinkedRate,
            double averagePromptBudgetUtilizationRate) {
    }
}