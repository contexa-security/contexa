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
 * Correlated observation used for prompt presentation experiments.
 */
public record PromptPresentationObservation(
        String correlationId,
        PromptPresentationPatternProfile patternProfile,
        boolean promptRuntimeTelemetryLinked,
        boolean modelPerformanceTelemetryLinked,
        boolean operatorReviewedOutcome,
        boolean reviewerDisagreement,
        boolean falsePositiveOutcome,
        boolean falseNegativeOutcome,
        int deniedContextCount,
        int omittedSectionCount,
        int promptOmissionCount,
        double promptBudgetUtilizationRate,
        List<String> evidenceFacts) {

    public PromptPresentationObservation {
        patternProfile = patternProfile == null ? PromptPresentationPatternProfile.unclassified() : patternProfile;
        deniedContextCount = Math.max(deniedContextCount, 0);
        omittedSectionCount = Math.max(omittedSectionCount, 0);
        promptOmissionCount = Math.max(promptOmissionCount, 0);
        promptBudgetUtilizationRate = Double.isFinite(promptBudgetUtilizationRate) ? promptBudgetUtilizationRate : 0.0d;
        evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
    }
}