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

import java.time.LocalDateTime;
import java.util.List;

/**
 * Portfolio summary for prompt presentation experiments.
 */
public record PromptPresentationExperimentPortfolio(
        long promptAuditCount,
        long experimentObservationCount,
        long unclassifiedAuditCount,
        List<PromptPresentationExperimentResult> results,
        LocalDateTime generatedAt) {

    public PromptPresentationExperimentPortfolio {
        promptAuditCount = Math.max(promptAuditCount, 0L);
        experimentObservationCount = Math.max(experimentObservationCount, 0L);
        unclassifiedAuditCount = Math.max(unclassifiedAuditCount, 0L);
        results = results == null ? List.of() : List.copyOf(results);
    }

    public static PromptPresentationExperimentPortfolio empty() {
        return new PromptPresentationExperimentPortfolio(0L, 0L, 0L, List.of(), LocalDateTime.now());
    }
}