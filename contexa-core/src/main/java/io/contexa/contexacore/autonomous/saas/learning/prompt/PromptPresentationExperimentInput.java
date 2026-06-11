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

import io.contexa.contexacore.autonomous.saas.dto.DecisionFeedbackPayload;
import io.contexa.contexacore.autonomous.saas.dto.ModelPerformanceTelemetryPayload;
import io.contexa.contexacore.autonomous.saas.dto.PromptContextAuditPayload;
import io.contexa.contexacore.autonomous.saas.dto.ThreatOutcomePayload;

import java.util.List;

/**
 * Raw experiment input joined only from presentation-safe learning feeds.
 */
public record PromptPresentationExperimentInput(
        List<PromptContextAuditPayload> promptAudits,
        List<DecisionFeedbackPayload> decisionFeedbacks,
        List<ThreatOutcomePayload> threatOutcomes,
        List<ModelPerformanceTelemetryPayload> performanceTelemetry) {

    public PromptPresentationExperimentInput {
        promptAudits = promptAudits == null ? List.of() : List.copyOf(promptAudits);
        decisionFeedbacks = decisionFeedbacks == null ? List.of() : List.copyOf(decisionFeedbacks);
        threatOutcomes = threatOutcomes == null ? List.of() : List.copyOf(threatOutcomes);
        performanceTelemetry = performanceTelemetry == null ? List.of() : List.copyOf(performanceTelemetry);
    }

    public static PromptPresentationExperimentInput empty() {
        return new PromptPresentationExperimentInput(List.of(), List.of(), List.of(), List.of());
    }
}