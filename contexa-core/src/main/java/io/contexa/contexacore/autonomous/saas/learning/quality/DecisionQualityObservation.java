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

import java.util.List;
import java.util.Map;

/**
 * Correlated observation used by the decision-quality learning engine.
 */
public record DecisionQualityObservation(
        String correlationId,
        String originalAction,
        String finalAction,
        String feedbackType,
        String outcomeType,
        String finalDisposition,
        String operatorReviewedOutcome,
        Double decisionConfidence,
        Integer aiAnalysisLevel,
        boolean promptAuditLinked,
        int deniedContextCount,
        boolean telemetryLinked,
        List<String> signalKeys,
        Map<String, Object> scenarioSignals,
        List<String> evidenceFacts) {

    public DecisionQualityObservation {
        signalKeys = signalKeys == null ? List.of() : List.copyOf(signalKeys);
        scenarioSignals = scenarioSignals == null ? Map.of() : Map.copyOf(scenarioSignals);
        evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
    }
}
