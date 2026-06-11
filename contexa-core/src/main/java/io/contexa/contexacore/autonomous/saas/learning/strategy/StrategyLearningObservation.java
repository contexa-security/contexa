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

import java.util.List;
import java.util.Map;

/**
 * Correlated observation used by the detection strategy engine.
 */
public record StrategyLearningObservation(
        String correlationId,
        String feedbackType,
        String originalAction,
        String finalAction,
        String outcomeType,
        String finalDisposition,
        Integer aiAnalysisLevel,
        boolean promptAuditLinked,
        int deniedContextCount,
        boolean telemetryLinked,
        double layer1EscalationRate,
        double blockRate,
        double challengeRate,
        boolean campaignObserved,
        List<String> signalKeys,
        Map<String, Object> strategySignals,
        List<String> evidenceFacts) {

    public StrategyLearningObservation {
        signalKeys = signalKeys == null ? List.of() : List.copyOf(signalKeys);
        strategySignals = strategySignals == null ? Map.of() : Map.copyOf(strategySignals);
        evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
    }
}
