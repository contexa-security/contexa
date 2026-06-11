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

import java.time.LocalDateTime;
import java.util.List;

/**
 * Portfolio result for decision-quality learning.
 */
public record DecisionQualityLearningPortfolio(
        long totalObservationCount,
        long classifiedObservationCount,
        long unclassifiedObservationCount,
        List<DecisionQualityScenarioResult> scenarios,
        LocalDateTime evaluatedAt) {

    public DecisionQualityLearningPortfolio {
        if (totalObservationCount < 0L) {
            throw new IllegalArgumentException("totalObservationCount must be >= 0");
        }
        if (classifiedObservationCount < 0L) {
            throw new IllegalArgumentException("classifiedObservationCount must be >= 0");
        }
        if (unclassifiedObservationCount < 0L) {
            throw new IllegalArgumentException("unclassifiedObservationCount must be >= 0");
        }
        scenarios = scenarios == null ? List.of() : List.copyOf(scenarios);
        evaluatedAt = evaluatedAt == null ? LocalDateTime.now() : evaluatedAt;
    }

    public static DecisionQualityLearningPortfolio empty() {
        return new DecisionQualityLearningPortfolio(0L, 0L, 0L, List.of(), LocalDateTime.now());
    }
}
