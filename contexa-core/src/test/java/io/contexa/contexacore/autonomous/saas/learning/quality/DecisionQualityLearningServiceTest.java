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

class DecisionQualityLearningServiceTest {

    @Test
    void groupsResolvedObservationsAndAggregatesPerScenarioClass() {
        ScenarioClassResolver resolver = observation -> {
            String marker = String.valueOf(observation.scenarioSignals().getOrDefault("scenario", ""));
            return switch (marker) {
                case "NEW_DEVICE_POST_MFA_SENSITIVE" -> new ScenarioClassResolution(marker, List.of("MFA followed by sensitive surface jump"));
                case "SESSION_PATH_SIMILARITY_BREAK" -> new ScenarioClassResolution(marker, List.of("Session path similarity collapsed"));
                default -> ScenarioClassResolution.unresolved();
            };
        };
        DecisionBiasAggregator aggregator = (scenarioClass, observations) -> new DecisionBiasAggregationResult(
                observations.size(),
                observations.size() - 1L,
                "SESSION_PATH_SIMILARITY_BREAK".equals(scenarioClass) ? 2L : 1L,
                "SESSION_PATH_SIMILARITY_BREAK".equals(scenarioClass) ? 1L : 0L,
                0.20d,
                0.10d,
                0.12d,
                0.08d,
                List.of("Bias aggregated for " + scenarioClass));

        DecisionQualityLearningService service = new DecisionQualityLearningService(resolver, aggregator);

        DecisionQualityLearningPortfolio portfolio = service.evaluate(new DecisionQualityLearningInput(List.of(
                observation("one", "NEW_DEVICE_POST_MFA_SENSITIVE", "signal one"),
                observation("two", "SESSION_PATH_SIMILARITY_BREAK", "signal two"),
                observation("three", "SESSION_PATH_SIMILARITY_BREAK", "signal three"),
                observation("four", null, "unresolved signal"))));

        assertThat(portfolio.totalObservationCount()).isEqualTo(4L);
        assertThat(portfolio.classifiedObservationCount()).isEqualTo(3L);
        assertThat(portfolio.unclassifiedObservationCount()).isEqualTo(1L);
        assertThat(portfolio.scenarios()).hasSize(2);
        assertThat(portfolio.scenarios().get(0).scenarioClass()).isEqualTo("SESSION_PATH_SIMILARITY_BREAK");
        assertThat(portfolio.scenarios().get(0).biasAggregation().sampleSize()).isEqualTo(2L);
        assertThat(portfolio.scenarios().get(0).evidenceFacts())
                .anyMatch(fact -> fact.contains("Bias aggregated for SESSION_PATH_SIMILARITY_BREAK"))
                .anyMatch(fact -> fact.contains("signal two") || fact.contains("signal three"));
    }

    private DecisionQualityObservation observation(String correlationId, String scenario, String evidenceFact) {
        return new DecisionQualityObservation(
                correlationId,
                "CHALLENGE",
                "ALLOW",
                "FALSE_POSITIVE",
                "OPERATOR_REVIEWED",
                "FALSE_POSITIVE",
                "FALSE_POSITIVE",
                0.74d,
                2,
                true,
                1,
                true,
                List.of("signal"),
                scenario == null ? Map.of() : Map.of("scenario", scenario),
                List.of(evidenceFact));
    }
}
