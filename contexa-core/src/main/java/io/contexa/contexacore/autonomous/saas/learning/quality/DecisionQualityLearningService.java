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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Main engine that calculates scenario-class bias from correlated observations.
 */
public class DecisionQualityLearningService {

    private final ScenarioClassResolver scenarioClassResolver;
    private final DecisionBiasAggregator decisionBiasAggregator;

    public DecisionQualityLearningService(
            ScenarioClassResolver scenarioClassResolver,
            DecisionBiasAggregator decisionBiasAggregator) {
        this.scenarioClassResolver = Objects.requireNonNull(scenarioClassResolver, "scenarioClassResolver is required");
        this.decisionBiasAggregator = Objects.requireNonNull(decisionBiasAggregator, "decisionBiasAggregator is required");
    }

    public DecisionQualityLearningPortfolio evaluate(DecisionQualityLearningInput input) {
        DecisionQualityLearningInput safeInput = input == null ? DecisionQualityLearningInput.empty() : input;
        List<DecisionQualityObservation> observations = safeInput.observations();
        if (observations.isEmpty()) {
            return DecisionQualityLearningPortfolio.empty();
        }

        List<ResolvedObservation> resolved = observations.stream()
                .map(this::resolveObservation)
                .toList();

        List<ResolvedObservation> classified = resolved.stream()
                .filter(item -> item.scenarioClassResolution().isResolved())
                .toList();
        if (classified.isEmpty()) {
            return new DecisionQualityLearningPortfolio(
                    observations.size(),
                    0,
                    observations.size(),
                    List.of(),
                    LocalDateTime.now());
        }

        Map<String, List<ResolvedObservation>> grouped = new LinkedHashMap<>();
        for (ResolvedObservation item : classified) {
            grouped.computeIfAbsent(item.scenarioClassResolution().scenarioClass(), ignored -> new ArrayList<>()).add(item);
        }

        List<DecisionQualityScenarioResult> scenarios = grouped.entrySet().stream()
                .map(entry -> toScenarioResult(entry.getKey(), entry.getValue()))
                .sorted(Comparator.comparing((DecisionQualityScenarioResult item) -> item.biasAggregation().sampleSize()).reversed()
                        .thenComparing(DecisionQualityScenarioResult::scenarioClass))
                .toList();

        return new DecisionQualityLearningPortfolio(
                observations.size(),
                classified.size(),
                observations.size() - classified.size(),
                scenarios,
                LocalDateTime.now());
    }

    private ResolvedObservation resolveObservation(DecisionQualityObservation observation) {
        ScenarioClassResolution resolution = scenarioClassResolver.resolve(observation);
        return new ResolvedObservation(observation, resolution == null ? ScenarioClassResolution.unresolved() : resolution);
    }

    private DecisionQualityScenarioResult toScenarioResult(
            String scenarioClass,
            List<ResolvedObservation> observations) {
        List<DecisionQualityObservation> rawObservations = observations.stream()
                .map(ResolvedObservation::observation)
                .toList();
        DecisionBiasAggregationResult aggregation = decisionBiasAggregator.aggregate(scenarioClass, rawObservations);
        DecisionBiasAggregationResult safeAggregation = aggregation == null
                ? DecisionBiasAggregationResult.empty()
                : aggregation;
        return new DecisionQualityScenarioResult(
                scenarioClass,
                safeAggregation,
                buildEvidenceFacts(scenarioClass, observations, safeAggregation));
    }

    private List<String> buildEvidenceFacts(
            String scenarioClass,
            List<ResolvedObservation> observations,
            DecisionBiasAggregationResult aggregation) {
        Set<String> facts = new LinkedHashSet<>();
        facts.add("Scenario class " + scenarioClass + " has " + aggregation.sampleSize() + " correlated observations.");
        facts.add("Operator-reviewed outcomes=" + aggregation.operatorReviewedOutcomeCount()
                + ", false positives=" + aggregation.falsePositiveCount()
                + ", false negatives=" + aggregation.falseNegativeCount() + ".");
        observations.stream()
                .flatMap(item -> item.scenarioClassResolution().resolutionFacts().stream())
                .filter(this::hasText)
                .limit(3)
                .forEach(facts::add);
        aggregation.aggregationFacts().stream()
                .filter(this::hasText)
                .limit(4)
                .forEach(facts::add);
        observations.stream()
                .flatMap(item -> item.observation().evidenceFacts().stream())
                .filter(this::hasText)
                .limit(4)
                .forEach(facts::add);
        return List.copyOf(facts);
    }

    private boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
    }

    private record ResolvedObservation(
            DecisionQualityObservation observation,
            ScenarioClassResolution scenarioClassResolution) {
    }
}
