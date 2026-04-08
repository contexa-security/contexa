package io.contexa.contexacore.autonomous.saas.learning.calibration;

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
public class CalibrationProfileLearningService {

    private final ScenarioClassResolver scenarioClassResolver;
    private final DecisionBiasAggregator decisionBiasAggregator;

    public CalibrationProfileLearningService(
            ScenarioClassResolver scenarioClassResolver,
            DecisionBiasAggregator decisionBiasAggregator) {
        this.scenarioClassResolver = Objects.requireNonNull(scenarioClassResolver, "scenarioClassResolver is required");
        this.decisionBiasAggregator = Objects.requireNonNull(decisionBiasAggregator, "decisionBiasAggregator is required");
    }

    public CalibrationProfileLearningPortfolio evaluate(CalibrationProfileLearningInput input) {
        CalibrationProfileLearningInput safeInput = input == null ? CalibrationProfileLearningInput.empty() : input;
        List<CalibrationLearningObservation> observations = safeInput.observations();
        if (observations.isEmpty()) {
            return CalibrationProfileLearningPortfolio.empty();
        }

        List<ResolvedObservation> resolved = observations.stream()
                .map(this::resolveObservation)
                .toList();

        List<ResolvedObservation> classified = resolved.stream()
                .filter(item -> item.scenarioClassResolution().isResolved())
                .toList();
        if (classified.isEmpty()) {
            return new CalibrationProfileLearningPortfolio(
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

        List<CalibrationProfileLearningScenarioResult> scenarios = grouped.entrySet().stream()
                .map(entry -> toScenarioResult(entry.getKey(), entry.getValue()))
                .sorted(Comparator.comparing((CalibrationProfileLearningScenarioResult item) -> item.biasAggregation().sampleSize()).reversed()
                        .thenComparing(CalibrationProfileLearningScenarioResult::scenarioClass))
                .toList();

        return new CalibrationProfileLearningPortfolio(
                observations.size(),
                classified.size(),
                observations.size() - classified.size(),
                scenarios,
                LocalDateTime.now());
    }

    private ResolvedObservation resolveObservation(CalibrationLearningObservation observation) {
        ScenarioClassResolution resolution = scenarioClassResolver.resolve(observation);
        return new ResolvedObservation(observation, resolution == null ? ScenarioClassResolution.unresolved() : resolution);
    }

    private CalibrationProfileLearningScenarioResult toScenarioResult(
            String scenarioClass,
            List<ResolvedObservation> observations) {
        List<CalibrationLearningObservation> rawObservations = observations.stream()
                .map(ResolvedObservation::observation)
                .toList();
        DecisionBiasAggregationResult aggregation = decisionBiasAggregator.aggregate(scenarioClass, rawObservations);
        DecisionBiasAggregationResult safeAggregation = aggregation == null
                ? DecisionBiasAggregationResult.empty()
                : aggregation;
        return new CalibrationProfileLearningScenarioResult(
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
        facts.add("Recommended action bias=" + aggregation.recommendedActionBias()
                + ", confidence adjustment=" + aggregation.recommendedConfidenceAdjustment() + ".");
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
            CalibrationLearningObservation observation,
            ScenarioClassResolution scenarioClassResolution) {
    }
}
