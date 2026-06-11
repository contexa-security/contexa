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

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetrics;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Main engine that calculates strategy-family effectiveness from correlated observations.
 */
public class DetectionStrategyLearningService {

    private final StrategyOutcomeJoinService outcomeJoinService;
    private final StrategyFamilyResolver strategyFamilyResolver;

    public DetectionStrategyLearningService(
            StrategyOutcomeJoinService outcomeJoinService,
            StrategyFamilyResolver strategyFamilyResolver) {
        this.outcomeJoinService = Objects.requireNonNull(outcomeJoinService, "outcomeJoinService is required");
        this.strategyFamilyResolver = Objects.requireNonNull(strategyFamilyResolver, "strategyFamilyResolver is required");
    }

    public DetectionStrategyLearningPortfolio evaluate(DetectionStrategyLearningInput input) {
        DetectionStrategyLearningInput safeInput = input == null ? DetectionStrategyLearningInput.empty() : input;
        List<StrategyLearningObservation> joined = outcomeJoinService.join(safeInput);
        if (joined == null || joined.isEmpty()) {
            return DetectionStrategyLearningPortfolio.empty();
        }

        List<ResolvedObservation> resolved = joined.stream()
                .map(this::resolveObservation)
                .toList();

        List<ResolvedObservation> classified = resolved.stream()
                .filter(item -> item.familyResolution().isResolved())
                .toList();
        if (classified.isEmpty()) {
            return new DetectionStrategyLearningPortfolio(
                    joined.size(),
                    0,
                    joined.size(),
                    List.of(),
                    LocalDateTime.now());
        }

        PortfolioBaseline baseline = baseline(classified);
        Map<String, List<ResolvedObservation>> grouped = new LinkedHashMap<>();
        for (ResolvedObservation item : classified) {
            grouped.computeIfAbsent(item.familyResolution().strategyFamily(), ignored -> new ArrayList<>()).add(item);
        }

        List<DetectionStrategyLearningFamilyResult> families = grouped.entrySet().stream()
                .map(entry -> toFamilyResult(entry.getKey(), entry.getValue(), baseline))
                .sorted(Comparator.comparing((DetectionStrategyLearningFamilyResult item) -> item.metrics().localLiftRate()).reversed()
                        .thenComparing(item -> item.metrics().sampleSize(), Comparator.reverseOrder())
                        .thenComparing(DetectionStrategyLearningFamilyResult::strategyFamily))
                .toList();

        return new DetectionStrategyLearningPortfolio(
                joined.size(),
                classified.size(),
                joined.size() - classified.size(),
                families,
                LocalDateTime.now());
    }

    private ResolvedObservation resolveObservation(StrategyLearningObservation observation) {
        StrategyFamilyResolution resolution = strategyFamilyResolver.resolve(observation);
        return new ResolvedObservation(observation, resolution == null ? StrategyFamilyResolution.unresolved() : resolution);
    }

    private DetectionStrategyLearningFamilyResult toFamilyResult(
            String family,
            List<ResolvedObservation> items,
            PortfolioBaseline baseline) {
        long sampleSize = items.size();
        long outcomeEvidenceCount = items.stream().filter(item -> hasOutcome(item.observation())).count();
        long hardNegativeCount = items.stream().filter(item -> isFalsePositive(item.observation())).count();
        long confirmedAttackCount = items.stream().filter(item -> isConfirmedAttack(item.observation())).count();
        long falsePositiveCount = hardNegativeCount;
        long falseNegativeCount = items.stream().filter(item -> isFalseNegative(item.observation())).count();
        long promptAuditLinkedCount = items.stream().filter(item -> item.observation().promptAuditLinked()).count();
        long telemetryLinkedCount = items.stream().filter(item -> item.observation().telemetryLinked()).count();
        long campaignObservationCount = items.stream().filter(item -> item.observation().campaignObserved()).count();

        double outcomeCoverageRate = ratio(outcomeEvidenceCount, sampleSize);
        double hardNegativeCoverage = ratio(hardNegativeCount, sampleSize);
        double confirmedAttackRate = ratio(confirmedAttackCount, sampleSize);
        double falsePositiveRate = ratio(falsePositiveCount, sampleSize);
        double falseNegativeRate = ratio(falseNegativeCount, sampleSize);

        LearningArtifactMetrics metrics = new LearningArtifactMetrics(
                sampleSize,
                outcomeCoverageRate,
                hardNegativeCoverage,
                confirmedAttackRate - baseline.confirmedAttackRate(),
                falsePositiveRate - baseline.falsePositiveRate(),
                falseNegativeRate - baseline.falseNegativeRate());

        return new DetectionStrategyLearningFamilyResult(
                family,
                metrics,
                outcomeEvidenceCount,
                hardNegativeCount,
                confirmedAttackCount,
                falsePositiveCount,
                falseNegativeCount,
                promptAuditLinkedCount,
                telemetryLinkedCount,
                campaignObservationCount,
                buildEvidenceFacts(family, metrics, items, outcomeEvidenceCount, hardNegativeCount, confirmedAttackCount, falsePositiveCount, falseNegativeCount, promptAuditLinkedCount, telemetryLinkedCount, campaignObservationCount));
    }

    private List<String> buildEvidenceFacts(
            String family,
            LearningArtifactMetrics metrics,
            List<ResolvedObservation> items,
            long outcomeEvidenceCount,
            long hardNegativeCount,
            long confirmedAttackCount,
            long falsePositiveCount,
            long falseNegativeCount,
            long promptAuditLinkedCount,
            long telemetryLinkedCount,
            long campaignObservationCount) {
        Set<String> facts = new LinkedHashSet<>();
        facts.add(String.format(Locale.ROOT,
                "Strategy family %s has %d correlated observations with %.2f outcome coverage.",
                family,
                metrics.sampleSize(),
                metrics.outcomeCoverageRate()));
        facts.add(String.format(Locale.ROOT,
                "Confirmed attacks=%d, false positives=%d, false negatives=%d.",
                confirmedAttackCount,
                falsePositiveCount,
                falseNegativeCount));
        facts.add(String.format(Locale.ROOT,
                "Prompt audit linked=%d, telemetry linked=%d, campaign observed=%d, hard negatives=%d.",
                promptAuditLinkedCount,
                telemetryLinkedCount,
                campaignObservationCount,
                hardNegativeCount));
        items.stream()
                .flatMap(item -> item.familyResolution().resolutionFacts().stream())
                .filter(fact -> fact != null && !fact.isBlank())
                .limit(3)
                .forEach(facts::add);
        items.stream()
                .flatMap(item -> item.observation().evidenceFacts().stream())
                .filter(fact -> fact != null && !fact.isBlank())
                .limit(4)
                .forEach(facts::add);
        return List.copyOf(facts);
    }

    private PortfolioBaseline baseline(List<ResolvedObservation> items) {
        long sampleSize = items.size();
        long confirmedAttackCount = items.stream().filter(item -> isConfirmedAttack(item.observation())).count();
        long falsePositiveCount = items.stream().filter(item -> isFalsePositive(item.observation())).count();
        long falseNegativeCount = items.stream().filter(item -> isFalseNegative(item.observation())).count();
        return new PortfolioBaseline(
                ratio(confirmedAttackCount, sampleSize),
                ratio(falsePositiveCount, sampleSize),
                ratio(falseNegativeCount, sampleSize));
    }

    private boolean hasOutcome(StrategyLearningObservation observation) {
        return hasText(observation.outcomeType()) || hasText(observation.finalDisposition()) || hasText(observation.finalAction());
    }

    private boolean isFalsePositive(StrategyLearningObservation observation) {
        return contains(observation.feedbackType(), "FALSE_POSITIVE");
    }

    private boolean isFalseNegative(StrategyLearningObservation observation) {
        return contains(observation.feedbackType(), "FALSE_NEGATIVE");
    }

    private boolean isConfirmedAttack(StrategyLearningObservation observation) {
        return containsAny(observation.finalDisposition(), "CONFIRMED_ATTACK", "COMPROMISED", "MALICIOUS")
                || containsAny(observation.outcomeType(), "CONFIRMED_ATTACK", "INCIDENT_CONFIRMED", "SESSION_TAKEOVER")
                || containsAny(observation.finalAction(), "BLOCK", "LOCK", "TERMINATE");
    }

    private boolean contains(String value, String candidate) {
        return value != null && value.trim().equalsIgnoreCase(candidate);
    }

    private boolean containsAny(String value, String... candidates) {
        if (!hasText(value)) {
            return false;
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        for (String candidate : candidates) {
            if (normalized.contains(candidate)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
    }

    private double ratio(long numerator, long denominator) {
        if (denominator <= 0L) {
            return 0.0d;
        }
        return (double) numerator / (double) denominator;
    }

    private record ResolvedObservation(
            StrategyLearningObservation observation,
            StrategyFamilyResolution familyResolution) {
    }

    private record PortfolioBaseline(
            double confirmedAttackRate,
            double falsePositiveRate,
            double falseNegativeRate) {
    }
}
