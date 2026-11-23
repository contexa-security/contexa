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
package io.contexa.contexacore.std.components.prompt.quality;

import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalDouble;
import java.util.function.Function;

/**
 * Compares two measurements rate by rate (plan 3.3): the same cases against each other, by root. For a rate, each
 * root holds the cases both measurements scored; the root is worse, better or unchanged by its own rate. The exact
 * sign test over the roots that differ says whether so many could turn one way by chance; it is the exact test of
 * McNemar when a root is one answer. The verdict:
 * <ul>
 * <li>the same, when the two rates do not differ, or differ by no more than the noise of the rate;</li>
 * <li>worse or better, when the difference is beyond the noise and the sign test rejects chance at the level;</li>
 * <li>undecidable otherwise: nothing is paired, the noise is not measured, or too few roots differ to tell.</li>
 * </ul>
 * Counting changed cases alone would stop the same prompt one time in four to one in two (plan 3.4).
 */
public final class QualityComparator {

    /** Rates that are equal as fractions can differ in the last bits as doubles; this is far below any real width. */
    private static final double ROUNDING = 1e-12;

    private QualityComparator() {
    }

    /**
     * The comparison of every rate. The two measurements must have been taken the same way: the same version of the
     * case set, the same model setting and the same number of runs.
     *
     * @param cases        the cases of the case set
     * @param current      the measurement of the version in use
     * @param candidate    the measurement of the candidate
     * @param basis        the action the rates are counted on
     * @param noise        the noise of the rates
     * @param significance the level of the sign test, such as 0.05
     */
    public static Map<QualityMetric, QualityComparison> compare(Collection<QualityCase> cases,
                                                                QualityMeasurement current,
                                                                QualityMeasurement candidate, QualityActionBasis basis,
                                                                QualityNoise noise, double significance) {
        if (!current.comparableWith(candidate)) {
            throw new IllegalArgumentException("Two measurements are compared only when they share the case set"
                    + " version, the model setting and the number of runs");
        }
        return compare(QualityTally.of(cases, current.answers(), basis),
                QualityTally.of(cases, candidate.answers(), basis), noise, significance);
    }

    /**
     * The comparison of every rate over the cases of each resource class (quality P46): the same comparison, root by
     * root, on the cases of the class alone, with the cases of the class the two versions answer differently. Every
     * class of {@code shown} is there in its order, also when no case has it and so nothing is compared, then the
     * other classes the cases have, by name, and the unclassified last. The noise is the one given.
     *
     * @param resourceOf the resource and class of a case, as the decision rows of the operation take them
     * @param shown      the classes shown even when no case has them
     */
    public static List<QualityResourceClassComparison> compareByResourceClass(
            Collection<QualityCase> cases, QualityMeasurement current, QualityMeasurement candidate,
            QualityActionBasis basis, QualityNoise noise, double significance,
            Function<QualityCase, QualityCaseResource> resourceOf, List<String> shown) {
        if (!current.comparableWith(candidate)) {
            throw new IllegalArgumentException("Two measurements are compared only when they share the case set"
                    + " version, the model setting and the number of runs");
        }
        Map<String, List<QualityCase>> groups = QualityScorer.byResourceClass(cases, resourceOf);
        List<QualityResourceClassComparison> comparisons = new ArrayList<>();
        for (String group : QualityCaseResource.order(shown, groups.keySet())) {
            List<QualityCase> members = groups.getOrDefault(group, List.of());
            int[] roots = QualityResourceClassScore.roots(members);
            if (members.isEmpty()) {
                comparisons.add(new QualityResourceClassComparison(group, 0, 0, 0, Map.of(),
                        QualityCaseChanges.none()));
                continue;
            }
            QualityTally before = QualityTally.of(members, current.answers(), basis);
            QualityTally after = QualityTally.of(members, candidate.answers(), basis);
            comparisons.add(new QualityResourceClassComparison(group, members.size(), roots[0], roots[1],
                    compare(before, after, noise, significance), QualityGateEvaluator.changes(before, after)));
        }
        return comparisons;
    }

    static Map<QualityMetric, QualityComparison> compare(QualityTally current, QualityTally candidate,
                                                         QualityNoise noise, double significance) {
        Map<QualityMetric, QualityComparison> comparisons = new EnumMap<>(QualityMetric.class);
        for (QualityMetric metric : QualityMetric.values()) {
            comparisons.put(metric, compare(metric, current, candidate, noise.width(metric), significance));
        }
        return comparisons;
    }

    static QualityComparison compare(QualityMetric metric, QualityTally current, QualityTally candidate,
                                     OptionalDouble noise, double significance) {
        // Per root: events and trials of the version in use, then of the candidate, over the paired cases.
        Map<String, long[]> roots = new LinkedHashMap<>();
        long[] total = new long[4];
        int pairedCases = 0;
        for (QualityTally.CaseTally before : current.cases()) {
            QualityTally.CaseTally after = candidate.find(before.item().key());
            if (after == null || before.trials(metric) == 0 || after.trials(metric) == 0) {
                continue;
            }
            pairedCases++;
            long[] root = roots.computeIfAbsent(before.item().rootKey(), key -> new long[4]);
            long[] counts = {before.events(metric), before.trials(metric), after.events(metric), after.trials(metric)};
            for (int index = 0; index < 4; index++) {
                root[index] += counts[index];
                total[index] += counts[index];
            }
        }
        double width = noise.isPresent() ? noise.getAsDouble() : Double.NaN;
        if (pairedCases == 0) {
            return new QualityComparison(metric, QualityVerdict.UNDECIDABLE, Double.NaN, Double.NaN, width, 0, 0, 0, 0,
                    1.0, 1.0);
        }
        int worse = 0;
        int better = 0;
        for (long[] root : roots.values()) {
            int turn = harm(metric, root);
            if (turn > 0) {
                worse++;
            }
            else if (turn < 0) {
                better++;
            }
        }
        double currentValue = (double) total[0] / total[1];
        double candidateValue = (double) total[2] / total[3];
        double worseProbability = QualityStatistics.signTestTail(worse, worse + better);
        double betterProbability = QualityStatistics.signTestTail(better, worse + better);
        int turn = harm(metric, total);
        double size = Math.abs(candidateValue - currentValue);
        QualityVerdict verdict;
        if (turn == 0) {
            verdict = QualityVerdict.SAME;
        }
        else if (noise.isEmpty()) {
            verdict = QualityVerdict.UNDECIDABLE;
        }
        else if (size <= width + ROUNDING) {
            verdict = QualityVerdict.SAME;
        }
        else if (turn > 0) {
            verdict = worseProbability <= significance ? QualityVerdict.WORSE : QualityVerdict.UNDECIDABLE;
        }
        else {
            verdict = betterProbability <= significance ? QualityVerdict.BETTER : QualityVerdict.UNDECIDABLE;
        }
        return new QualityComparison(metric, verdict, currentValue, candidateValue, width, pairedCases, roots.size(),
                worse, better, worseProbability, betterProbability);
    }

    /**
     * Which way the candidate's rate lies from that of the version in use: positive when it is worse, negative when
     * better, zero when the two fractions are equal. The fractions are compared exactly, not as doubles.
     */
    private static int harm(QualityMetric metric, long[] counts) {
        int higher = Long.compare(counts[2] * counts[1], counts[0] * counts[3]);
        return metric.lowerIsBetter() ? higher : -higher;
    }
}
