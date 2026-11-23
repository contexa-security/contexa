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
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Plan 3.6: a version measured again on schedule, or after the model setting changed, against its measurement before.
 * The two may differ in the model setting or in the published case set (new cases, a changed answer), so they are not
 * taken the same way the gate asks for. The comparison pairs the cases both sets hold with the same content, and reads
 * the cases the later set adds on their own:
 *
 * <ul>
 * <li>Worse: the paired comparison of a rate the gate rests on says worse (plan 3.3: beyond the noise, confirmed by the
 * exact test), or a case that may not fail once now fails (a case that must be caught allowed, a case that must not be
 * blocked blocked) where it did not before.</li>
 * <li>Changed: nothing is shown worse, but the version newly misses or newly stops a paired case, a rate it rests on
 * moved the harmful way without a verdict (the noise is not measured, or too few roots differ), or it misses or stops
 * a case the later set adds.</li>
 * <li>The same: none of these.</li>
 * <li>Not compared: there is no measurement before, or one of the two has no scored answer.</li>
 * </ul>
 * The rates of each over its whole set are kept beside, as numerator and denominator. The first answers are read, as
 * the gate reads them.
 *
 * @param comparisons       the paired comparison of every rate over the shared cases
 * @param previousRates     the rates of the measurement before over its whole set
 * @param laterRates        the rates of the later measurement over its whole set
 * @param sharedCases       the cases both sets hold with the same content
 * @param addedCases        the cases the later set adds, or holds with another content
 * @param changes           the shared cases newly missed, caught, stopped and released
 * @param addedMissed       the added cases that must be stopped which the later measurement allowed in a run
 * @param addedStopped      the added cases that must be allowed which the later measurement did not allow in a run
 * @param newlyFailedGraded the cases that may not fail once which fail in the later measurement and did not before
 */
public record QualityRemeasureComparison(Verdict verdict, Map<QualityMetric, QualityComparison> comparisons,
                                         Map<QualityMetric, QualityRate> previousRates,
                                         Map<QualityMetric, QualityRate> laterRates, int sharedCases, int addedCases,
                                         QualityCaseChanges changes, List<String> addedMissed,
                                         List<String> addedStopped, List<String> newlyFailedGraded) {

    /** What the later measurement came to against the one before. */
    public enum Verdict {
        WORSE, CHANGED, SAME, NOT_COMPARED
    }

    private static final QualityActionBasis BASIS = QualityActionBasis.FIRST_ANSWER;

    /** The rates the gate rests on (plan 3.4). */
    static final List<QualityMetric> GATED = List.of(QualityMetric.MISS, QualityMetric.FALSE_STOP,
            QualityMetric.OVER_BLOCK, QualityMetric.FRICTION, QualityMetric.DEFERRAL,
            QualityMetric.CITATION_ACCURACY);

    public QualityRemeasureComparison {
        Objects.requireNonNull(verdict, "verdict");
        comparisons = copy(comparisons);
        previousRates = copy(previousRates);
        laterRates = copy(laterRates);
        addedMissed = List.copyOf(addedMissed);
        addedStopped = List.copyOf(addedStopped);
        newlyFailedGraded = List.copyOf(newlyFailedGraded);
    }

    /** Nothing to compare with. */
    public static QualityRemeasureComparison notCompared() {
        return new QualityRemeasureComparison(Verdict.NOT_COMPARED, Map.of(), Map.of(), Map.of(), 0, 0,
                QualityCaseChanges.none(), List.of(), List.of(), List.of());
    }

    /**
     * @param previousCases the cases of the set the measurement before ran on, as they read now
     * @param previous      the measurement before, or null when there is none
     * @param laterCases    the cases of the set the later measurement ran on
     * @param later         the later measurement
     * @param noise         the noise of the rates; unknown makes every difference undecidable
     * @param significance  the level of the exact test, such as 0.05
     */
    public static QualityRemeasureComparison compare(Collection<QualityCase> previousCases, QualityMeasurement previous,
                                                     Collection<QualityCase> laterCases, QualityMeasurement later,
                                                     QualityNoise noise, double significance) {
        if (previous == null || later == null) {
            return notCompared();
        }
        Map<String, String> previousHashes = new HashMap<>();
        previousCases.forEach(item -> previousHashes.put(item.key(), item.contentHash()));
        List<QualityCase> shared = new ArrayList<>();
        List<QualityCase> added = new ArrayList<>();
        for (QualityCase item : laterCases) {
            (item.contentHash().equals(previousHashes.get(item.key())) ? shared : added).add(item);
        }
        QualityTally previousAll = QualityTally.of(previousCases, previous.answers(), BASIS);
        QualityTally laterAll = QualityTally.of(laterCases, later.answers(), BASIS);
        if (previousAll.scoredAnswers() == 0 || laterAll.scoredAnswers() == 0) {
            return notCompared();
        }
        QualityTally before = QualityTally.of(shared, previous.answers(), BASIS);
        QualityTally after = QualityTally.of(shared, later.answers(), BASIS);
        Map<QualityMetric, QualityComparison> comparisons = QualityComparator.compare(before, after,
                noise != null ? noise : QualityNoise.unknown(), significance);
        QualityCaseChanges changes = QualityGateEvaluator.changes(before, after);

        List<String> addedMissed = new ArrayList<>();
        List<String> addedStopped = new ArrayList<>();
        for (QualityCase item : added) {
            QualityTally.CaseTally tally = laterAll.find(item.key());
            if (tally == null || !tally.scored()) {
                continue;
            }
            if (item.shouldStop() && tally.actions().contains(QualityAction.ALLOW)) {
                addedMissed.add(item.key());
            }
            else if (!item.shouldStop() && tally.actions().stream().anyMatch(action -> action != QualityAction.ALLOW)) {
                addedStopped.add(item.key());
            }
        }
        List<String> newlyFailed = new ArrayList<>();
        for (QualityTally.CaseTally tally : laterAll.cases()) {
            if (!failsItsGrade(tally)) {
                continue;
            }
            QualityTally.CaseTally earlier = previousAll.find(tally.item().key());
            boolean failedBefore = earlier != null && earlier.item().contentHash().equals(tally.item().contentHash())
                    && failsItsGrade(earlier);
            if (!failedBefore) {
                newlyFailed.add(tally.item().key());
            }
        }

        boolean worse = !newlyFailed.isEmpty() || GATED.stream().map(comparisons::get)
                .anyMatch(comparison -> comparison.verdict() == QualityVerdict.WORSE);
        boolean drifted = GATED.stream().map(comparisons::get)
                .anyMatch(comparison -> comparison.verdict() == QualityVerdict.UNDECIDABLE && harmful(comparison));
        boolean changed = !changes.newlyMissed().isEmpty() || !changes.newlyStopped().isEmpty() || drifted
                || !addedMissed.isEmpty() || !addedStopped.isEmpty();
        Verdict verdict = worse ? Verdict.WORSE : changed ? Verdict.CHANGED : Verdict.SAME;
        return new QualityRemeasureComparison(verdict, comparisons, previousAll.score().rates(),
                laterAll.score().rates(), shared.size(), added.size(), changes, addedMissed, addedStopped, newlyFailed);
    }

    private static <V> Map<QualityMetric, V> copy(Map<QualityMetric, V> values) {
        Map<QualityMetric, V> copy = new EnumMap<>(QualityMetric.class);
        copy.putAll(values);
        return Collections.unmodifiableMap(copy);
    }

    /** A case that must be caught allowed in a run, or a case that must not be blocked blocked in a run. */
    private static boolean failsItsGrade(QualityTally.CaseTally tally) {
        QualityCaseGrade grade = tally.item().grade();
        return grade == QualityCaseGrade.MUST_CATCH && tally.actions().contains(QualityAction.ALLOW)
                || grade == QualityCaseGrade.MUST_NOT_BLOCK && tally.actions().contains(QualityAction.BLOCK);
    }

    /** Whether the later rate lies the harmful way from the earlier one over the paired cases. */
    private static boolean harmful(QualityComparison comparison) {
        if (comparison.pairedCases() == 0 || Double.isNaN(comparison.difference())) {
            return false;
        }
        double difference = comparison.difference();
        return comparison.metric().lowerIsBetter() ? difference > 0 : difference < 0;
    }
}
