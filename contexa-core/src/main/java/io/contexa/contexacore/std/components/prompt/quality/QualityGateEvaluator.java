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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Computes the verdict of the quality gate (plan 3.4): the conditions of its table, each with its result and the
 * numbers behind it, and the cases the two versions answer differently. The gate reads the first answers, which speak
 * of the prompt. "Significantly" means a paired comparison that says worse: a difference beyond what two measurements
 * of the same version show, that the exact test confirms. Only the two graded kinds of cases allow no single failure.
 * This is the computation alone; overriding a blocked version, rolling back and storing the verdict are not here.
 */
public final class QualityGateEvaluator {

    private static final QualityActionBasis BASIS = QualityActionBasis.FIRST_ANSWER;

    private static final List<QualityMetric> STOPPING = List.of(QualityMetric.FALSE_STOP, QualityMetric.OVER_BLOCK,
            QualityMetric.FRICTION, QualityMetric.DEFERRAL);

    /** The comparisons the gate rests on; one that cannot be decided is a shortage of cases. */
    private static final List<QualityMetric> COMPARED = List.of(QualityMetric.MISS, QualityMetric.FALSE_STOP,
            QualityMetric.OVER_BLOCK, QualityMetric.FRICTION, QualityMetric.DEFERRAL, QualityMetric.CITATION_ACCURACY);

    /** The rates read on the later cases: the ones graded against the right answer that the gate blocks on. */
    private static final List<QualityMetric> ON_LATER_CASES = List.of(QualityMetric.MISS, QualityMetric.FALSE_STOP,
            QualityMetric.OVER_BLOCK, QualityMetric.FRICTION);

    /** Rates that are equal as fractions can differ in the last bits as doubles; this is far below any real limit. */
    private static final double ROUNDING = 1e-12;

    private QualityGateEvaluator() {
    }

    public static QualityGateResult evaluate(QualityGateInput input) {
        QualityGateSettings settings = input.settings();
        QualityTally current = input.current() != null
                ? QualityTally.of(input.cases(), input.current().answers(), BASIS) : null;
        QualityTally candidate = input.candidate() != null
                ? QualityTally.of(input.cases(), input.candidate().answers(), BASIS) : null;
        // A measurement without a scored answer is no measurement.
        QualityTally measured = candidate != null && candidate.scoredAnswers() > 0 ? candidate : null;
        boolean comparable = measured != null && current != null && current.scoredAnswers() > 0
                && input.current().comparableWith(input.candidate());
        Map<QualityMetric, QualityComparison> comparisons = comparable
                ? QualityComparator.compare(current, candidate, input.noise(), settings.significance()) : Map.of();
        QualityCaseChanges changes = comparable ? changes(current, candidate) : QualityCaseChanges.none();

        List<QualityGateFinding> findings = new ArrayList<>();
        findings.add(comparableMeasurements(input, current, candidate, comparable));
        findings.add(neverAnswered(QualityGateCondition.MUST_CATCH_NEVER_ALLOWED, measured,
                QualityCaseGrade.MUST_CATCH, QualityAction.ALLOW));
        findings.add(mustCatchNotWeakened(measured, comparable ? current : null));
        findings.add(neverAnswered(QualityGateCondition.MUST_NOT_BLOCK_NEVER_BLOCKED, measured,
                QualityCaseGrade.MUST_NOT_BLOCK, QualityAction.BLOCK));
        QualityGateFinding miss = notIncreased(QualityGateCondition.MISS_NOT_INCREASED, comparisons,
                List.of(QualityMetric.MISS));
        QualityGateFinding stopping = notIncreased(QualityGateCondition.STOPPING_NOT_INCREASED, comparisons, STOPPING);
        QualityGateFinding friction = frictionWithinLimit(comparisons, changes, settings);
        findings.add(miss);
        findings.add(stopping);
        findings.add(friction);
        findings.add(modelUsedAndCitationsAccurate(measured, comparisons, settings));
        // A friction over the limit blocks for the newly stopped cases as a stopping rate does.
        findings.add(newlyMissedOrStopped(comparable, changes, miss.status(),
                stopping.status().worse(friction.status())));
        findings.add(enoughCases(measured, comparisons, settings, input.noise()));
        findings.add(laterCases(input, measured != null, settings));

        QualityGateStatus status = QualityGateStatus.NOT_EVALUATED;
        for (QualityGateFinding finding : findings) {
            status = status.worse(finding.status());
        }
        return new QualityGateResult(status, findings, comparisons, changes);
    }

    /** Row 1: both versions are measured on the same case set version, model setting and number of runs. */
    private static QualityGateFinding comparableMeasurements(QualityGateInput input, QualityTally current,
                                                             QualityTally candidate, boolean comparable) {
        Map<String, Number> figures = new LinkedHashMap<>();
        figures.put("currentScoredAnswers", current != null ? current.scoredAnswers() : 0);
        figures.put("candidateScoredAnswers", candidate != null ? candidate.scoredAnswers() : 0);
        if (input.current() != null && input.candidate() != null) {
            QualityMeasurement before = input.current();
            QualityMeasurement after = input.candidate();
            figures.put("sameCaseSetVersion", before.caseSetVersion().equals(after.caseSetVersion()) ? 1 : 0);
            figures.put("sameModelSetting", before.modelSetting().equals(after.modelSetting()) ? 1 : 0);
            figures.put("currentRepeats", before.repeats());
            figures.put("candidateRepeats", after.repeats());
        }
        return new QualityGateFinding(QualityGateCondition.COMPARABLE_MEASUREMENTS,
                comparable ? QualityGateStatus.PASSED : QualityGateStatus.BLOCKED, figures, List.of(), List.of());
    }

    /** Rows 2 and 3: no answer of a case of the grade took the action, not in a single run. */
    private static QualityGateFinding neverAnswered(QualityGateCondition condition, QualityTally candidate,
                                                    QualityCaseGrade grade, QualityAction forbidden) {
        if (candidate == null) {
            return notEvaluated(condition);
        }
        int graded = 0;
        int unmeasured = 0;
        int answers = 0;
        List<String> failed = new ArrayList<>();
        for (QualityTally.CaseTally tally : candidate.cases()) {
            if (tally.item().grade() != grade) {
                continue;
            }
            graded++;
            if (!tally.scored()) {
                unmeasured++;
            }
            long hits = tally.actions().stream().filter(action -> action == forbidden).count();
            if (hits > 0) {
                answers += (int) hits;
                failed.add(tally.item().key());
            }
        }
        Map<String, Number> figures = new LinkedHashMap<>();
        figures.put("gradedCases", graded);
        figures.put("unmeasuredCases", unmeasured);
        figures.put("failedCases", failed.size());
        figures.put("failedAnswers", answers);
        return new QualityGateFinding(condition, failed.isEmpty() ? QualityGateStatus.PASSED
                : QualityGateStatus.BLOCKED, figures, List.of(), failed);
    }

    /**
     * Beside row 2 (quality P35): no case that must be caught was answered outside its allowed actions, other than by
     * allowing it, which row 2 counts, where the version in use never answered it so. Plan 3.4 lets the two graded
     * kinds of cases fail not once, so one such answer in one run blocks, as with row 2. A case the version in use also
     * answered outside its allowed actions (allowing it included) in a run is no change the candidate brings: as with
     * the newly missed cases of row 7, which only the difference between the two versions makes, it is a warning that
     * names the cases, and the same version measured again is not blocked for it. Without a comparable measurement of
     * the version in use nothing shows such an answer to be older than the candidate, so it counts against the
     * candidate; row 1 blocks then anyway.
     *
     * @param current the measurement of the version in use, or null when there is none comparable
     */
    private static QualityGateFinding mustCatchNotWeakened(QualityTally candidate, QualityTally current) {
        QualityGateCondition condition = QualityGateCondition.MUST_CATCH_NOT_WEAKENED;
        if (candidate == null) {
            return notEvaluated(condition);
        }
        int graded = 0;
        int unmeasured = 0;
        int answers = 0;
        List<String> weakened = new ArrayList<>();
        List<String> alreadyOutside = new ArrayList<>();
        for (QualityTally.CaseTally tally : candidate.cases()) {
            QualityCase item = tally.item();
            if (item.grade() != QualityCaseGrade.MUST_CATCH) {
                continue;
            }
            graded++;
            if (!tally.scored()) {
                unmeasured++;
                continue;
            }
            long outside = tally.actions().stream().filter(action -> action != QualityAction.ALLOW
                    && !item.expectation().allows(action)).count();
            if (outside == 0) {
                continue;
            }
            QualityTally.CaseTally before = current != null ? current.find(item.key()) : null;
            if (before != null && before.actions().stream().anyMatch(action -> !item.expectation().allows(action))) {
                alreadyOutside.add(item.key());
            }
            else {
                answers += (int) outside;
                weakened.add(item.key());
            }
        }
        Map<String, Number> figures = new LinkedHashMap<>();
        figures.put("gradedCases", graded);
        figures.put("unmeasuredCases", unmeasured);
        figures.put("weakenedCases", weakened.size());
        figures.put("weakenedAnswers", answers);
        figures.put("currentAlsoOutsideCases", alreadyOutside.size());
        figures.put("comparedWithCurrent", current != null ? 1 : 0);
        QualityGateStatus status = !weakened.isEmpty() ? QualityGateStatus.BLOCKED
                : !alreadyOutside.isEmpty() ? QualityGateStatus.WARNING : QualityGateStatus.PASSED;
        return new QualityGateFinding(condition, status, figures, List.of(),
                !weakened.isEmpty() ? weakened : alreadyOutside);
    }

    /** Rows 4 and 5: none of the rates is worse than with the version in use. */
    private static QualityGateFinding notIncreased(QualityGateCondition condition,
                                                   Map<QualityMetric, QualityComparison> comparisons,
                                                   List<QualityMetric> metrics) {
        if (comparisons.isEmpty()) {
            return notEvaluated(condition);
        }
        List<QualityComparison> read = metrics.stream().map(comparisons::get).toList();
        long worse = read.stream().filter(comparison -> comparison.verdict() == QualityVerdict.WORSE).count();
        return new QualityGateFinding(condition, worse > 0 ? QualityGateStatus.BLOCKED : QualityGateStatus.PASSED,
                Map.of("worseRates", worse), read, List.of());
    }

    /**
     * Beside row 5 (quality P8): the friction did not grow by the limit of the installation or more over the version in
     * use, whatever the significance and the noise. The two rates are those of the paired comparison of the friction,
     * over the cases both measurements scored, the rate the gate shows. Where the version in use already stops most
     * normal work, too few roots are left that can turn for the exact test to say worse (plan 6: a version that
     * challenges every request), so a large rise blocks by itself. Without cases that must be allowed there is no
     * friction to compare and nothing grew.
     */
    private static QualityGateFinding frictionWithinLimit(Map<QualityMetric, QualityComparison> comparisons,
                                                          QualityCaseChanges changes, QualityGateSettings settings) {
        QualityGateCondition condition = QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT;
        if (comparisons.isEmpty()) {
            return notEvaluated(condition);
        }
        QualityComparison friction = comparisons.get(QualityMetric.FRICTION);
        Map<String, Number> figures = new LinkedHashMap<>();
        figures.put("pairedCases", friction.pairedCases());
        figures.put("currentRate", friction.currentValue());
        figures.put("candidateRate", friction.candidateValue());
        figures.put("increase", friction.difference());
        figures.put("limit", settings.frictionIncreaseLimit());
        figures.put("newlyStoppedCases", changes.newlyStopped().size());
        boolean over = friction.pairedCases() > 0
                && friction.difference() + ROUNDING >= settings.frictionIncreaseLimit();
        return new QualityGateFinding(condition, over ? QualityGateStatus.BLOCKED : QualityGateStatus.PASSED, figures,
                List.of(friction), changes.newlyStopped());
    }

    /** Row 6: the share decided without the model is within its limit, and the citation accuracy is not worse. */
    private static QualityGateFinding modelUsedAndCitationsAccurate(QualityTally candidate,
                                                                    Map<QualityMetric, QualityComparison> comparisons,
                                                                    QualityGateSettings settings) {
        QualityGateCondition condition = QualityGateCondition.MODEL_USED_AND_CITATIONS_ACCURATE;
        if (candidate == null) {
            return notEvaluated(condition);
        }
        QualityRate modelLess = candidate.rate(QualityMetric.MODEL_LESS);
        boolean overLimit = modelLess.defined() && modelLess.value() > settings.modelLessLimit();
        QualityComparison citations = comparisons.get(QualityMetric.CITATION_ACCURACY);
        Map<String, Number> figures = new LinkedHashMap<>();
        figures.put("modelLessAnswers", modelLess.events());
        figures.put("answers", modelLess.trials());
        figures.put("modelLessRate", modelLess.value());
        figures.put("modelLessLimit", settings.modelLessLimit());
        QualityGateStatus status;
        if (overLimit || (citations != null && citations.verdict() == QualityVerdict.WORSE)) {
            status = QualityGateStatus.BLOCKED;
        }
        else {
            // Without a comparison the citation half of the condition was not looked at.
            status = citations != null ? QualityGateStatus.PASSED : QualityGateStatus.NOT_EVALUATED;
        }
        return new QualityGateFinding(condition, status, figures, citations != null ? List.of(citations) : List.of(),
                List.of());
    }

    /** Row 7: cases newly missed or newly stopped while the rate itself did not block. */
    private static QualityGateFinding newlyMissedOrStopped(boolean comparable, QualityCaseChanges changes,
                                                           QualityGateStatus miss, QualityGateStatus stopping) {
        QualityGateCondition condition = QualityGateCondition.NO_NEWLY_MISSED_OR_STOPPED_CASES;
        if (!comparable) {
            return notEvaluated(condition);
        }
        boolean warn = (!changes.newlyMissed().isEmpty() && miss != QualityGateStatus.BLOCKED)
                || (!changes.newlyStopped().isEmpty() && stopping != QualityGateStatus.BLOCKED);
        Map<String, Number> figures = new LinkedHashMap<>();
        figures.put("newlyMissedCases", changes.newlyMissed().size());
        figures.put("newlyStoppedCases", changes.newlyStopped().size());
        List<String> cases = new ArrayList<>(changes.newlyMissed());
        cases.addAll(changes.newlyStopped());
        return new QualityGateFinding(condition, warn ? QualityGateStatus.WARNING : QualityGateStatus.PASSED, figures,
                List.of(), cases);
    }

    /**
     * Row 8: the cases are enough to tell. They are not when the distinct roots of the measured cases fall short of
     * the needed number, or when a comparison the gate rests on came out undecidable.
     */
    private static QualityGateFinding enoughCases(QualityTally candidate,
                                                  Map<QualityMetric, QualityComparison> comparisons,
                                                  QualityGateSettings settings, QualityNoise noise) {
        QualityGateCondition condition = QualityGateCondition.ENOUGH_CASES;
        if (candidate == null) {
            return notEvaluated(condition);
        }
        Set<String> stopRoots = new HashSet<>();
        Set<String> allowRoots = new HashSet<>();
        for (QualityTally.CaseTally tally : candidate.cases()) {
            if (tally.scored()) {
                (tally.item().shouldStop() ? stopRoots : allowRoots).add(tally.item().rootKey());
            }
        }
        int stopShort = Math.max(0, settings.minimumStopRoots() - stopRoots.size());
        int allowShort = Math.max(0, settings.minimumAllowRoots() - allowRoots.size());
        List<QualityComparison> undecidable = COMPARED.stream().map(comparisons::get)
                .filter(comparison -> comparison != null && comparison.verdict() == QualityVerdict.UNDECIDABLE)
                .toList();
        Map<String, Number> figures = new LinkedHashMap<>();
        figures.put("stopRoots", stopRoots.size());
        figures.put("stopRootsNeeded", settings.minimumStopRoots());
        figures.put("stopRootsShort", stopShort);
        figures.put("allowRoots", allowRoots.size());
        figures.put("allowRootsNeeded", settings.minimumAllowRoots());
        figures.put("allowRootsShort", allowShort);
        figures.put("undecidableRates", undecidable.size());
        figures.put("ratesWithoutNoise", COMPARED.stream().filter(metric -> noise.width(metric).isEmpty()).count());
        boolean warn = stopShort > 0 || allowShort > 0 || !undecidable.isEmpty();
        return new QualityGateFinding(condition, warn ? QualityGateStatus.WARNING : QualityGateStatus.PASSED, figures,
                undecidable, List.of());
    }

    /**
     * Row 9: the candidate is worse only on the cases that came in after it was made, which its author could not have
     * seen. For each rate, a root of the later cases and a root of the earlier ones is marked when at least half of
     * its trials are events; the exact test of Fisher says whether the later roots are marked more often than chance
     * allows. The two groups are different cases, so they are not paired.
     */
    private static QualityGateFinding laterCases(QualityGateInput input, boolean measured,
                                                 QualityGateSettings settings) {
        QualityGateCondition condition = QualityGateCondition.NOT_WORSE_ON_LATER_CASES_ONLY;
        if (!measured) {
            return notEvaluated(condition);
        }
        List<QualityCase> later = input.cases().stream()
                .filter(item -> item.arrivedAfter(input.candidateCreatedAt())).toList();
        List<QualityCase> earlier = input.cases().stream()
                .filter(item -> !item.arrivedAfter(input.candidateCreatedAt())).toList();
        Map<String, Number> figures = new LinkedHashMap<>();
        figures.put("laterCases", later.size());
        figures.put("earlierCases", earlier.size());
        if (later.isEmpty() || earlier.isEmpty()) {
            return new QualityGateFinding(condition, QualityGateStatus.PASSED, figures, List.of(), List.of());
        }
        QualityTally laterTally = QualityTally.of(later, input.candidate().answers(), BASIS);
        QualityTally earlierTally = QualityTally.of(earlier, input.candidate().answers(), BASIS);
        Set<String> cases = new HashSet<>();
        boolean warn = false;
        for (QualityMetric metric : ON_LATER_CASES) {
            QualityRate laterRate = laterTally.rate(metric);
            QualityRate earlierRate = earlierTally.rate(metric);
            if (!laterRate.defined() || !earlierRate.defined()) {
                continue;
            }
            int laterMarked = markedRoots(laterTally, metric);
            int earlierMarked = markedRoots(earlierTally, metric);
            double probability = QualityStatistics.fisherTail(laterMarked, laterRate.roots(), earlierMarked,
                    earlierRate.roots());
            String name = metric.name();
            figures.put(name + ".earlierRate", earlierRate.value());
            figures.put(name + ".laterRate", laterRate.value());
            figures.put(name + ".earlierRoots", earlierRate.roots());
            figures.put(name + ".earlierMarkedRoots", earlierMarked);
            figures.put(name + ".laterRoots", laterRate.roots());
            figures.put(name + ".laterMarkedRoots", laterMarked);
            figures.put(name + ".probability", probability);
            if (laterRate.value() > earlierRate.value() && probability <= settings.significance()) {
                warn = true;
                for (QualityTally.CaseTally tally : laterTally.cases()) {
                    if (tally.events(metric) > 0) {
                        cases.add(tally.item().key());
                    }
                }
            }
        }
        List<String> named = later.stream().map(QualityCase::key).filter(cases::contains).toList();
        return new QualityGateFinding(condition, warn ? QualityGateStatus.WARNING : QualityGateStatus.PASSED, figures,
                List.of(), named);
    }

    /** The roots of the tally where at least half of the trials of the rate are events. */
    private static int markedRoots(QualityTally tally, QualityMetric metric) {
        int marked = 0;
        for (long[] root : tally.rootCounts(metric).values()) {
            if (root[0] * 2 >= root[1]) {
                marked++;
            }
        }
        return marked;
    }

    /** The cases the two tallies answer differently, among those both scored (plan 3.4, 3.6). */
    static QualityCaseChanges changes(QualityTally current, QualityTally candidate) {
        List<String> newlyMissed = new ArrayList<>();
        List<String> newlyCaught = new ArrayList<>();
        List<String> newlyStopped = new ArrayList<>();
        List<String> newlyReleased = new ArrayList<>();
        for (QualityTally.CaseTally before : current.cases()) {
            QualityTally.CaseTally after = candidate.find(before.item().key());
            if (after == null || !before.scored() || !after.scored()) {
                continue;
            }
            String key = before.item().key();
            if (before.item().shouldStop()) {
                boolean missedBefore = before.actions().contains(QualityAction.ALLOW);
                boolean missedAfter = after.actions().contains(QualityAction.ALLOW);
                if (!missedBefore && missedAfter) {
                    newlyMissed.add(key);
                }
                else if (missedBefore && !missedAfter) {
                    newlyCaught.add(key);
                }
            }
            else {
                boolean stoppedBefore = before.actions().stream().anyMatch(action -> action != QualityAction.ALLOW);
                boolean stoppedAfter = after.actions().stream().anyMatch(action -> action != QualityAction.ALLOW);
                if (!stoppedBefore && stoppedAfter) {
                    newlyStopped.add(key);
                }
                else if (stoppedBefore && !stoppedAfter) {
                    newlyReleased.add(key);
                }
            }
        }
        return new QualityCaseChanges(newlyMissed, newlyCaught, newlyStopped, newlyReleased);
    }

    private static QualityGateFinding notEvaluated(QualityGateCondition condition) {
        return new QualityGateFinding(condition, QualityGateStatus.NOT_EVALUATED, Map.of(), List.of(), List.of());
    }
}
