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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The counts of a measurement per case (plan 3.3): for every rate, how many trials each case has and how many of them
 * are events. The score sums them; the comparison of two measurements pairs them case by case and root by root.
 * Answers of cases outside the given ones are not counted; an answer whose measurement failed, or that has no action
 * on the basis, is counted as incomplete and enters no rate.
 */
final class QualityTally {

    private static final int METRICS = QualityMetric.values().length;

    /** The counts of one case. */
    static final class CaseTally {

        private final QualityCase item;
        private final long[] events = new long[METRICS];
        private final long[] trials = new long[METRICS];
        private final List<QualityAction> actions = new ArrayList<>();

        private CaseTally(QualityCase item) {
            this.item = item;
        }

        QualityCase item() {
            return item;
        }

        long events(QualityMetric metric) {
            return events[metric.ordinal()];
        }

        long trials(QualityMetric metric) {
            return trials[metric.ordinal()];
        }

        /** The actions of the scored answers, on the basis of the tally. */
        List<QualityAction> actions() {
            return actions;
        }

        boolean scored() {
            return !actions.isEmpty();
        }

        private void count(QualityMetric metric, boolean event) {
            trials[metric.ordinal()]++;
            if (event) {
                events[metric.ordinal()]++;
            }
        }

        private void add(QualityAnswer answer, QualityAction action) {
            QualityCaseExpectation expectation = item.expectation();
            actions.add(action);
            if (item.shouldStop()) {
                count(QualityMetric.MISS, action == QualityAction.ALLOW);
            }
            else {
                count(QualityMetric.FALSE_STOP, !expectation.allows(action));
                count(QualityMetric.FRICTION, action != QualityAction.ALLOW);
            }
            if (!expectation.allows(QualityAction.BLOCK)) {
                count(QualityMetric.OVER_BLOCK, action == QualityAction.BLOCK);
            }
            count(QualityMetric.ACTION_HIT, expectation.allows(action));
            // Deferring is a property of the first answer on either basis: the closing rules end an ESCALATE.
            if (answer.firstAction() != null) {
                count(QualityMetric.DEFERRAL, answer.firstAction() == QualityAction.ESCALATE);
            }
            count(QualityMetric.REASK, answer.reasked());
            count(QualityMetric.MODEL_LESS, answer.decidedWithoutModel());
            trials[QualityMetric.CITATION_ACCURACY.ordinal()] += answer.citedFacts();
            events[QualityMetric.CITATION_ACCURACY.ordinal()] += answer.accurateCitedFacts();
        }

        private void close() {
            // One answer cannot show whether a case is answered the same way every time.
            if (actions.size() >= 2) {
                count(QualityMetric.CONSISTENCY, actions.stream().allMatch(action -> action == actions.get(0)));
            }
        }
    }

    private final QualityActionBasis basis;
    private final Map<String, CaseTally> cases = new LinkedHashMap<>();
    private final List<Long> decisionMillis = new ArrayList<>();
    private final List<Integer> answerTokens = new ArrayList<>();
    private int answers;
    private int scoredAnswers;

    private QualityTally(QualityActionBasis basis) {
        this.basis = basis;
    }

    static QualityTally of(Collection<QualityCase> cases, Collection<QualityAnswer> answers, QualityActionBasis basis) {
        QualityTally tally = new QualityTally(basis);
        for (QualityCase item : cases) {
            if (tally.cases.put(item.key(), new CaseTally(item)) != null) {
                throw new IllegalArgumentException("The case " + item.key() + " is given twice");
            }
        }
        for (QualityAnswer answer : answers) {
            CaseTally caseTally = tally.cases.get(answer.caseKey());
            if (caseTally == null) {
                continue;
            }
            tally.answers++;
            QualityAction action = basis.of(answer);
            if (answer.measurementFailed() || action == null) {
                continue;
            }
            tally.scoredAnswers++;
            caseTally.add(answer, action);
            if (answer.decisionMillis() != null) {
                tally.decisionMillis.add(answer.decisionMillis());
            }
            if (answer.answerTokens() != null) {
                tally.answerTokens.add(answer.answerTokens());
            }
        }
        tally.cases.values().forEach(CaseTally::close);
        return tally;
    }

    Collection<CaseTally> cases() {
        return cases.values();
    }

    CaseTally find(String key) {
        return cases.get(key);
    }

    int scoredAnswers() {
        return scoredAnswers;
    }

    /** The events and trials of the rate per root, over the cases with a trial. */
    Map<String, long[]> rootCounts(QualityMetric metric) {
        Map<String, long[]> roots = new LinkedHashMap<>();
        for (CaseTally caseTally : cases.values()) {
            if (caseTally.trials(metric) == 0) {
                continue;
            }
            long[] root = roots.computeIfAbsent(caseTally.item().rootKey(), key -> new long[2]);
            root[0] += caseTally.events(metric);
            root[1] += caseTally.trials(metric);
        }
        return roots;
    }

    QualityRate rate(QualityMetric metric) {
        long events = 0;
        long trials = 0;
        int counted = 0;
        int withEvent = 0;
        Set<String> roots = new HashSet<>();
        for (CaseTally caseTally : cases.values()) {
            if (caseTally.trials(metric) == 0) {
                continue;
            }
            events += caseTally.events(metric);
            trials += caseTally.trials(metric);
            counted++;
            if (caseTally.events(metric) > 0) {
                withEvent++;
            }
            roots.add(caseTally.item().rootKey());
        }
        return new QualityRate(events, trials, counted, withEvent, roots.size());
    }

    QualityScore score() {
        Map<QualityMetric, QualityRate> rates = new EnumMap<>(QualityMetric.class);
        for (QualityMetric metric : QualityMetric.values()) {
            rates.put(metric, rate(metric));
        }
        Set<String> roots = new HashSet<>();
        int unmeasured = 0;
        for (CaseTally caseTally : cases.values()) {
            if (caseTally.scored()) {
                roots.add(caseTally.item().rootKey());
            }
            else {
                unmeasured++;
            }
        }
        return new QualityScore(basis, rates, QualitySpread.of(decisionMillis), QualitySpread.of(answerTokens), answers,
                scoredAnswers, answers - scoredAnswers, cases.size(), unmeasured, roots.size());
    }
}
