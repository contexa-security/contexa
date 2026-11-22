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

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Scores the answers of a measurement against the right answers of the cases (plan 3.3). The scoring is a fixed rule;
 * no model grades an answer. A case that is uncertain counts with those that must be stopped. Answers whose
 * measurement failed enter no rate and are counted as incomplete. Answers of cases that are not given are left out,
 * so a group of cases is scored by giving that group.
 */
public final class QualityScorer {

    private QualityScorer() {
    }

    /** The metrics of the answers to the cases, counted on the basis. */
    public static QualityScore score(Collection<QualityCase> cases, Collection<QualityAnswer> answers,
                                     QualityActionBasis basis) {
        return QualityTally.of(cases, answers, basis).score();
    }

    /** The metrics of each group of cases the classifier makes, in the order the groups first appear. */
    public static <K> Map<K, QualityScore> scoreBy(Collection<QualityCase> cases, Collection<QualityAnswer> answers,
                                                   QualityActionBasis basis, Function<QualityCase, K> classifier) {
        Map<K, List<QualityCase>> groups = new LinkedHashMap<>();
        for (QualityCase item : cases) {
            groups.computeIfAbsent(classifier.apply(item), group -> new ArrayList<>()).add(item);
        }
        Map<K, QualityScore> scores = new LinkedHashMap<>();
        groups.forEach((group, members) -> scores.put(group, score(members, answers, basis)));
        return scores;
    }

    /** The metrics by who is behind the request. */
    public static Map<QualityCaseKind, QualityScore> scoreByKind(Collection<QualityCase> cases,
                                                                 Collection<QualityAnswer> answers,
                                                                 QualityActionBasis basis) {
        return scoreBy(cases, answers, basis, item -> item.expectation().kind());
    }

    /** The metrics by grade. */
    public static Map<QualityCaseGrade, QualityScore> scoreByGrade(Collection<QualityCase> cases,
                                                                   Collection<QualityAnswer> answers,
                                                                   QualityActionBasis basis) {
        return scoreBy(cases, answers, basis, QualityCase::grade);
    }

    /**
     * The metrics by where the cases come from, so the default set, which the product versions were made with, is
     * counted apart from the cases of the customer (plan 9).
     */
    public static Map<QualityCaseOrigin, QualityScore> scoreByOrigin(Collection<QualityCase> cases,
                                                                     Collection<QualityAnswer> answers,
                                                                     QualityActionBasis basis) {
        return scoreBy(cases, answers, basis, QualityCase::origin);
    }

    /**
     * The metrics of the cases that came in after the moment, such as the making of a version: cases its author could
     * not have seen (plan 3.2). Under {@code true} are the later cases, under {@code false} the others.
     */
    public static Map<Boolean, QualityScore> scoreByArrival(Collection<QualityCase> cases,
                                                            Collection<QualityAnswer> answers,
                                                            QualityActionBasis basis, Instant moment) {
        return scoreBy(cases, answers, basis, item -> item.arrivedAfter(moment));
    }
}
