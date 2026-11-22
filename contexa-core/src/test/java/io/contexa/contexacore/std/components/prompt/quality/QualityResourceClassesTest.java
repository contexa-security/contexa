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

import org.assertj.core.data.Offset;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Quality P46: the cases and the metrics by the resource class of the cases. Each class is checked against a hand
 * count and against the scoring of its cases alone; a class without a case is shown without numbers; the comparison
 * of a class can say worse where the whole set says the same; the coverage marks the classes the operation decides in
 * without enough cases.
 */
class QualityResourceClassesTest {

    private static final Offset<Double> EXACT = Offset.offset(1e-12);
    private static final List<String> SHOWN = List.of("CRITICAL", "SENSITIVE", "NORMAL", "PUBLIC");

    private final Map<String, QualityCaseResource> resources = new HashMap<>();

    private QualityCase on(QualityCase item, String resourceClass, String resource) {
        resources.put(item.key(), new QualityCaseResource(resourceClass, resource, resource != null ? "GET" : null,
                resource != null ? "/api/" + resource.toLowerCase() : null));
        return item;
    }

    private Function<QualityCase, QualityCaseResource> resourceOf() {
        return item -> resources.get(item.key());
    }

    /** Three critical cases of two roots, two sensitive, one of a class nobody shows, and one without a class. */
    private List<QualityCase> mixed() {
        return List.of(
                on(QualityFixtures.threat("C1"), "CRITICAL", "EXPORT"),
                on(QualityFixtures.threat("C2", "C1"), "CRITICAL", "EXPORT"),
                on(QualityFixtures.normal("C3"), "CRITICAL", "GRANT"),
                on(QualityFixtures.threat("S1"), "SENSITIVE", "READ"),
                on(QualityFixtures.normal("S2"), "SENSITIVE", null),
                on(QualityFixtures.threat("X1"), "UNKNOWN", "READ"),
                on(QualityFixtures.normal("U1"), null, null));
    }

    private static Map<String, QualityAction> actions(Object... pairs) {
        Map<String, QualityAction> actions = new LinkedHashMap<>();
        for (int index = 0; index < pairs.length; index += 2) {
            actions.put((String) pairs[index], (QualityAction) pairs[index + 1]);
        }
        return actions;
    }

    private static List<QualityAnswer> answers(Map<String, QualityAction> actions) {
        List<QualityAnswer> answers = new ArrayList<>();
        actions.forEach((key, action) -> answers.add(QualityAnswerFixtures.answer(key, 1, action)));
        return answers;
    }

    @Test
    void everyClassIsScoredOnItsOwnCasesAndAClassWithoutACaseHasNoScore() {
        List<QualityCase> cases = mixed();
        List<QualityAnswer> answers = answers(actions("C1", QualityAction.ALLOW, "C2", QualityAction.BLOCK,
                "C3", QualityAction.BLOCK, "S1", QualityAction.BLOCK, "S2", QualityAction.ALLOW,
                "X1", QualityAction.ALLOW, "U1", QualityAction.ALLOW));

        List<QualityResourceClassScore> scores = QualityScorer.scoreByResourceClass(cases, answers,
                QualityActionBasis.FIRST_ANSWER, resourceOf(), SHOWN);

        assertThat(scores).extracting(QualityResourceClassScore::resourceClass)
                .containsExactly("CRITICAL", "SENSITIVE", "NORMAL", "PUBLIC", "UNKNOWN",
                        QualityCaseResource.UNCLASSIFIED);
        QualityResourceClassScore critical = scores.get(0);
        assertThat(critical.cases()).isEqualTo(3);
        assertThat(critical.stopRoots()).as("C2 is a variant of C1").isEqualTo(1);
        assertThat(critical.allowRoots()).isEqualTo(1);
        // C1 allowed, C2 blocked: one miss in two answers, over one root; C3 blocked although it must be allowed.
        QualityRate miss = critical.score().rate(QualityMetric.MISS);
        assertThat(miss.events()).isEqualTo(1);
        assertThat(miss.trials()).isEqualTo(2);
        assertThat(miss.roots()).isEqualTo(1);
        assertThat(miss.lower()).isCloseTo(QualityStatistics.wilson(0.5, 1)[0], EXACT);
        assertThat(miss.upper()).isCloseTo(QualityStatistics.wilson(0.5, 1)[1], EXACT);
        assertThat(critical.score().rate(QualityMetric.FALSE_STOP).events()).isEqualTo(1);
        assertThat(critical.score().rate(QualityMetric.FALSE_STOP).trials()).isEqualTo(1);
        QualityResourceClassScore sensitive = scores.get(1);
        assertThat(sensitive.score().rate(QualityMetric.MISS).events()).isZero();
        assertThat(sensitive.score().rate(QualityMetric.FALSE_STOP).events()).isZero();
        // No case is NORMAL or PUBLIC: shown, with nothing to score.
        assertThat(scores.get(2).scored()).isFalse();
        assertThat(scores.get(2).cases()).isZero();
        assertThat(scores.get(3).score()).isNull();
        // A class has the numbers of its cases scored alone, and the classes together the numbers of the whole.
        for (QualityResourceClassScore score : scores) {
            if (!score.scored()) {
                continue;
            }
            List<QualityCase> members = cases.stream()
                    .filter(item -> resources.get(item.key()).group().equals(score.resourceClass())).toList();
            QualityScore alone = QualityScorer.score(members, answers, QualityActionBasis.FIRST_ANSWER);
            for (QualityMetric metric : QualityMetric.values()) {
                assertThat(score.score().rate(metric)).as("%s %s", score.resourceClass(), metric)
                        .isEqualTo(alone.rate(metric));
            }
        }
        QualityScore whole = QualityScorer.score(cases, answers, QualityActionBasis.FIRST_ANSWER);
        assertThat(scores.stream().filter(QualityResourceClassScore::scored)
                .mapToLong(score -> score.score().rate(QualityMetric.MISS).events()).sum())
                .isEqualTo(whole.rate(QualityMetric.MISS).events()).isEqualTo(2);
        assertThat(scores.stream().filter(QualityResourceClassScore::scored)
                .mapToLong(score -> score.score().rate(QualityMetric.MISS).trials()).sum())
                .isEqualTo(whole.rate(QualityMetric.MISS).trials());
    }

    @Test
    void aVersionWorseOnTheCriticalResourcesAloneIsWorseThereWhereTheWholeSetIsTheSame() {
        List<QualityCase> cases = new ArrayList<>();
        Map<String, QualityAction> before = new LinkedHashMap<>();
        Map<String, QualityAction> after = new LinkedHashMap<>();
        for (int index = 1; index <= 6; index++) {
            // The candidate lets every critical threat through and catches every sensitive one the version missed.
            cases.add(on(QualityFixtures.threat("C" + index), "CRITICAL", "EXPORT"));
            before.put("C" + index, QualityAction.BLOCK);
            after.put("C" + index, QualityAction.ALLOW);
            cases.add(on(QualityFixtures.threat("S" + index), "SENSITIVE", "READ"));
            before.put("S" + index, QualityAction.ALLOW);
            after.put("S" + index, QualityAction.BLOCK);
        }
        QualityMeasurement current = QualityAnswerFixtures.measurement("v1.0", 1, answers(before));
        QualityMeasurement candidate = QualityAnswerFixtures.measurement("v2.0", 1, answers(after));
        QualityNoise noise = new QualityNoise(Map.of(QualityMetric.MISS, 0.0));

        Map<QualityMetric, QualityComparison> whole = QualityComparator.compare(cases, current, candidate,
                QualityActionBasis.FIRST_ANSWER, noise, 0.05);
        List<QualityResourceClassComparison> classes = QualityComparator.compareByResourceClass(cases, current,
                candidate, QualityActionBasis.FIRST_ANSWER, noise, 0.05, resourceOf(), SHOWN);

        assertThat(whole.get(QualityMetric.MISS).verdict()).as("six roots worse, six better")
                .isEqualTo(QualityVerdict.SAME);
        assertThat(classes).extracting(QualityResourceClassComparison::resourceClass)
                .containsExactly("CRITICAL", "SENSITIVE", "NORMAL", "PUBLIC");
        QualityResourceClassComparison critical = classes.get(0);
        assertThat(critical.comparison(QualityMetric.MISS).verdict()).isEqualTo(QualityVerdict.WORSE);
        assertThat(critical.comparison(QualityMetric.MISS).worseRoots()).isEqualTo(6);
        assertThat(critical.comparison(QualityMetric.MISS).pairedCases()).isEqualTo(6);
        assertThat(critical.comparison(QualityMetric.MISS).worseProbability()).isCloseTo(1.0 / 64, EXACT);
        assertThat(critical.changes().newlyMissed()).containsExactly("C1", "C2", "C3", "C4", "C5", "C6");
        assertThat(critical.changedCases()).isEqualTo(6);
        QualityResourceClassComparison sensitive = classes.get(1);
        assertThat(sensitive.comparison(QualityMetric.MISS).verdict()).isEqualTo(QualityVerdict.BETTER);
        assertThat(sensitive.changes().newlyCaught()).hasSize(6);
        assertThat(sensitive.changes().newlyMissed()).isEmpty();
        // The class of the critical cases is compared exactly as the comparison of those cases alone.
        List<QualityCase> criticalCases = cases.stream().filter(item -> item.key().startsWith("C")).toList();
        assertThat(critical.comparison(QualityMetric.MISS)).isEqualTo(QualityComparator.compare(criticalCases,
                current, candidate, QualityActionBasis.FIRST_ANSWER, noise, 0.05).get(QualityMetric.MISS));
        // A class without a case is shown and compares nothing.
        QualityResourceClassComparison normal = classes.get(2);
        assertThat(normal.compared()).isFalse();
        assertThat(normal.comparisons()).isEmpty();
        assertThat(normal.changedCases()).isZero();

        QualityMeasurement otherRuns = new QualityMeasurement("v2.0", QualityAnswerFixtures.MODEL,
                QualityAnswerFixtures.CASE_SET, 3, answers(after));
        assertThatThrownBy(() -> QualityComparator.compareByResourceClass(cases, current, otherRuns,
                QualityActionBasis.FIRST_ANSWER, noise, 0.05, resourceOf(), SHOWN))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theCoverageMarksTheClassesTheOperationDecidesInWithoutEnoughCases() {
        List<QualityCase> cases = new ArrayList<>(mixed());
        // Five sensitive roots on each side: as many as a paired comparison needs at the 5% level.
        for (int index = 3; index <= 7; index++) {
            cases.add(on(QualityFixtures.threat("S" + index), "SENSITIVE", "READ"));
            cases.add(on(QualityFixtures.normal("SN" + index), "SENSITIVE", "READ"));
        }
        Map<String, Long> decisions = new LinkedHashMap<>();
        decisions.put("CRITICAL", 100L);
        decisions.put("SENSITIVE", 50L);
        decisions.put("NORMAL", 400L);
        decisions.put("PUBLIC", 0L);
        decisions.put(QualityCaseResource.UNCLASSIFIED, 7L);

        QualityResourceCoverage coverage = QualityResourceCoverage.of(cases, resourceOf(), decisions, SHOWN,
                QualityResourceCoverage.minimumRoots(0.05), 2);

        assertThat(coverage.cases()).isEqualTo(17);
        assertThat(coverage.minimumRoots()).isEqualTo(5);
        assertThat(coverage.operationDecisions()).isEqualTo(557);
        assertThat(coverage.classes()).extracting(QualityResourceCoverage.ClassRow::resourceClass)
                .containsExactly("CRITICAL", "SENSITIVE", "NORMAL", "PUBLIC", "UNKNOWN",
                        QualityCaseResource.UNCLASSIFIED);
        QualityResourceCoverage.ClassRow critical = coverage.find("CRITICAL").orElseThrow();
        assertThat(critical).isEqualTo(new QualityResourceCoverage.ClassRow("CRITICAL", 3, 2, 1, 1, 1, 2, 100,
                QualityResourceCoverage.Gap.FEW_CASES));
        QualityResourceCoverage.ClassRow sensitive = coverage.find("SENSITIVE").orElseThrow();
        assertThat(sensitive).isEqualTo(new QualityResourceCoverage.ClassRow("SENSITIVE", 12, 6, 6, 6, 6, 1, 50,
                QualityResourceCoverage.Gap.NONE));
        assertThat(coverage.find("NORMAL").orElseThrow()).isEqualTo(new QualityResourceCoverage.ClassRow("NORMAL",
                0, 0, 0, 0, 0, 0, 400, QualityResourceCoverage.Gap.NO_CASES));
        // No decision of the operation: not a gap, though no case has the class.
        assertThat(coverage.find("PUBLIC").orElseThrow().gap()).isEqualTo(QualityResourceCoverage.Gap.NONE);
        assertThat(coverage.find("UNKNOWN").orElseThrow().gap()).isEqualTo(QualityResourceCoverage.Gap.NONE);
        assertThat(coverage.find(QualityCaseResource.UNCLASSIFIED).orElseThrow().gap())
                .isEqualTo(QualityResourceCoverage.Gap.FEW_CASES);
        assertThat(coverage.gaps()).extracting(QualityResourceCoverage.ClassRow::resourceClass)
                .containsExactly("CRITICAL", "NORMAL", QualityCaseResource.UNCLASSIFIED);
        // READ has twelve cases (S1, X1 and the ten added), EXPORT two, GRANT one; S2 and U1 name no resource.
        assertThat(coverage.resources()).isEqualTo(3);
        assertThat(coverage.unidentifiedCases()).isEqualTo(2);
        assertThat(coverage.topResources()).hasSize(2);
        QualityResourceCoverage.ResourceRow read = coverage.topResources().get(0);
        assertThat(read.resource()).isEqualTo("READ");
        assertThat(read.cases()).isEqualTo(12);
        assertThat(read.stopCases()).isEqualTo(7);
        assertThat(read.allowCases()).isEqualTo(5);
        assertThat(read.resourceClasses()).containsExactly("SENSITIVE", "UNKNOWN");
        assertThat(read.httpMethod()).isEqualTo("GET");
        assertThat(read.urlTemplate()).isEqualTo("/api/read");
        assertThat(coverage.topResources().get(1).resource()).isEqualTo("EXPORT");
        assertThat(coverage.topResources().get(1).roots()).isEqualTo(1);
    }

    @Test
    void theRootsASideNeedsFollowTheLevelOfTheSignTest() {
        assertThat(QualityResourceCoverage.minimumRoots(0.05)).isEqualTo(5);
        assertThat(QualityResourceCoverage.minimumRoots(0.01)).isEqualTo(7);
        assertThat(QualityResourceCoverage.minimumRoots(0.5)).isEqualTo(1);
        assertThat(QualityStatistics.signTestTail(4, 4)).isGreaterThan(0.05);
        assertThat(QualityStatistics.signTestTail(5, 5)).isLessThanOrEqualTo(0.05);
        assertThatThrownBy(() -> QualityResourceCoverage.minimumRoots(0)).isInstanceOf(IllegalArgumentException.class);
    }
}
