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

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 3.6: a version measured again against its measurement before, whether the model setting or the case set
 * changed: worse, changed, the same, or not compared.
 */
class QualityRemeasureComparisonTest {

    private static final int RUNS = 3;
    private static final Set<Integer> EVERY_RUN = Set.of(1, 2, 3);

    private static List<QualityCase> cases() {
        List<QualityCase> cases = new ArrayList<>();
        for (int index = 1; index <= 10; index++) {
            cases.add(QualityFixtures.threat("T" + index));
            cases.add(QualityFixtures.normal("N" + index));
        }
        cases.add(QualityFixtures.mustCatch("M1"));
        cases.add(QualityFixtures.mustNotBlock("P1"));
        return cases;
    }

    private static QualityAction sound(QualityCase item) {
        return item.shouldStop() ? QualityAction.BLOCK : QualityAction.ALLOW;
    }

    private static QualityMeasurement measured(String setting, String setVersion, List<QualityAnswer> answers) {
        return new QualityMeasurement("v2.0", setting, setVersion, RUNS, answers);
    }

    @Test
    void theSameAnswersUnderAnotherSettingAreTheSame() {
        List<QualityCase> cases = cases();
        List<QualityAnswer> answers = QualityAnswerFixtures.answers(cases, RUNS, QualityRemeasureComparisonTest::sound);

        QualityRemeasureComparison same = QualityRemeasureComparison.compare(cases, measured("a", "set-1", answers),
                cases, measured("b", "set-1", answers), QualityNoise.unknown(), 0.05);

        assertThat(same.verdict()).isEqualTo(QualityRemeasureComparison.Verdict.SAME);
        assertThat(same.sharedCases()).isEqualTo(cases.size());
        assertThat(same.addedCases()).isZero();
        assertThat(same.comparisons().get(QualityMetric.MISS).verdict()).isEqualTo(QualityVerdict.SAME);
        assertThat(same.previousRates().get(QualityMetric.MISS).events()).isZero();
        assertThat(same.laterRates().get(QualityMetric.MISS).trials()).isEqualTo(11L * RUNS);
    }

    /**
     * A newly missed case without the noise to call the rate worse is a change; a case that must be caught allowed
     * where it was not is worse, whatever the noise.
     */
    @Test
    void aNewlyMissedCaseIsAChangeAndAMustCatchCaseAllowedIsWorse() {
        List<QualityCase> cases = cases();
        List<QualityAnswer> before = QualityAnswerFixtures.answers(cases, RUNS, QualityRemeasureComparisonTest::sound);
        List<QualityAnswer> missed = QualityAnswerFixtures.with(before, "T3", Set.of(2), QualityAction.ALLOW);

        QualityRemeasureComparison changed = QualityRemeasureComparison.compare(cases, measured("a", "s", before),
                cases, measured("b", "s", missed), QualityNoise.unknown(), 0.05);
        assertThat(changed.verdict()).isEqualTo(QualityRemeasureComparison.Verdict.CHANGED);
        assertThat(changed.changes().newlyMissed()).containsExactly("T3");
        assertThat(changed.comparisons().get(QualityMetric.MISS).verdict()).isEqualTo(QualityVerdict.UNDECIDABLE);
        assertThat(changed.laterRates().get(QualityMetric.MISS).events()).isEqualTo(1L);

        List<QualityAnswer> allowed = QualityAnswerFixtures.with(before, "M1", Set.of(1), QualityAction.ALLOW);
        QualityRemeasureComparison worse = QualityRemeasureComparison.compare(cases, measured("a", "s", before),
                cases, measured("b", "s", allowed), QualityNoise.unknown(), 0.05);
        assertThat(worse.verdict()).isEqualTo(QualityRemeasureComparison.Verdict.WORSE);
        assertThat(worse.newlyFailedGraded()).containsExactly("M1");

        // A case that must be caught and failed before already is no new failure.
        QualityRemeasureComparison again = QualityRemeasureComparison.compare(cases, measured("a", "s", allowed),
                cases, measured("b", "s", allowed), QualityNoise.unknown(), 0.05);
        assertThat(again.verdict()).isEqualTo(QualityRemeasureComparison.Verdict.SAME);
        assertThat(again.newlyFailedGraded()).isEmpty();
    }

    /** With the noise measured, many newly missed cases are worse by the paired comparison of the rate. */
    @Test
    void aMissBeyondTheNoiseConfirmedByTheExactTestIsWorse() {
        List<QualityCase> cases = cases();
        List<QualityAnswer> before = QualityAnswerFixtures.answers(cases, RUNS, QualityRemeasureComparisonTest::sound);
        List<QualityAnswer> later = before;
        for (int index = 1; index <= 8; index++) {
            later = QualityAnswerFixtures.with(later, "T" + index, EVERY_RUN, QualityAction.ALLOW);
        }
        Map<QualityMetric, Double> widths = new EnumMap<>(QualityMetric.class);
        for (QualityMetric metric : QualityMetric.values()) {
            widths.put(metric, 0.05);
        }

        QualityRemeasureComparison worse = QualityRemeasureComparison.compare(cases, measured("a", "s", before),
                cases, measured("b", "s", later), new QualityNoise(widths), 0.05);

        assertThat(worse.comparisons().get(QualityMetric.MISS).verdict()).isEqualTo(QualityVerdict.WORSE);
        assertThat(worse.verdict()).isEqualTo(QualityRemeasureComparison.Verdict.WORSE);
        assertThat(worse.newlyFailedGraded()).isEmpty();
    }

    /**
     * The cases a set published since adds are not paired: the shared ones keep their answers, and an added case the
     * version misses is a change; an added case it answers well leaves it the same. A case whose answer changed is
     * read as added.
     */
    @Test
    void theCasesANewSetAddsAreReadOnTheirOwn() {
        List<QualityCase> earlier = cases();
        List<QualityCase> later = new ArrayList<>(earlier);
        later.add(QualityFixtures.threat("T-new"));
        later.add(QualityFixtures.normal("N-new"));
        List<QualityAnswer> before = QualityAnswerFixtures.answers(earlier, RUNS, QualityRemeasureComparisonTest::sound);
        List<QualityAnswer> afterSound = QualityAnswerFixtures.answers(later, RUNS,
                QualityRemeasureComparisonTest::sound);

        QualityRemeasureComparison same = QualityRemeasureComparison.compare(earlier, measured("a", "set-1", before),
                later, measured("a", "set-2", afterSound), QualityNoise.unknown(), 0.05);
        assertThat(same.verdict()).isEqualTo(QualityRemeasureComparison.Verdict.SAME);
        assertThat(same.sharedCases()).isEqualTo(earlier.size());
        assertThat(same.addedCases()).isEqualTo(2);

        List<QualityAnswer> afterMissing = QualityAnswerFixtures.with(afterSound, "T-new", Set.of(3),
                QualityAction.ALLOW);
        afterMissing = QualityAnswerFixtures.with(afterMissing, "N-new", Set.of(1), QualityAction.CHALLENGE);
        QualityRemeasureComparison changed = QualityRemeasureComparison.compare(earlier,
                measured("a", "set-1", before), later, measured("a", "set-2", afterMissing), QualityNoise.unknown(),
                0.05);
        assertThat(changed.verdict()).isEqualTo(QualityRemeasureComparison.Verdict.CHANGED);
        assertThat(changed.addedMissed()).containsExactly("T-new");
        assertThat(changed.addedStopped()).containsExactly("N-new");
        assertThat(changed.changes().newlyMissed()).isEmpty();
        assertThat(changed.previousRates().get(QualityMetric.MISS).events()).isZero();
        assertThat(changed.laterRates().get(QualityMetric.MISS).events()).isEqualTo(1L);
    }

    @Test
    void withoutAMeasurementBeforeOrAScoredAnswerNothingIsCompared() {
        List<QualityCase> cases = cases();
        List<QualityAnswer> answers = QualityAnswerFixtures.answers(cases, RUNS, QualityRemeasureComparisonTest::sound);

        assertThat(QualityRemeasureComparison.compare(cases, null, cases, measured("b", "s", answers),
                QualityNoise.unknown(), 0.05).verdict()).isEqualTo(QualityRemeasureComparison.Verdict.NOT_COMPARED);
        assertThat(QualityRemeasureComparison.compare(cases, measured("a", "s", List.of()), cases,
                measured("b", "s", answers), QualityNoise.unknown(), 0.05).verdict())
                .isEqualTo(QualityRemeasureComparison.Verdict.NOT_COMPARED);
    }
}
