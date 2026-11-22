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
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Plan 3.3: the statistics and the paired comparison of two versions. The comparison is made root by root with an
 * exact test, says one of four things, and calls "the same" whatever two measurements of one version differ by.
 */
class QualityComparatorTest {

    private static final Offset<Double> EXACT = Offset.offset(1e-12);
    private static final double LEVEL = 0.05;

    /** Twelve threats, each its own root. */
    private static final List<QualityCase> TWELVE = roots(12);

    private static List<QualityCase> roots(int count) {
        List<QualityCase> cases = new ArrayList<>();
        for (int index = 1; index <= count; index++) {
            cases.add(QualityFixtures.threat("R" + index));
        }
        return cases;
    }

    /** A measurement of the twelve where the roots up to the number are allowed and the others blocked. */
    private static QualityMeasurement missingTheFirst(String version, int missed) {
        return QualityAnswerFixtures.measurement(version, 1, QualityAnswerFixtures.answers(TWELVE, 1,
                item -> Integer.parseInt(item.key().substring(1)) <= missed ? QualityAction.ALLOW
                        : QualityAction.BLOCK));
    }

    private static QualityNoise noise(double width) {
        Map<QualityMetric, Double> widths = new EnumMap<>(QualityMetric.class);
        for (QualityMetric metric : QualityMetric.values()) {
            widths.put(metric, width);
        }
        return new QualityNoise(widths);
    }

    private static QualityComparison miss(QualityMeasurement current, QualityMeasurement candidate,
                                          QualityNoise noise) {
        return QualityComparator.compare(TWELVE, current, candidate, QualityActionBasis.FIRST_ANSWER, noise, LEVEL)
                .get(QualityMetric.MISS);
    }

    @Test
    void theWilsonIntervalIsTheOneOfTheLocalMeasurement() {
        // 13 of 45 and 0 of 15 as the local aggregation gave them; 0 of 15 and 0 of 300 are the numbers of plan 3.2.
        assertThat(QualityStatistics.wilson(13.0 / 45, 45)[0]).isCloseTo(0.1773008248284927, EXACT);
        assertThat(QualityStatistics.wilson(13.0 / 45, 45)[1]).isCloseTo(0.43368540574761577, EXACT);
        assertThat(QualityStatistics.wilson(0, 15)[0]).isZero();
        assertThat(QualityStatistics.wilson(0, 15)[1]).isCloseTo(0.20388330103584862, EXACT);
        assertThat(QualityStatistics.wilson(0, 300)[1]).isCloseTo(0.012642971224546034, EXACT);
        assertThat(QualityStatistics.wilson(1, 1)[0]).isCloseTo(1 - 0.7934506856227626, EXACT);
        assertThat(QualityStatistics.wilson(1, 1)[1]).isEqualTo(1.0);
        // No sample, or nothing to take a share of: no interval.
        assertThat(QualityStatistics.wilson(0.5, 0)).containsExactly(Double.NaN, Double.NaN);
        assertThat(QualityStatistics.wilson(Double.NaN, 10)).containsExactly(Double.NaN, Double.NaN);
    }

    @Test
    void theExactTestsCountEveryOutcome() {
        // Sign test: the chance of at least so many of the differing roots on one side.
        assertThat(QualityStatistics.signTestTail(0, 0)).isEqualTo(1.0);
        assertThat(QualityStatistics.signTestTail(4, 4)).isEqualTo(0.0625);
        assertThat(QualityStatistics.signTestTail(5, 5)).isEqualTo(0.03125);
        assertThat(QualityStatistics.signTestTail(3, 5)).isEqualTo(0.5);
        assertThat(QualityStatistics.signTestTail(9, 10)).isEqualTo(11.0 / 1024);
        assertThat(QualityStatistics.signTestTail(600, 1000)).isBetween(0.0, 1e-9);
        // Fisher: 3 marked of 10 against 0 of 25 is C(10,3) / C(35,3).
        assertThat(QualityStatistics.fisherTail(3, 10, 0, 25)).isCloseTo(120.0 / 6545, EXACT);
        assertThat(QualityStatistics.fisherTail(1, 1, 0, 25)).isCloseTo(1.0 / 26, EXACT);
        assertThat(QualityStatistics.fisherTail(0, 10, 5, 25)).isEqualTo(1.0);
        assertThat(QualityStatistics.fisherTail(0, 0, 0, 0)).isEqualTo(1.0);
        assertThatThrownBy(() -> QualityStatistics.signTestTail(3, 2)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> QualityStatistics.fisherTail(3, 2, 0, 1)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theSameAnswersTwiceAreTheSameWhetherOrNotTheNoiseIsMeasured() {
        QualityMeasurement current = missingTheFirst("v1", 3);
        QualityMeasurement again = missingTheFirst("v1-renamed", 3);

        Map<QualityMetric, QualityComparison> comparisons = QualityComparator.compare(TWELVE, current, again,
                QualityActionBasis.FIRST_ANSWER, QualityNoise.unknown(), LEVEL);

        // Every rate that can be taken is the same; the rates with nothing to count cannot be told.
        assertThat(comparisons).containsOnlyKeys(QualityMetric.values());
        for (QualityMetric metric : List.of(QualityMetric.MISS, QualityMetric.ACTION_HIT, QualityMetric.DEFERRAL,
                QualityMetric.CITATION_ACCURACY, QualityMetric.REASK, QualityMetric.MODEL_LESS)) {
            assertThat(comparisons.get(metric).verdict()).as("%s", metric).isEqualTo(QualityVerdict.SAME);
        }
        QualityComparison miss = comparisons.get(QualityMetric.MISS);
        assertThat(miss.currentValue()).isEqualTo(0.25);
        assertThat(miss.difference()).isZero();
        assertThat(miss.pairedCases()).isEqualTo(12);
        assertThat(miss.pairedRoots()).isEqualTo(12);
        assertThat(miss.worseRoots()).isZero();
        assertThat(miss.betterRoots()).isZero();
        assertThat(miss.noiseWidth()).isNaN();
        QualityComparison falseStop = comparisons.get(QualityMetric.FALSE_STOP);
        assertThat(falseStop.verdict()).isEqualTo(QualityVerdict.UNDECIDABLE);
        assertThat(falseStop.pairedCases()).isZero();
        assertThat(falseStop.currentValue()).isNaN();
    }

    @Test
    void aDifferenceWithinTheNoiseIsTheSameAndOneBeyondItNeedsTheExactTest() {
        QualityMeasurement current = missingTheFirst("v1", 0);

        // One root of twelve: 8.3%, inside a noise of 10%.
        QualityComparison within = miss(current, missingTheFirst("v2", 1), noise(0.10));
        // Four roots: beyond the noise, but four roots all turning one way happens by chance 1 time in 16.
        QualityComparison few = miss(current, missingTheFirst("v2", 4), noise(0.10));
        // Six roots: 1 time in 64.
        QualityComparison many = miss(current, missingTheFirst("v2", 6), noise(0.10));

        assertThat(within.verdict()).isEqualTo(QualityVerdict.SAME);
        assertThat(within.difference()).isCloseTo(1.0 / 12, EXACT);
        assertThat(within.worseRoots()).isEqualTo(1);
        assertThat(few.verdict()).isEqualTo(QualityVerdict.UNDECIDABLE);
        assertThat(few.worseRoots()).isEqualTo(4);
        assertThat(few.worseProbability()).isEqualTo(0.0625);
        assertThat(many.verdict()).isEqualTo(QualityVerdict.WORSE);
        assertThat(many.worseRoots()).isEqualTo(6);
        assertThat(many.betterRoots()).isZero();
        assertThat(many.worseProbability()).isEqualTo(1.0 / 64);
        assertThat(many.noiseWidth()).isEqualTo(0.10);
        // The other way round the candidate is better.
        QualityComparison better = miss(missingTheFirst("v1", 6), missingTheFirst("v2", 0), noise(0.10));
        assertThat(better.verdict()).isEqualTo(QualityVerdict.BETTER);
        assertThat(better.betterProbability()).isEqualTo(1.0 / 64);
        // A difference exactly as large as the noise is still the same.
        assertThat(miss(current, missingTheFirst("v2", 6), noise(0.5)).verdict()).isEqualTo(QualityVerdict.SAME);
    }

    @Test
    void withoutMeasuredNoiseADifferenceIsUndecidableNotWorse() {
        QualityComparison comparison = miss(missingTheFirst("v1", 0), missingTheFirst("v2", 12),
                QualityNoise.unknown());

        // Every root turned, yet nobody has shown what two measurements of one version differ by.
        assertThat(comparison.worseRoots()).isEqualTo(12);
        assertThat(comparison.verdict()).isEqualTo(QualityVerdict.UNDECIDABLE);
        assertThat(comparison.noiseWidth()).isNaN();
    }

    @Test
    void theVariantsOfOneRootCountAsOneRoot() {
        List<QualityCase> cases = new ArrayList<>(TWELVE);
        for (int variant = 1; variant <= 10; variant++) {
            cases.add(QualityFixtures.threat("V" + variant + "-R1", "R1"));
        }
        QualityMeasurement current = QualityAnswerFixtures.measurement("v1", 1,
                QualityAnswerFixtures.answers(cases, 1, item -> QualityAction.BLOCK));
        QualityMeasurement candidate = QualityAnswerFixtures.measurement("v2", 1,
                QualityAnswerFixtures.answers(cases, 1,
                        item -> item.rootKey().equals("R1") ? QualityAction.ALLOW : QualityAction.BLOCK));

        QualityComparison comparison = QualityComparator.compare(cases, current, candidate,
                QualityActionBasis.FIRST_ANSWER, noise(0.05), LEVEL).get(QualityMetric.MISS);

        // Eleven answers of 22 changed, all under one root: one root cannot show a version is worse.
        assertThat(comparison.difference()).isEqualTo(0.5);
        assertThat(comparison.pairedCases()).isEqualTo(22);
        assertThat(comparison.pairedRoots()).isEqualTo(12);
        assertThat(comparison.worseRoots()).isEqualTo(1);
        assertThat(comparison.worseProbability()).isEqualTo(0.5);
        assertThat(comparison.verdict()).isEqualTo(QualityVerdict.UNDECIDABLE);
    }

    @Test
    void onlyTheCasesBothMeasurementsScoredArePaired() {
        QualityMeasurement current = missingTheFirst("v1", 2);
        List<QualityAnswer> answers = new ArrayList<>(missingTheFirst("v2", 2).answers());
        answers.set(0, QualityAnswer.failed("R1", 1, "model server busy"));
        QualityMeasurement candidate = QualityAnswerFixtures.measurement("v2", 1, answers);

        QualityComparison comparison = miss(current, candidate, noise(0.05));

        // R1 is left out of both rates: 1 of 11 on either side, not 2 of 12 against 1 of 11.
        assertThat(comparison.pairedCases()).isEqualTo(11);
        assertThat(comparison.currentValue()).isCloseTo(1.0 / 11, EXACT);
        assertThat(comparison.candidateValue()).isCloseTo(1.0 / 11, EXACT);
        assertThat(comparison.verdict()).isEqualTo(QualityVerdict.SAME);
    }

    @Test
    void aRateWhereMoreIsBetterTurnsTheOtherWay() {
        List<QualityAnswer> accurate = QualityAnswerFixtures.answers(TWELVE, 1, item -> QualityAction.BLOCK);
        List<QualityAnswer> careless = TWELVE.stream().map(item -> new QualityAnswer(item.key(), 1,
                QualityAction.BLOCK, null, false, false, 3, 1, 7000L, 120, false, null)).toList();

        Map<QualityMetric, QualityComparison> comparisons = QualityComparator.compare(TWELVE,
                QualityAnswerFixtures.measurement("v1", 1, accurate),
                QualityAnswerFixtures.measurement("v2", 1, careless), QualityActionBasis.FIRST_ANSWER, noise(0.05),
                LEVEL);

        QualityComparison citations = comparisons.get(QualityMetric.CITATION_ACCURACY);
        assertThat(citations.currentValue()).isEqualTo(1.0);
        assertThat(citations.candidateValue()).isCloseTo(1.0 / 3, EXACT);
        assertThat(citations.worseRoots()).isEqualTo(12);
        assertThat(citations.verdict()).isEqualTo(QualityVerdict.WORSE);
        assertThat(comparisons.get(QualityMetric.MISS).verdict()).isEqualTo(QualityVerdict.SAME);
    }

    @Test
    void measurementsTakenDifferentlyAreNotCompared() {
        QualityMeasurement current = missingTheFirst("v1", 0);
        List<QualityAnswer> answers = current.answers();

        assertThat(current.comparableWith(missingTheFirst("v2", 5))).isTrue();
        for (QualityMeasurement other : List.of(
                new QualityMeasurement("v2", QualityAnswerFixtures.MODEL, QualityAnswerFixtures.CASE_SET, 3, answers),
                new QualityMeasurement("v2", QualityAnswerFixtures.MODEL, "case-set-version-2", 1, answers),
                new QualityMeasurement("v2", "another-model", QualityAnswerFixtures.CASE_SET, 1, answers))) {
            assertThat(current.comparableWith(other)).isFalse();
            assertThatThrownBy(() -> QualityComparator.compare(TWELVE, current, other,
                    QualityActionBasis.FIRST_ANSWER, noise(0.05), LEVEL)).isInstanceOf(IllegalArgumentException.class);
        }
        assertThat(current.comparableWith(null)).isFalse();
    }

    @Test
    void theNoiseIsWhatTwoMeasurementsOfOneVersionDifferBy() {
        QualityNoise noise = QualityNoise.between(TWELVE, missingTheFirst("v1", 1), missingTheFirst("v1", 3),
                QualityActionBasis.FIRST_ANSWER);

        assertThat(noise.width(QualityMetric.MISS).getAsDouble()).isCloseTo(2.0 / 12, EXACT);
        assertThat(noise.width(QualityMetric.DEFERRAL).getAsDouble()).isZero();
        // No case to allow, so nothing says how far the false stops of one version move.
        assertThat(noise.width(QualityMetric.FALSE_STOP)).isEmpty();
        assertThat(QualityNoise.unknown().width(QualityMetric.MISS)).isEmpty();
        // The noise of one version, not the difference of two.
        assertThatThrownBy(() -> QualityNoise.between(TWELVE, missingTheFirst("v1", 1), missingTheFirst("v2", 3),
                QualityActionBasis.FIRST_ANSWER)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new QualityNoise(Map.of(QualityMetric.MISS, -0.1)))
                .isInstanceOf(IllegalArgumentException.class);

        // A third measurement that differs from the first by as much is the same; by more, it is not.
        assertThat(miss(missingTheFirst("v1", 1), missingTheFirst("v2", 3), noise).verdict())
                .isEqualTo(QualityVerdict.SAME);
        assertThat(miss(missingTheFirst("v1", 0), missingTheFirst("v2", 6), noise).verdict())
                .isEqualTo(QualityVerdict.WORSE);
        assertThat(Set.of(QualityVerdict.values())).hasSize(4);
    }
}
