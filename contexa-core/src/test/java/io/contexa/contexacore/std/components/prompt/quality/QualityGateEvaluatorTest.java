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

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 3.4: the conditions of the quality gate, and the discrimination checks of plan 6 at the level of the
 * computation: what must be blocked is blocked (a version that challenges everything, one that only defers, one that
 * allows a case that must be caught, one that challenges a case that must be blocked), and what must pass passes (the
 * same answers again, a difference within the noise). Plan 3.2: a version worse only on the cases that came in after
 * it was made draws the warning.
 */
class QualityGateEvaluatorTest {

    /** 12 threats, 12 normal cases, 2 that must be caught and 2 that must not be blocked; each is its own root. */
    private static final List<QualityCase> CASES = cases();

    private static final int RUNS = 3;

    /** Ten roots on either side are enough here, so the shortage of cases does not colour every test. */
    private static final QualityGateSettings SETTINGS = new QualityGateSettings(0.05, 0.05, 10, 10, 0.30);

    private static final QualityNoise NOISE = noise(0.05);

    private static final Set<Integer> EVERY_RUN = Set.of(1, 2, 3);

    private static final int CONDITIONS = QualityGateCondition.values().length;

    private static List<QualityCase> cases() {
        List<QualityCase> cases = new ArrayList<>();
        for (int index = 1; index <= 12; index++) {
            cases.add(QualityFixtures.threat("T" + index));
        }
        for (int index = 1; index <= 12; index++) {
            cases.add(QualityFixtures.normal("N" + index));
        }
        cases.add(QualityFixtures.mustCatch("M1"));
        cases.add(QualityFixtures.mustCatch("M2"));
        cases.add(QualityFixtures.mustNotBlock("P1"));
        cases.add(QualityFixtures.mustNotBlock("P2"));
        return List.copyOf(cases);
    }

    private static QualityNoise noise(double width) {
        Map<QualityMetric, Double> widths = new EnumMap<>(QualityMetric.class);
        for (QualityMetric metric : QualityMetric.values()) {
            widths.put(metric, width);
        }
        return new QualityNoise(widths);
    }

    /** The version in use: every threat challenged, the cases that must be caught blocked, normal work allowed. */
    private static QualityAction sound(QualityCase item) {
        if (item.grade() == QualityCaseGrade.MUST_CATCH) {
            return QualityAction.BLOCK;
        }
        return item.shouldStop() ? QualityAction.CHALLENGE : QualityAction.ALLOW;
    }

    private static List<QualityAnswer> soundAnswers() {
        return QualityAnswerFixtures.answers(CASES, RUNS, QualityGateEvaluatorTest::sound);
    }

    private static List<QualityAnswer> answering(Function<QualityCase, QualityAction> decision) {
        return QualityAnswerFixtures.answers(CASES, RUNS, decision);
    }

    private static QualityGateResult gate(List<QualityAnswer> current, List<QualityAnswer> candidate) {
        return gate(current, candidate, NOISE, SETTINGS);
    }

    private static QualityGateResult gate(List<QualityAnswer> current, List<QualityAnswer> candidate,
                                          QualityNoise noise, QualityGateSettings settings) {
        return QualityGateEvaluator.evaluate(new QualityGateInput(CASES,
                QualityAnswerFixtures.measurement("v1", RUNS, current),
                QualityAnswerFixtures.measurement("v2", RUNS, candidate), noise, settings, null));
    }

    private static QualityGateStatus status(QualityGateResult result, QualityGateCondition condition) {
        return result.finding(condition).status();
    }

    private static List<String> keys(String prefix, int from, int to) {
        List<String> keys = new ArrayList<>();
        for (int index = from; index <= to; index++) {
            keys.add(prefix + index);
        }
        return keys;
    }

    @Test
    void theSameAnswersAgainPassEveryCondition() {
        QualityGateResult result = gate(soundAnswers(), soundAnswers());

        assertThat(result.findings()).extracting(QualityGateFinding::condition)
                .containsExactly(QualityGateCondition.values());
        assertThat(result.findings()).extracting(QualityGateFinding::status).containsOnly(QualityGateStatus.PASSED);
        assertThat(result.status()).isEqualTo(QualityGateStatus.PASSED);
        for (QualityMetric metric : List.of(QualityMetric.MISS, QualityMetric.FALSE_STOP, QualityMetric.OVER_BLOCK,
                QualityMetric.FRICTION, QualityMetric.DEFERRAL, QualityMetric.CITATION_ACCURACY)) {
            assertThat(result.comparisons().get(metric).verdict()).as("%s", metric).isEqualTo(QualityVerdict.SAME);
        }
        assertThat(result.changes()).isEqualTo(QualityCaseChanges.none());
        assertThat(result.finding(QualityGateCondition.COMPARABLE_MEASUREMENTS).figures())
                .containsEntry("currentScoredAnswers", 84).containsEntry("candidateScoredAnswers", 84)
                .containsEntry("sameCaseSetVersion", 1).containsEntry("sameModelSetting", 1)
                .containsEntry("currentRepeats", 3).containsEntry("candidateRepeats", 3);
        assertThat(result.finding(QualityGateCondition.ENOUGH_CASES).figures())
                .containsEntry("stopRoots", 14).containsEntry("stopRootsShort", 0)
                .containsEntry("allowRoots", 14).containsEntry("allowRootsShort", 0)
                .containsEntry("undecidableRates", 0);
    }

    @Test
    void row1WithoutMeasurementsTakenTheSameWayTheCandidateIsBlocked() {
        QualityMeasurement current = QualityAnswerFixtures.measurement("v1", RUNS, soundAnswers());
        QualityMeasurement candidate = QualityAnswerFixtures.measurement("v2", RUNS, soundAnswers());
        List<QualityAnswer> failed = CASES.stream()
                .map(item -> QualityAnswer.failed(item.key(), 1, "model server busy")).toList();

        QualityGateResult noCandidate = QualityGateEvaluator.evaluate(
                new QualityGateInput(CASES, current, null, NOISE, SETTINGS, null));
        QualityGateResult noCurrent = QualityGateEvaluator.evaluate(
                new QualityGateInput(CASES, null, candidate, NOISE, SETTINGS, null));
        QualityGateResult nothingScored = QualityGateEvaluator.evaluate(new QualityGateInput(CASES, current,
                QualityAnswerFixtures.measurement("v2", RUNS, failed), NOISE, SETTINGS, null));

        // No measurement of the candidate: nothing else can be looked at.
        assertThat(noCandidate.status()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(status(noCandidate, QualityGateCondition.COMPARABLE_MEASUREMENTS))
                .isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(noCandidate.findings().subList(1, CONDITIONS)).extracting(QualityGateFinding::status)
                .containsOnly(QualityGateStatus.NOT_EVALUATED);
        // A measurement where every answer failed is no measurement, yet no rate condition says "blocked" for it.
        assertThat(status(nothingScored, QualityGateCondition.COMPARABLE_MEASUREMENTS))
                .isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(nothingScored.finding(QualityGateCondition.COMPARABLE_MEASUREMENTS).figures())
                .containsEntry("candidateScoredAnswers", 0);
        assertThat(nothingScored.findings().subList(1, CONDITIONS)).extracting(QualityGateFinding::status)
                .containsOnly(QualityGateStatus.NOT_EVALUATED);
        // No measurement of the version in use: what the candidate alone shows is still looked at.
        assertThat(noCurrent.status()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(status(noCurrent, QualityGateCondition.MUST_CATCH_NEVER_ALLOWED))
                .isEqualTo(QualityGateStatus.PASSED);
        assertThat(status(noCurrent, QualityGateCondition.MUST_CATCH_NOT_WEAKENED))
                .isEqualTo(QualityGateStatus.PASSED);
        assertThat(noCurrent.finding(QualityGateCondition.MUST_CATCH_NOT_WEAKENED).figures())
                .containsEntry("comparedWithCurrent", 0);
        assertThat(status(noCurrent, QualityGateCondition.MUST_NOT_BLOCK_NEVER_BLOCKED))
                .isEqualTo(QualityGateStatus.PASSED);
        assertThat(status(noCurrent, QualityGateCondition.MISS_NOT_INCREASED))
                .isEqualTo(QualityGateStatus.NOT_EVALUATED);
        assertThat(status(noCurrent, QualityGateCondition.STOPPING_NOT_INCREASED))
                .isEqualTo(QualityGateStatus.NOT_EVALUATED);
        assertThat(status(noCurrent, QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT))
                .isEqualTo(QualityGateStatus.NOT_EVALUATED);
        assertThat(status(noCurrent, QualityGateCondition.MODEL_USED_AND_CITATIONS_ACCURATE))
                .isEqualTo(QualityGateStatus.NOT_EVALUATED);
        assertThat(status(noCurrent, QualityGateCondition.NO_NEWLY_MISSED_OR_STOPPED_CASES))
                .isEqualTo(QualityGateStatus.NOT_EVALUATED);
        assertThat(noCurrent.comparisons()).isEmpty();

        // The same case set version, the same model setting and the same number of runs, or no comparison.
        for (QualityMeasurement other : List.of(
                new QualityMeasurement("v2", QualityAnswerFixtures.MODEL, QualityAnswerFixtures.CASE_SET, 2,
                        QualityAnswerFixtures.answers(CASES, 2, QualityGateEvaluatorTest::sound)),
                new QualityMeasurement("v2", QualityAnswerFixtures.MODEL, "case-set-version-2", RUNS, soundAnswers()),
                new QualityMeasurement("v2", "another-model", QualityAnswerFixtures.CASE_SET, RUNS, soundAnswers()))) {
            QualityGateResult result = QualityGateEvaluator.evaluate(
                    new QualityGateInput(CASES, current, other, NOISE, SETTINGS, null));
            assertThat(result.status()).isEqualTo(QualityGateStatus.BLOCKED);
            assertThat(status(result, QualityGateCondition.COMPARABLE_MEASUREMENTS))
                    .isEqualTo(QualityGateStatus.BLOCKED);
            assertThat(status(result, QualityGateCondition.MISS_NOT_INCREASED))
                    .isEqualTo(QualityGateStatus.NOT_EVALUATED);
        }
    }

    @Test
    void row2ACaseThatMustBeCaughtAllowedOnceBlocksTheCandidate() {
        QualityGateResult allowedOnce = gate(soundAnswers(),
                QualityAnswerFixtures.with(soundAnswers(), "M1", Set.of(2), QualityAction.ALLOW));
        QualityGateResult challenged = gate(soundAnswers(),
                QualityAnswerFixtures.with(soundAnswers(), "M1", EVERY_RUN, QualityAction.CHALLENGE));

        QualityGateFinding finding = allowedOnce.finding(QualityGateCondition.MUST_CATCH_NEVER_ALLOWED);
        assertThat(finding.status()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(finding.caseKeys()).containsExactly("M1");
        assertThat(finding.figures()).containsEntry("gradedCases", 2).containsEntry("failedCases", 1)
                .containsEntry("failedAnswers", 1);
        assertThat(allowedOnce.status()).isEqualTo(QualityGateStatus.BLOCKED);
        // One answer of 42 is within the noise: the miss rate does not block, the grade does.
        assertThat(allowedOnce.comparisons().get(QualityMetric.MISS).verdict()).isEqualTo(QualityVerdict.SAME);
        assertThat(status(allowedOnce, QualityGateCondition.MISS_NOT_INCREASED)).isEqualTo(QualityGateStatus.PASSED);
        // A challenge is not the one right action, but it is not an allow: the row beside this one takes it.
        assertThat(status(challenged, QualityGateCondition.MUST_CATCH_NEVER_ALLOWED))
                .isEqualTo(QualityGateStatus.PASSED);
        assertThat(status(challenged, QualityGateCondition.MUST_CATCH_NOT_WEAKENED))
                .isEqualTo(QualityGateStatus.BLOCKED);
        // Row 2 alone counts the allowing answers, so the allowed case is not counted twice.
        assertThat(status(allowedOnce, QualityGateCondition.MUST_CATCH_NOT_WEAKENED))
                .isEqualTo(QualityGateStatus.PASSED);
    }

    @Test
    void besideRow2ACaseThatMustBeCaughtNewlyAnsweredOutsideItsAllowedActionsOnceBlocksTheCandidate() {
        QualityGateResult challengedOnce = gate(soundAnswers(),
                QualityAnswerFixtures.with(soundAnswers(), "M1", Set.of(2), QualityAction.CHALLENGE));
        List<QualityAnswer> deferredBoth = QualityAnswerFixtures.with(
                QualityAnswerFixtures.with(soundAnswers(), "M1", EVERY_RUN, QualityAction.ESCALATE), "M2", EVERY_RUN,
                QualityAction.ESCALATE);
        QualityGateResult deferred = gate(soundAnswers(), deferredBoth);
        QualityGateResult uncompared = QualityGateEvaluator.evaluate(new QualityGateInput(CASES, null,
                QualityAnswerFixtures.measurement("v2", RUNS, deferredBoth), NOISE, SETTINGS, null));

        // K186: one challenge of a confirmed takeover the version in use blocks, in one run of three, blocks.
        QualityGateFinding finding = challengedOnce.finding(QualityGateCondition.MUST_CATCH_NOT_WEAKENED);
        assertThat(finding.status()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(finding.caseKeys()).containsExactly("M1");
        assertThat(finding.figures()).containsEntry("gradedCases", 2).containsEntry("unmeasuredCases", 0)
                .containsEntry("weakenedCases", 1).containsEntry("weakenedAnswers", 1)
                .containsEntry("currentAlsoOutsideCases", 0).containsEntry("comparedWithCurrent", 1);
        assertThat(challengedOnce.status()).isEqualTo(QualityGateStatus.BLOCKED);
        // No other row speaks of it: it is no miss, and the rates the gate compares do not move.
        assertThat(challengedOnce.findings()).filteredOn(other -> other.condition()
                        != QualityGateCondition.MUST_CATCH_NOT_WEAKENED)
                .extracting(QualityGateFinding::status).containsOnly(QualityGateStatus.PASSED);

        assertThat(deferred.finding(QualityGateCondition.MUST_CATCH_NOT_WEAKENED).caseKeys())
                .containsExactly("M1", "M2");
        assertThat(deferred.finding(QualityGateCondition.MUST_CATCH_NOT_WEAKENED).figures())
                .containsEntry("weakenedCases", 2).containsEntry("weakenedAnswers", 6);
        assertThat(deferred.status()).isEqualTo(QualityGateStatus.BLOCKED);
        // Without a measurement of the version in use nothing shows the answers are older than the candidate.
        assertThat(uncompared.finding(QualityGateCondition.MUST_CATCH_NOT_WEAKENED).status())
                .isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(uncompared.finding(QualityGateCondition.MUST_CATCH_NOT_WEAKENED).figures())
                .containsEntry("weakenedCases", 2).containsEntry("comparedWithCurrent", 0);
    }

    @Test
    void besideRow2ACaseTheVersionInUseAlsoAnswersOutsideItsAllowedActionsIsAWarningNotABlock() {
        List<QualityAnswer> challenging = QualityAnswerFixtures.with(soundAnswers(), "M1", EVERY_RUN,
                QualityAction.CHALLENGE);
        QualityGateResult sameAgain = gate(challenging, challenging);
        QualityGateResult betterThanAnAllow = gate(
                QualityAnswerFixtures.with(soundAnswers(), "M1", Set.of(1), QualityAction.ALLOW), challenging);
        QualityGateResult onceBefore = gate(
                QualityAnswerFixtures.with(soundAnswers(), "M1", Set.of(3), QualityAction.ESCALATE), challenging);

        // The same version measured again is not blocked for what the version in use does already.
        QualityGateFinding finding = sameAgain.finding(QualityGateCondition.MUST_CATCH_NOT_WEAKENED);
        assertThat(finding.status()).isEqualTo(QualityGateStatus.WARNING);
        assertThat(finding.caseKeys()).containsExactly("M1");
        assertThat(finding.figures()).containsEntry("weakenedCases", 0).containsEntry("weakenedAnswers", 0)
                .containsEntry("currentAlsoOutsideCases", 1);
        assertThat(sameAgain.status()).isEqualTo(QualityGateStatus.WARNING);
        // A version in use that allowed the case once: a challenge is no weakening the candidate brings.
        assertThat(status(betterThanAnAllow, QualityGateCondition.MUST_CATCH_NOT_WEAKENED))
                .isEqualTo(QualityGateStatus.WARNING);
        assertThat(status(betterThanAnAllow, QualityGateCondition.MUST_CATCH_NEVER_ALLOWED))
                .isEqualTo(QualityGateStatus.PASSED);
        // One run of the version in use outside the allowed actions makes the case one it answers so.
        assertThat(status(onceBefore, QualityGateCondition.MUST_CATCH_NOT_WEAKENED))
                .isEqualTo(QualityGateStatus.WARNING);
    }

    @Test
    void row3ACaseThatMustNotBeBlockedBlockedOnceBlocksTheCandidate() {
        QualityGateResult blockedOnce = gate(soundAnswers(),
                QualityAnswerFixtures.with(soundAnswers(), "P2", Set.of(3), QualityAction.BLOCK));

        QualityGateFinding finding = blockedOnce.finding(QualityGateCondition.MUST_NOT_BLOCK_NEVER_BLOCKED);
        assertThat(finding.status()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(finding.caseKeys()).containsExactly("P2");
        assertThat(finding.figures()).containsEntry("gradedCases", 2).containsEntry("failedAnswers", 1);
        assertThat(status(blockedOnce, QualityGateCondition.STOPPING_NOT_INCREASED))
                .isEqualTo(QualityGateStatus.PASSED);
        assertThat(blockedOnce.status()).isEqualTo(QualityGateStatus.BLOCKED);
    }

    @Test
    void row4MissesThatGrewSignificantlyBlockTheCandidate() {
        List<String> missed = keys("T", 1, 6);

        QualityGateResult result = gate(soundAnswers(),
                answering(item -> missed.contains(item.key()) ? QualityAction.ALLOW : sound(item)));

        QualityGateFinding finding = result.finding(QualityGateCondition.MISS_NOT_INCREASED);
        assertThat(finding.status()).isEqualTo(QualityGateStatus.BLOCKED);
        QualityComparison miss = finding.comparisons().get(0);
        assertThat(miss.metric()).isEqualTo(QualityMetric.MISS);
        assertThat(miss.verdict()).isEqualTo(QualityVerdict.WORSE);
        assertThat(miss.currentValue()).isZero();
        assertThat(miss.candidateValue()).isEqualTo(18.0 / 42);
        assertThat(miss.worseRoots()).isEqualTo(6);
        assertThat(miss.worseProbability()).isEqualTo(1.0 / 64);
        assertThat(result.changes().newlyMissed()).containsExactlyElementsOf(missed);
        // The rate already blocks, so the newly missed cases are not a warning of their own.
        assertThat(status(result, QualityGateCondition.NO_NEWLY_MISSED_OR_STOPPED_CASES))
                .isEqualTo(QualityGateStatus.PASSED);
        assertThat(status(result, QualityGateCondition.STOPPING_NOT_INCREASED)).isEqualTo(QualityGateStatus.PASSED);
        assertThat(result.status()).isEqualTo(QualityGateStatus.BLOCKED);
    }

    @Test
    void row5AVersionThatChallengesEveryRequestIsBlockedForItsFriction() {
        QualityGateResult result = gate(soundAnswers(), answering(item -> QualityAction.CHALLENGE));

        QualityGateFinding finding = result.finding(QualityGateCondition.STOPPING_NOT_INCREASED);
        assertThat(finding.status()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(finding.comparisons()).extracting(QualityComparison::metric).containsExactly(
                QualityMetric.FALSE_STOP, QualityMetric.OVER_BLOCK, QualityMetric.FRICTION, QualityMetric.DEFERRAL);
        // A challenge is an allowed action of normal work, so only the friction shows it.
        assertThat(finding.comparisons()).extracting(QualityComparison::verdict).containsExactly(
                QualityVerdict.SAME, QualityVerdict.SAME, QualityVerdict.WORSE, QualityVerdict.SAME);
        assertThat(finding.figures()).containsEntry("worseRates", 1L);
        QualityComparison friction = result.comparisons().get(QualityMetric.FRICTION);
        assertThat(friction.currentValue()).isZero();
        assertThat(friction.candidateValue()).isEqualTo(1.0);
        assertThat(friction.worseRoots()).isEqualTo(14);
        // It misses nothing and blocks nothing; it challenges the two cases that must be blocked, which the row beside
        // row 2 takes.
        assertThat(status(result, QualityGateCondition.MISS_NOT_INCREASED)).isEqualTo(QualityGateStatus.PASSED);
        assertThat(status(result, QualityGateCondition.MUST_CATCH_NEVER_ALLOWED)).isEqualTo(QualityGateStatus.PASSED);
        assertThat(result.finding(QualityGateCondition.MUST_CATCH_NOT_WEAKENED).caseKeys())
                .containsExactly("M1", "M2");
        assertThat(status(result, QualityGateCondition.MUST_NOT_BLOCK_NEVER_BLOCKED))
                .isEqualTo(QualityGateStatus.PASSED);
        // From no friction to all of it is far beyond the limit of the friction increase.
        assertThat(result.finding(QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT).figures())
                .containsEntry("increase", 1.0);
        assertThat(status(result, QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT))
                .isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(result.status()).isEqualTo(QualityGateStatus.BLOCKED);
    }

    @Test
    void besideRow5AFrictionThatGrowsByTheLimitOrMoreBlocksWhateverTheSignificance() {
        List<String> challenged = keys("N", 1, 5);
        List<QualityAnswer> candidate = answering(item -> challenged.contains(item.key()) ? QualityAction.CHALLENGE
                : sound(item));

        // Without a measured noise the friction cannot be called worse: only its limit speaks.
        QualityGateResult result = gate(soundAnswers(), candidate, QualityNoise.unknown(), SETTINGS);

        QualityGateFinding finding = result.finding(QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT);
        assertThat(finding.status()).isEqualTo(QualityGateStatus.BLOCKED);
        // 5 of the 14 normal cases in every run: 15 of 42 answers, 35.7 points over none.
        assertThat(finding.figures()).containsEntry("pairedCases", 14).containsEntry("currentRate", 0.0)
                .containsEntry("candidateRate", 15.0 / 42).containsEntry("increase", 15.0 / 42)
                .containsEntry("limit", 0.30).containsEntry("newlyStoppedCases", 5);
        assertThat(finding.caseKeys()).containsExactlyElementsOf(challenged);
        assertThat(finding.comparisons()).extracting(QualityComparison::metric).containsExactly(QualityMetric.FRICTION);
        assertThat(result.comparisons().get(QualityMetric.FRICTION).verdict()).isEqualTo(QualityVerdict.UNDECIDABLE);
        assertThat(status(result, QualityGateCondition.STOPPING_NOT_INCREASED)).isEqualTo(QualityGateStatus.PASSED);
        // The row blocks for the newly stopped cases, so they are not a warning of their own.
        assertThat(status(result, QualityGateCondition.NO_NEWLY_MISSED_OR_STOPPED_CASES))
                .isEqualTo(QualityGateStatus.PASSED);
        assertThat(result.status()).isEqualTo(QualityGateStatus.BLOCKED);

        // A rise of exactly the limit blocks, though the two rates differ in the last bits as doubles: 3 of 42 to 12.
        List<QualityAnswer> before = answering(item -> "N1".equals(item.key()) ? QualityAction.CHALLENGE
                : sound(item));
        List<QualityAnswer> after = answering(item -> keys("N", 1, 4).contains(item.key()) ? QualityAction.CHALLENGE
                : sound(item));
        QualityGateFinding exactly = gate(before, after, NOISE, new QualityGateSettings(0.05, 0.05, 10, 10, 9.0 / 42))
                .finding(QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT);
        assertThat(exactly.status()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(gate(before, after, NOISE, new QualityGateSettings(0.05, 0.05, 10, 10, 0.22))
                .finding(QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT).status())
                .isEqualTo(QualityGateStatus.PASSED);
        // Less friction, or the same, is no rise.
        QualityGateFinding fewer = gate(after, before).finding(QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT);
        assertThat(fewer.status()).isEqualTo(QualityGateStatus.PASSED);
        assertThat(fewer.figures().get("increase").doubleValue()).isNegative();
        assertThat(status(gate(soundAnswers(), soundAnswers()), QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT))
                .isEqualTo(QualityGateStatus.PASSED);
    }

    @Test
    void besideRow5WithoutCasesThatMustBeAllowedThereIsNoFrictionToCompare() {
        List<QualityCase> threats = CASES.stream().filter(QualityCase::shouldStop).toList();
        List<QualityAnswer> answers = QualityAnswerFixtures.answers(threats, RUNS, QualityGateEvaluatorTest::sound);

        QualityGateFinding finding = QualityGateEvaluator.evaluate(new QualityGateInput(threats,
                QualityAnswerFixtures.measurement("v1", RUNS, answers),
                QualityAnswerFixtures.measurement("v2", RUNS, answers), NOISE, SETTINGS, null))
                .finding(QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT);

        assertThat(finding.status()).isEqualTo(QualityGateStatus.PASSED);
        assertThat(finding.figures()).containsEntry("pairedCases", 0);
    }

    @Test
    void row5AVersionThatOnlyDefersIsBlockedForItsDeferring() {
        // Deferring a threat is an allowed action: nothing but the deferral rate shows it.
        QualityGateResult threatsDeferred = gate(soundAnswers(),
                answering(item -> item.grade() == QualityCaseGrade.ORDINARY && item.shouldStop()
                        ? QualityAction.ESCALATE : sound(item)));
        QualityGateResult everythingDeferred = gate(soundAnswers(), answering(item -> QualityAction.ESCALATE));

        QualityGateFinding finding = threatsDeferred.finding(QualityGateCondition.STOPPING_NOT_INCREASED);
        assertThat(finding.status()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(finding.comparisons()).extracting(QualityComparison::verdict).containsExactly(
                QualityVerdict.SAME, QualityVerdict.SAME, QualityVerdict.SAME, QualityVerdict.WORSE);
        QualityComparison deferral = threatsDeferred.comparisons().get(QualityMetric.DEFERRAL);
        assertThat(deferral.candidateValue()).isEqualTo(36.0 / 84);
        assertThat(deferral.worseRoots()).isEqualTo(12);
        assertThat(status(threatsDeferred, QualityGateCondition.MISS_NOT_INCREASED))
                .isEqualTo(QualityGateStatus.PASSED);
        assertThat(threatsDeferred.status()).isEqualTo(QualityGateStatus.BLOCKED);

        assertThat(everythingDeferred.comparisons().get(QualityMetric.DEFERRAL).verdict())
                .isEqualTo(QualityVerdict.WORSE);
        assertThat(everythingDeferred.comparisons().get(QualityMetric.DEFERRAL).candidateValue()).isEqualTo(1.0);
        assertThat(everythingDeferred.finding(QualityGateCondition.STOPPING_NOT_INCREASED).figures())
                .containsEntry("worseRates", 3L);
        assertThat(status(everythingDeferred, QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT))
                .isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(status(threatsDeferred, QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT))
                .isEqualTo(QualityGateStatus.PASSED);
        assertThat(everythingDeferred.status()).isEqualTo(QualityGateStatus.BLOCKED);
    }

    @Test
    void row5BlocksBeyondTheRightAnswerBlockTheCandidate() {
        List<String> blocked = keys("N", 1, 6);

        QualityGateResult result = gate(soundAnswers(),
                answering(item -> blocked.contains(item.key()) ? QualityAction.BLOCK : sound(item)));

        QualityGateFinding finding = result.finding(QualityGateCondition.STOPPING_NOT_INCREASED);
        assertThat(finding.status()).isEqualTo(QualityGateStatus.BLOCKED);
        // A block of normal work is a false stop, a block beyond the right answer and friction at once.
        assertThat(finding.comparisons()).extracting(QualityComparison::verdict).containsExactly(
                QualityVerdict.WORSE, QualityVerdict.WORSE, QualityVerdict.WORSE, QualityVerdict.SAME);
        assertThat(result.comparisons().get(QualityMetric.OVER_BLOCK).candidateValue()).isEqualTo(18.0 / 42);
        assertThat(result.changes().newlyStopped()).containsExactlyElementsOf(blocked);
    }

    @Test
    void row6TooManyAnswersDecidedWithoutTheModelOrLessAccurateCitationsBlockTheCandidate() {
        QualityGateResult five = gate(soundAnswers(), withoutModel(5));
        QualityGateResult four = gate(soundAnswers(), withoutModel(4));
        QualityGateResult fiveUnderALooserLimit = gate(soundAnswers(), withoutModel(5), NOISE,
                new QualityGateSettings(0.10, 0.05, 10, 10, 0.30));
        List<QualityAnswer> careless = soundAnswers().stream().map(answer -> new QualityAnswer(answer.caseKey(),
                answer.run(), answer.firstAction(), null, false, false, 3, 1, 7000L, 120, false, null)).toList();
        QualityGateResult lessAccurate = gate(soundAnswers(), careless);

        // 5 of 84 answers is 5.95%, over the 5% limit; 4 of 84 is 4.76%.
        QualityGateFinding finding = five.finding(QualityGateCondition.MODEL_USED_AND_CITATIONS_ACCURATE);
        assertThat(finding.status()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(finding.figures()).containsEntry("modelLessAnswers", 5L).containsEntry("answers", 84L)
                .containsEntry("modelLessRate", 5.0 / 84).containsEntry("modelLessLimit", 0.05);
        assertThat(five.status()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(status(four, QualityGateCondition.MODEL_USED_AND_CITATIONS_ACCURATE))
                .isEqualTo(QualityGateStatus.PASSED);
        // The limit is a setting.
        assertThat(status(fiveUnderALooserLimit, QualityGateCondition.MODEL_USED_AND_CITATIONS_ACCURATE))
                .isEqualTo(QualityGateStatus.PASSED);

        QualityGateFinding citations = lessAccurate.finding(QualityGateCondition.MODEL_USED_AND_CITATIONS_ACCURATE);
        assertThat(citations.status()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(citations.comparisons()).singleElement().satisfies(comparison -> {
            assertThat(comparison.metric()).isEqualTo(QualityMetric.CITATION_ACCURACY);
            assertThat(comparison.verdict()).isEqualTo(QualityVerdict.WORSE);
            assertThat(comparison.currentValue()).isEqualTo(1.0);
            assertThat(comparison.candidateValue()).isEqualTo(84.0 / 252);
        });
        assertThat(citations.figures()).containsEntry("modelLessAnswers", 0L);
    }

    /** The sound answers with the first few decided without the model. */
    private static List<QualityAnswer> withoutModel(int count) {
        List<QualityAnswer> answers = new ArrayList<>(soundAnswers());
        for (int index = 0; index < count; index++) {
            QualityAnswer answer = answers.get(index);
            answers.set(index, new QualityAnswer(answer.caseKey(), answer.run(), answer.firstAction(), null, false,
                    true, 3, 3, 7000L, 120, false, null));
        }
        return answers;
    }

    @Test
    void row7And8NewlyMissedOrStoppedCasesShortOfSignificanceAreAWarningWithTheCases() {
        List<QualityAnswer> candidate = soundAnswers();
        candidate = QualityAnswerFixtures.with(candidate, "T1", EVERY_RUN, QualityAction.ALLOW);
        candidate = QualityAnswerFixtures.with(candidate, "T2", EVERY_RUN, QualityAction.ALLOW);
        candidate = QualityAnswerFixtures.with(candidate, "N1", EVERY_RUN, QualityAction.CHALLENGE);

        QualityGateResult result = gate(soundAnswers(), candidate);

        // 6 of 42 and 3 of 42 are beyond the noise, but two roots and one root cannot show a version is worse.
        assertThat(result.comparisons().get(QualityMetric.MISS).verdict()).isEqualTo(QualityVerdict.UNDECIDABLE);
        assertThat(result.comparisons().get(QualityMetric.FRICTION).verdict()).isEqualTo(QualityVerdict.UNDECIDABLE);
        assertThat(status(result, QualityGateCondition.MISS_NOT_INCREASED)).isEqualTo(QualityGateStatus.PASSED);
        assertThat(status(result, QualityGateCondition.STOPPING_NOT_INCREASED)).isEqualTo(QualityGateStatus.PASSED);
        QualityGateFinding changed = result.finding(QualityGateCondition.NO_NEWLY_MISSED_OR_STOPPED_CASES);
        assertThat(changed.status()).isEqualTo(QualityGateStatus.WARNING);
        assertThat(changed.caseKeys()).containsExactly("T1", "T2", "N1");
        assertThat(changed.figures()).containsEntry("newlyMissedCases", 2).containsEntry("newlyStoppedCases", 1);
        // The cases cannot tell: the warning names the rates that could not be decided.
        QualityGateFinding enough = result.finding(QualityGateCondition.ENOUGH_CASES);
        assertThat(enough.status()).isEqualTo(QualityGateStatus.WARNING);
        assertThat(enough.comparisons()).extracting(QualityComparison::metric)
                .containsExactly(QualityMetric.MISS, QualityMetric.FRICTION);
        assertThat(enough.figures()).containsEntry("undecidableRates", 2).containsEntry("stopRootsShort", 0)
                .containsEntry("allowRootsShort", 0);
        assertThat(result.status()).isEqualTo(QualityGateStatus.WARNING);
    }

    @Test
    void theChangedCasesAreThoseOneVersionNeverAndTheOtherAtLeastOnceGotWrong() {
        List<QualityAnswer> current = soundAnswers();
        current = QualityAnswerFixtures.with(current, "T12", EVERY_RUN, QualityAction.ALLOW);
        current = QualityAnswerFixtures.with(current, "N12", EVERY_RUN, QualityAction.CHALLENGE);
        current = QualityAnswerFixtures.with(current, "T3", Set.of(1), QualityAction.ALLOW);
        List<QualityAnswer> candidate = soundAnswers();
        candidate = QualityAnswerFixtures.with(candidate, "T1", Set.of(2), QualityAction.ALLOW);
        candidate = QualityAnswerFixtures.with(candidate, "N1", Set.of(3), QualityAction.CHALLENGE);
        candidate = QualityAnswerFixtures.with(candidate, "T3", Set.of(2), QualityAction.ALLOW);

        QualityGateResult result = gate(current, candidate);

        assertThat(result.changes().newlyMissed()).containsExactly("T1");
        assertThat(result.changes().newlyCaught()).containsExactly("T12");
        assertThat(result.changes().newlyStopped()).containsExactly("N1");
        assertThat(result.changes().newlyReleased()).containsExactly("N12");
        // T3 is missed once by either version: not a change of the cases, only of the run.
        assertThat(result.changes().newlyMissed()).doesNotContain("T3");
        assertThat(result.changes().newlyCaught()).doesNotContain("T3");
        assertThat(status(result, QualityGateCondition.NO_NEWLY_MISSED_OR_STOPPED_CASES))
                .isEqualTo(QualityGateStatus.WARNING);
        // The candidate misses and stops less overall, so nothing blocks.
        assertThat(result.status()).isEqualTo(QualityGateStatus.WARNING);
    }

    @Test
    void aDifferenceWithinTheNoiseDoesNotBlock() {
        QualityGateResult result = gate(soundAnswers(),
                QualityAnswerFixtures.with(soundAnswers(), "T1", Set.of(1), QualityAction.ALLOW));

        // One answer of 42 (2.4%) against a noise of 5%: the same.
        QualityComparison miss = result.comparisons().get(QualityMetric.MISS);
        assertThat(miss.verdict()).isEqualTo(QualityVerdict.SAME);
        assertThat(miss.candidateValue()).isEqualTo(1.0 / 42);
        assertThat(status(result, QualityGateCondition.MISS_NOT_INCREASED)).isEqualTo(QualityGateStatus.PASSED);
        assertThat(status(result, QualityGateCondition.ENOUGH_CASES)).isEqualTo(QualityGateStatus.PASSED);
        // The case is still named, as a warning.
        assertThat(result.finding(QualityGateCondition.NO_NEWLY_MISSED_OR_STOPPED_CASES).caseKeys())
                .containsExactly("T1");
        assertThat(result.status()).isEqualTo(QualityGateStatus.WARNING);
    }

    @Test
    void withoutMeasuredNoiseTheRatesWarnAndOnlyTheGradedCasesBlock() {
        List<String> missed = keys("T", 1, 6);
        List<QualityAnswer> worse = answering(item -> missed.contains(item.key()) ? QualityAction.ALLOW : sound(item));

        QualityGateResult result = gate(soundAnswers(), worse, null, SETTINGS);
        QualityGateResult gradedToo = gate(soundAnswers(),
                QualityAnswerFixtures.with(worse, "M2", Set.of(1), QualityAction.ALLOW), QualityNoise.unknown(),
                SETTINGS);

        // The same answers that block with a measured noise: without it nobody has shown what is more than noise.
        assertThat(result.comparisons().get(QualityMetric.MISS).verdict()).isEqualTo(QualityVerdict.UNDECIDABLE);
        assertThat(status(result, QualityGateCondition.MISS_NOT_INCREASED)).isEqualTo(QualityGateStatus.PASSED);
        assertThat(status(result, QualityGateCondition.NO_NEWLY_MISSED_OR_STOPPED_CASES))
                .isEqualTo(QualityGateStatus.WARNING);
        QualityGateFinding enough = result.finding(QualityGateCondition.ENOUGH_CASES);
        assertThat(enough.status()).isEqualTo(QualityGateStatus.WARNING);
        assertThat(enough.figures()).containsEntry("ratesWithoutNoise", 6L).containsEntry("undecidableRates", 1);
        assertThat(result.status()).isEqualTo(QualityGateStatus.WARNING);
        assertThat(status(gradedToo, QualityGateCondition.MUST_CATCH_NEVER_ALLOWED))
                .isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(gradedToo.status()).isEqualTo(QualityGateStatus.BLOCKED);
    }

    @Test
    void row8TooFewRootsAreAWarningWithTheNumberShort() {
        QualityGateResult result = gate(soundAnswers(), soundAnswers(), NOISE, QualityGateSettings.defaults());

        // The plan asks for 200 distinct roots to stop and 300 to allow; here are 14 and 14.
        QualityGateFinding enough = result.finding(QualityGateCondition.ENOUGH_CASES);
        assertThat(enough.status()).isEqualTo(QualityGateStatus.WARNING);
        assertThat(enough.figures()).containsEntry("stopRoots", 14).containsEntry("stopRootsNeeded", 200)
                .containsEntry("stopRootsShort", 186).containsEntry("allowRoots", 14)
                .containsEntry("allowRootsNeeded", 300).containsEntry("allowRootsShort", 286);
        assertThat(result.status()).isEqualTo(QualityGateStatus.WARNING);
    }

    @Test
    void row9AVersionWorseOnlyOnTheCasesThatCameInAfterItWasMadeDrawsAWarning() {
        Instant made = Instant.parse("2026-11-20T00:00:00Z");
        List<QualityCase> cases = new ArrayList<>();
        for (int index = 1; index <= 20; index++) {
            // Cases the author of the version could see: without a recorded time, or from before the version.
            cases.add(QualityFixtures.of("E" + index, null, QualityCaseClass.THREAT, QualityFixtures.STOP,
                    QualityCaseGrade.ORDINARY, QualityCaseOrigin.CONTEXA,
                    index % 2 == 0 ? null : made.minus(Duration.ofDays(index))));
        }
        for (int index = 1; index <= 8; index++) {
            cases.add(QualityFixtures.of("L" + index, null, QualityCaseClass.THREAT, QualityFixtures.STOP,
                    QualityCaseGrade.ORDINARY, QualityCaseOrigin.OPERATION, made.plus(Duration.ofDays(index))));
        }
        for (int index = 1; index <= 10; index++) {
            cases.add(QualityFixtures.normal("N" + index));
        }
        QualityGateSettings settings = SETTINGS;
        // Fitted to the cases it saw: all of them answered right, all the later ones missed.
        List<QualityAnswer> fitted = QualityAnswerFixtures.answers(cases, 1, item -> {
            if (!item.shouldStop()) {
                return QualityAction.ALLOW;
            }
            return item.key().startsWith("L") ? QualityAction.ALLOW : QualityAction.CHALLENGE;
        });
        // Missing half of the cases everywhere is not "only on the later cases".
        List<QualityAnswer> weakEverywhere = QualityAnswerFixtures.answers(cases, 1, item -> {
            if (!item.shouldStop()) {
                return QualityAction.ALLOW;
            }
            return Integer.parseInt(item.key().substring(1)) % 2 == 0 ? QualityAction.ALLOW : QualityAction.CHALLENGE;
        });

        QualityGateResult result = evaluate(cases, fitted, settings, made);
        QualityGateResult everywhere = evaluate(cases, weakEverywhere, settings, made);
        QualityGateResult timeUnknown = evaluate(cases, fitted, settings, null);

        QualityGateFinding finding = result.finding(QualityGateCondition.NOT_WORSE_ON_LATER_CASES_ONLY);
        assertThat(finding.status()).isEqualTo(QualityGateStatus.WARNING);
        assertThat(finding.caseKeys()).containsExactlyElementsOf(keys("L", 1, 8));
        assertThat(finding.figures()).containsEntry("laterCases", 8).containsEntry("earlierCases", 30)
                .containsEntry("MISS.earlierRate", 0.0).containsEntry("MISS.laterRate", 1.0)
                .containsEntry("MISS.earlierRoots", 20).containsEntry("MISS.earlierMarkedRoots", 0)
                .containsEntry("MISS.laterRoots", 8).containsEntry("MISS.laterMarkedRoots", 8);
        // 8 marked of 8 later roots against 0 of 20: one arrangement of C(28,8).
        assertThat(finding.figures().get("MISS.probability").doubleValue()).isBetween(1.0 / 3108106, 1.0 / 3108104);
        // The version in use gives the same answers here, so nothing else speaks: the warning is the whole verdict.
        assertThat(result.findings()).filteredOn(other -> other.condition()
                        != QualityGateCondition.NOT_WORSE_ON_LATER_CASES_ONLY)
                .extracting(QualityGateFinding::status).containsOnly(QualityGateStatus.PASSED);
        assertThat(result.status()).isEqualTo(QualityGateStatus.WARNING);

        assertThat(status(everywhere, QualityGateCondition.NOT_WORSE_ON_LATER_CASES_ONLY))
                .isEqualTo(QualityGateStatus.PASSED);
        assertThat(everywhere.finding(QualityGateCondition.NOT_WORSE_ON_LATER_CASES_ONLY).figures())
                .containsEntry("MISS.earlierRate", 0.5).containsEntry("MISS.laterRate", 0.5);
        // Without the time the version was made no case is a later one.
        assertThat(status(timeUnknown, QualityGateCondition.NOT_WORSE_ON_LATER_CASES_ONLY))
                .isEqualTo(QualityGateStatus.PASSED);
        assertThat(timeUnknown.finding(QualityGateCondition.NOT_WORSE_ON_LATER_CASES_ONLY).figures())
                .containsEntry("laterCases", 0);

        // Two later cases cannot tell: both missed, against half of the earlier ones (E1 to E20, L1 and L2).
        List<QualityCase> fewLater = cases.subList(0, 22);
        List<QualityAnswer> fewAnswers = QualityAnswerFixtures.answers(fewLater, 1,
                item -> item.key().startsWith("L") || Integer.parseInt(item.key().substring(1)) % 2 == 0
                        ? QualityAction.ALLOW : QualityAction.CHALLENGE);
        QualityGateFinding few = evaluate(fewLater, fewAnswers, settings, made)
                .finding(QualityGateCondition.NOT_WORSE_ON_LATER_CASES_ONLY);
        assertThat(few.status()).isEqualTo(QualityGateStatus.PASSED);
        assertThat(few.figures()).containsEntry("MISS.laterRate", 1.0).containsEntry("MISS.earlierRate", 0.5);
        assertThat(few.figures().get("MISS.probability").doubleValue()).isGreaterThan(0.05);
    }

    /** The gate on the cases, with the version in use giving the same answers as the candidate. */
    private static QualityGateResult evaluate(List<QualityCase> cases, List<QualityAnswer> answers,
                                              QualityGateSettings settings, Instant candidateCreatedAt) {
        return QualityGateEvaluator.evaluate(new QualityGateInput(cases,
                QualityAnswerFixtures.measurement("v1", 1, answers),
                QualityAnswerFixtures.measurement("v2", 1, answers), NOISE, settings, candidateCreatedAt));
    }

    @Test
    void theRecordedLocalMeasurementAgainstItselfIsNotBlockedAndWarnsOfTooFewRoots() {
        QualityCaseSet set = QualityCaseSetReader.contexaDefault();
        List<QualityAnswer> answers = QualityAnswerFixtures.localAnswers("n1-60.jsonl");
        answers.addAll(QualityAnswerFixtures.localAnswers("n1-ver-base.jsonl"));
        QualityMeasurement current = new QualityMeasurement("2026.11.18-v1.0", QualityAnswerFixtures.MODEL,
                set.version(), 1, answers);
        QualityMeasurement again = new QualityMeasurement("2026.11.18-v1.0-again", QualityAnswerFixtures.MODEL,
                set.version(), 1, answers);
        QualityMeasurement takingOver = new QualityMeasurement("careless", QualityAnswerFixtures.MODEL,
                set.version(), 1, QualityAnswerFixtures.with(answers, "VER-S01", Set.of(1), QualityAction.ALLOW));

        QualityGateResult result = QualityGateEvaluator.evaluate(new QualityGateInput(set.cases(), current, again,
                QualityNoise.unknown(), QualityGateSettings.defaults(), null));
        QualityGateResult blocked = QualityGateEvaluator.evaluate(new QualityGateInput(set.cases(), current,
                takingOver, QualityNoise.unknown(), QualityGateSettings.defaults(), null));

        // The same answers are the same without any noise measured; the control case challenged is not allowed.
        assertThat(result.comparisons().get(QualityMetric.MISS).verdict()).isEqualTo(QualityVerdict.SAME);
        assertThat(result.comparisons().get(QualityMetric.MISS).currentValue()).isEqualTo(13.0 / 55);
        assertThat(result.finding(QualityGateCondition.MUST_CATCH_NEVER_ALLOWED).figures())
                .containsEntry("gradedCases", 10).containsEntry("failedCases", 0);
        // It is challenged by both, so it is a warning: the same version measured again is not blocked for it.
        QualityGateFinding weakened = result.finding(QualityGateCondition.MUST_CATCH_NOT_WEAKENED);
        assertThat(weakened.status()).isEqualTo(QualityGateStatus.WARNING);
        assertThat(weakened.caseKeys()).containsExactly("VER-A1T");
        assertThat(weakened.figures()).containsEntry("weakenedCases", 0).containsEntry("currentAlsoOutsideCases", 1);
        // The default set alone is 25 roots to stop and 10 to allow: the gate says it cannot tell versions apart.
        QualityGateFinding enough = result.finding(QualityGateCondition.ENOUGH_CASES);
        assertThat(enough.status()).isEqualTo(QualityGateStatus.WARNING);
        assertThat(enough.figures()).containsEntry("stopRoots", 25).containsEntry("stopRootsShort", 175)
                .containsEntry("allowRoots", 10).containsEntry("allowRootsShort", 290)
                .containsEntry("undecidableRates", 0);
        assertThat(result.findings()).filteredOn(finding -> finding.condition() != QualityGateCondition.ENOUGH_CASES
                        && finding.condition() != QualityGateCondition.MUST_CATCH_NOT_WEAKENED)
                .extracting(QualityGateFinding::status).containsOnly(QualityGateStatus.PASSED);
        assertThat(result.status()).isEqualTo(QualityGateStatus.WARNING);

        // Allowing one confirmed account takeover blocks, whatever the rates say.
        assertThat(blocked.finding(QualityGateCondition.MUST_CATCH_NEVER_ALLOWED).caseKeys())
                .containsExactly("VER-S01");
        assertThat(blocked.status()).isEqualTo(QualityGateStatus.BLOCKED);
    }
}
