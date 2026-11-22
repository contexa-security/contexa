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

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 3.3: the metrics of a measurement. Every rate is checked against a hand count, the boundaries against what
 * they must leave out, and the whole against the recorded local measurement of 2026-11-19.
 */
class QualityScorerTest {

    private static final Offset<Double> EXACT = Offset.offset(1e-12);

    private static QualityAnswer answer(String key, int run, QualityAction first, QualityAction closing,
                                        boolean reasked, boolean withoutModel, int cited, int accurate, long millis,
                                        int tokens) {
        return new QualityAnswer(key, run, first, closing, reasked, withoutModel, cited, accurate, millis, tokens,
                false, null);
    }

    private static void assertRate(QualityScore score, QualityMetric metric, long events, long trials) {
        assertThat(score.rate(metric).events()).as("%s events", metric).isEqualTo(events);
        assertThat(score.rate(metric).trials()).as("%s trials", metric).isEqualTo(trials);
    }

    @Test
    void everyRateCountsWhatItsDefinitionSays() {
        List<QualityCase> cases = List.of(QualityFixtures.threat("T1"), QualityFixtures.threat("T2"),
                QualityFixtures.uncertain("U1"), QualityFixtures.normal("N1"), QualityFixtures.normal("N2"),
                QualityFixtures.mustCatch("M1"));
        List<QualityAnswer> answers = List.of(
                answer("T1", 1, QualityAction.ALLOW, null, true, false, 3, 2, 1000, 100),
                answer("T2", 1, QualityAction.ESCALATE, null, false, false, 2, 2, 2000, 110),
                answer("U1", 1, QualityAction.ALLOW, null, false, true, 0, 0, 3000, 120),
                answer("N1", 1, QualityAction.CHALLENGE, null, false, false, 0, 0, 4000, 130),
                answer("N2", 1, QualityAction.BLOCK, null, false, false, 0, 0, 5000, 140),
                answer("M1", 1, QualityAction.CHALLENGE, null, false, false, 0, 0, 6000, 150));

        QualityScore score = QualityScorer.score(cases, answers, QualityActionBasis.FIRST_ANSWER);

        // Cases to stop are T1, T2, M1 and the uncertain U1; T1 and U1 were allowed.
        assertRate(score, QualityMetric.MISS, 2, 4);
        // Cases to allow are N1 and N2: BLOCK is outside the allowed actions, CHALLENGE is inside but is friction.
        assertRate(score, QualityMetric.FALSE_STOP, 1, 2);
        assertRate(score, QualityMetric.FRICTION, 2, 2);
        // Only N1 and N2 have a right answer without BLOCK.
        assertRate(score, QualityMetric.OVER_BLOCK, 1, 2);
        // Inside the allowed actions: T2 (ESCALATE) and N1 (CHALLENGE); M1 allows BLOCK alone.
        assertRate(score, QualityMetric.ACTION_HIT, 2, 6);
        assertRate(score, QualityMetric.DEFERRAL, 1, 6);
        assertRate(score, QualityMetric.REASK, 1, 6);
        assertRate(score, QualityMetric.MODEL_LESS, 1, 6);
        // The accuracy is a share of cited facts, not of answers.
        assertRate(score, QualityMetric.CITATION_ACCURACY, 4, 5);
        assertThat(score.rate(QualityMetric.CITATION_ACCURACY).cases()).isEqualTo(2);
        assertThat(score.rate(QualityMetric.MISS).value()).isEqualTo(0.5);
        assertThat(score.rate(QualityMetric.MISS).roots()).isEqualTo(4);
        // One run cannot show whether a case is answered the same way every time.
        assertThat(score.rate(QualityMetric.CONSISTENCY).defined()).isFalse();
        assertThat(score.decisionMillis()).isEqualTo(new QualitySpread(6, 3500.0, 6000.0));
        assertThat(score.answerTokens()).isEqualTo(new QualitySpread(6, 125.0, 150.0));
        assertThat(score.answers()).isEqualTo(6);
        assertThat(score.scoredAnswers()).isEqualTo(6);
        assertThat(score.incompleteAnswers()).isZero();
        assertThat(score.cases()).isEqualTo(6);
        assertThat(score.unmeasuredCases()).isZero();
        assertThat(score.roots()).isEqualTo(6);
    }

    @Test
    void theSameCountIsTakenOnTheFirstAnswerOrOnTheFinalAction() {
        List<QualityCase> cases = List.of(QualityFixtures.threat("T1"), QualityFixtures.threat("T2"),
                QualityFixtures.normal("N1"));
        List<QualityAnswer> answers = List.of(
                answer("T1", 1, QualityAction.ESCALATE, QualityAction.BLOCK, false, false, 0, 0, 1000, 100),
                answer("T2", 1, QualityAction.ALLOW, null, false, false, 0, 0, 1000, 100),
                answer("N1", 1, QualityAction.ALLOW, QualityAction.CHALLENGE, false, false, 0, 0, 1000, 100));

        QualityScore first = QualityScorer.score(cases, answers, QualityActionBasis.FIRST_ANSWER);
        QualityScore closing = QualityScorer.score(cases, answers, QualityActionBasis.FINAL);

        assertThat(first.basis()).isEqualTo(QualityActionBasis.FIRST_ANSWER);
        assertRate(first, QualityMetric.MISS, 1, 2);
        assertRate(first, QualityMetric.FRICTION, 0, 1);
        assertRate(first, QualityMetric.DEFERRAL, 1, 3);
        assertThat(first.incompleteAnswers()).isZero();
        // T2 has no final action yet, so it is incomplete on that basis; deferring stays a matter of first answers.
        assertThat(closing.basis()).isEqualTo(QualityActionBasis.FINAL);
        assertRate(closing, QualityMetric.MISS, 0, 1);
        assertRate(closing, QualityMetric.FRICTION, 1, 1);
        assertRate(closing, QualityMetric.DEFERRAL, 1, 2);
        assertThat(closing.scoredAnswers()).isEqualTo(2);
        assertThat(closing.incompleteAnswers()).isEqualTo(1);
    }

    @Test
    void aFailedMeasurementEntersNoRateAndRunsMayDifferFromCaseToCase() {
        List<QualityCase> cases = List.of(QualityFixtures.threat("A"), QualityFixtures.threat("B"),
                QualityFixtures.threat("C"), QualityFixtures.threat("D"));
        List<QualityAnswer> answers = List.of(
                QualityAnswerFixtures.answer("A", 1, QualityAction.ALLOW),
                QualityAnswerFixtures.answer("A", 2, QualityAction.BLOCK),
                QualityAnswerFixtures.answer("A", 3, QualityAction.BLOCK),
                QualityAnswerFixtures.answer("B", 1, QualityAction.ALLOW),
                QualityAnswerFixtures.answer("B", 2, QualityAction.ALLOW),
                QualityAnswer.failed("B", 3, "model server busy"),
                QualityAnswerFixtures.answer("C", 1, QualityAction.BLOCK),
                QualityAnswer.failed("C", 2, "model server busy"),
                QualityAnswer.failed("C", 3, "model server busy"),
                // A failed measurement says nothing of the prompt, whatever action it carries.
                new QualityAnswer("D", 1, QualityAction.ALLOW, null, true, true, 3, 0, 9000L, 10, true, "timeout"),
                QualityAnswer.failed("D", 2, "model server busy"),
                QualityAnswer.failed("D", 3, "model server busy"));

        QualityScore score = QualityScorer.score(cases, answers, QualityActionBasis.FIRST_ANSWER);

        assertThat(score.answers()).isEqualTo(12);
        assertThat(score.scoredAnswers()).isEqualTo(6);
        assertThat(score.incompleteAnswers()).isEqualTo(6);
        assertThat(score.unmeasuredCases()).isEqualTo(1);
        assertThat(score.roots()).isEqualTo(3);
        // The value is the share of answers over all runs: 1 of 3, 2 of 2 and 0 of 1.
        QualityRate miss = score.rate(QualityMetric.MISS);
        assertRate(score, QualityMetric.MISS, 3, 6);
        assertThat(miss.value()).isEqualTo(0.5);
        assertThat(miss.cases()).isEqualTo(3);
        // Beside it: the cases missed in at least one run, which grows with the number of runs.
        assertThat(miss.casesWithEvent()).isEqualTo(2);
        assertThat(miss.anyRunValue()).isCloseTo(2.0 / 3, EXACT);
        // A is answered two ways, B one way; C has one answer left and D none, so neither can show it.
        assertRate(score, QualityMetric.CONSISTENCY, 1, 2);
        assertRate(score, QualityMetric.REASK, 0, 6);
        assertRate(score, QualityMetric.MODEL_LESS, 0, 6);
        assertRate(score, QualityMetric.CITATION_ACCURACY, 18, 18);
        assertThat(score.decisionMillis().count()).isEqualTo(6);
    }

    @Test
    void aRateWithNothingToCountIsUndefinedNotZero() {
        List<QualityCase> threats = List.of(QualityFixtures.threat("T1"), QualityFixtures.threat("T2"));

        QualityScore onlyThreats = QualityScorer.score(threats,
                QualityAnswerFixtures.answers(threats, 1, item -> QualityAction.BLOCK),
                QualityActionBasis.FIRST_ANSWER);
        QualityScore noAnswers = QualityScorer.score(threats,
                List.of(QualityAnswerFixtures.answer("ELSEWHERE", 1, QualityAction.ALLOW)),
                QualityActionBasis.FIRST_ANSWER);

        // No case to allow: no false stop rate, where 0% would read as "no false stops".
        for (QualityMetric metric : List.of(QualityMetric.FALSE_STOP, QualityMetric.FRICTION,
                QualityMetric.OVER_BLOCK, QualityMetric.CONSISTENCY)) {
            QualityRate rate = onlyThreats.rate(metric);
            assertThat(rate.defined()).as("%s defined", metric).isFalse();
            assertThat(rate.value()).isNaN();
            assertThat(rate.anyRunValue()).isNaN();
            assertThat(rate.lower()).isNaN();
            assertThat(rate.upper()).isNaN();
        }
        assertThat(onlyThreats.rate(QualityMetric.MISS).value()).isZero();
        // An answer of a case that is not given is not counted at all.
        assertThat(noAnswers.answers()).isZero();
        assertThat(noAnswers.unmeasuredCases()).isEqualTo(2);
        assertThat(noAnswers.roots()).isZero();
        assertThat(noAnswers.rates().values()).noneMatch(QualityRate::defined);
        assertThat(noAnswers.decisionMillis()).isEqualTo(new QualitySpread(0, Double.NaN, Double.NaN));
    }

    @Test
    void theIntervalIsTakenOverRootsSoVariantsDoNotNarrowIt() {
        List<QualityCase> roots = new ArrayList<>();
        for (int index = 1; index <= 10; index++) {
            roots.add(QualityFixtures.threat("R" + index));
        }
        List<QualityCase> withVariants = new ArrayList<>(roots);
        for (QualityCase root : roots) {
            for (int variant = 1; variant <= 4; variant++) {
                withVariants.add(QualityFixtures.threat("V" + variant + "-" + root.key(), root.key()));
            }
        }
        // Three roots are missed, with every variant of them.
        List<String> missed = List.of("R1", "R2", "R3");

        QualityRate ten = QualityScorer.score(roots, QualityAnswerFixtures.answers(roots, 1,
                        item -> missed.contains(item.rootKey()) ? QualityAction.ALLOW : QualityAction.BLOCK),
                QualityActionBasis.FIRST_ANSWER).rate(QualityMetric.MISS);
        QualityRate fifty = QualityScorer.score(withVariants, QualityAnswerFixtures.answers(withVariants, 1,
                        item -> missed.contains(item.rootKey()) ? QualityAction.ALLOW : QualityAction.BLOCK),
                QualityActionBasis.FIRST_ANSWER).rate(QualityMetric.MISS);

        assertThat(ten.trials()).isEqualTo(10);
        assertThat(fifty.trials()).isEqualTo(50);
        assertThat(fifty.cases()).isEqualTo(50);
        assertThat(fifty.roots()).isEqualTo(10);
        assertThat(fifty.value()).isEqualTo(ten.value()).isCloseTo(0.3, EXACT);
        // Five times the answers, the same ten roots: the same interval, not the one 50 independent cases would give.
        assertThat(fifty.lower()).isEqualTo(ten.lower()).isCloseTo(0.10779126740630099, EXACT);
        assertThat(fifty.upper()).isEqualTo(ten.upper()).isCloseTo(0.6032218525388546, EXACT);
        double[] independent = QualityStatistics.wilson(0.3, 50);
        assertThat(fifty.lower()).isLessThan(independent[0]);
        assertThat(fifty.upper()).isGreaterThan(independent[1]);
        // More runs of the same cases do not narrow it either.
        QualityRate threeRuns = QualityScorer.score(roots, QualityAnswerFixtures.answers(roots, 3,
                        item -> missed.contains(item.rootKey()) ? QualityAction.ALLOW : QualityAction.BLOCK),
                QualityActionBasis.FIRST_ANSWER).rate(QualityMetric.MISS);
        assertThat(threeRuns.trials()).isEqualTo(30);
        assertThat(threeRuns.upper() - threeRuns.lower()).isEqualTo(ten.upper() - ten.lower());
    }

    @Test
    void aSmallSampleGivesAWideIntervalEvenWithoutASingleEvent() {
        List<QualityCase> one = List.of(QualityFixtures.normal("N1"));

        QualityRate falseStop = QualityScorer.score(one,
                QualityAnswerFixtures.answers(one, 3, item -> QualityAction.ALLOW),
                QualityActionBasis.FIRST_ANSWER).rate(QualityMetric.FALSE_STOP);

        assertThat(falseStop.value()).isZero();
        assertThat(falseStop.roots()).isEqualTo(1);
        assertThat(falseStop.lower()).isZero();
        assertThat(falseStop.upper()).isCloseTo(0.7934506856227626, EXACT);
    }

    @Test
    void theCasesAreScoredByKindGradeOriginAndArrival() {
        Instant made = Instant.parse("2026-11-20T00:00:00Z");
        List<QualityCase> cases = List.of(QualityFixtures.threat("T1"), QualityFixtures.normal("N1"),
                QualityFixtures.mustCatch("M1"),
                QualityFixtures.of("C1", null, QualityCaseClass.THREAT, QualityFixtures.STOP, QualityCaseGrade.ORDINARY,
                        QualityCaseOrigin.CUSTOMER, made.plusSeconds(60)),
                QualityFixtures.of("O1", null, QualityCaseClass.THREAT, QualityFixtures.STOP, QualityCaseGrade.ORDINARY,
                        QualityCaseOrigin.OPERATION, made.minusSeconds(60)));
        List<QualityAnswer> answers = List.of(QualityAnswerFixtures.answer("T1", 1, QualityAction.ALLOW),
                QualityAnswerFixtures.answer("N1", 1, QualityAction.CHALLENGE),
                QualityAnswerFixtures.answer("M1", 1, QualityAction.BLOCK),
                QualityAnswerFixtures.answer("C1", 1, QualityAction.ALLOW),
                QualityAnswerFixtures.answer("O1", 1, QualityAction.BLOCK));
        QualityActionBasis basis = QualityActionBasis.FIRST_ANSWER;

        Map<QualityCaseOrigin, QualityScore> byOrigin = QualityScorer.scoreByOrigin(cases, answers, basis);
        Map<QualityCaseGrade, QualityScore> byGrade = QualityScorer.scoreByGrade(cases, answers, basis);
        Map<QualityCaseKind, QualityScore> byKind = QualityScorer.scoreByKind(cases, answers, basis);
        Map<Boolean, QualityScore> byArrival = QualityScorer.scoreByArrival(cases, answers, basis, made);

        // The default set, which the product versions were made with, apart from the cases of the customer.
        assertThat(byOrigin).containsOnlyKeys(QualityCaseOrigin.CONTEXA, QualityCaseOrigin.CUSTOMER,
                QualityCaseOrigin.OPERATION);
        assertRate(byOrigin.get(QualityCaseOrigin.CONTEXA), QualityMetric.MISS, 1, 2);
        assertRate(byOrigin.get(QualityCaseOrigin.CUSTOMER), QualityMetric.MISS, 1, 1);
        assertRate(byOrigin.get(QualityCaseOrigin.OPERATION), QualityMetric.MISS, 0, 1);
        assertThat(byOrigin.get(QualityCaseOrigin.CUSTOMER).answers()).isEqualTo(1);
        assertRate(byGrade.get(QualityCaseGrade.MUST_CATCH), QualityMetric.ACTION_HIT, 1, 1);
        assertRate(byGrade.get(QualityCaseGrade.ORDINARY), QualityMetric.MISS, 2, 3);
        assertRate(byKind.get(QualityCaseKind.OUTSIDER), QualityMetric.MISS, 2, 4);
        assertRate(byKind.get(QualityCaseKind.NORMAL_WORK), QualityMetric.FRICTION, 1, 1);
        // The cases that came in after the version was made, which its author could not have seen.
        assertRate(byArrival.get(true), QualityMetric.MISS, 1, 1);
        assertRate(byArrival.get(false), QualityMetric.MISS, 1, 3);
        // The groups add up to the whole.
        QualityScore whole = QualityScorer.score(cases, answers, basis);
        assertRate(whole, QualityMetric.MISS, 2, 4);
        assertThat(byOrigin.values().stream().mapToInt(QualityScore::answers).sum()).isEqualTo(whole.answers());
    }

    @Test
    void theRecordedLocalMeasurementGivesItsRecordedValues() {
        List<QualityCase> cases = QualityCaseSetReader.contexaDefault().cases();
        List<QualityAnswer> sixty = QualityAnswerFixtures.localAnswers("n1-60.jsonl");

        QualityScore score = QualityScorer.score(cases, sixty, QualityActionBasis.FIRST_ANSWER);

        // The six recorded values of 2026-11-19 (60 cases, one run, version 2026.11.18-v1.0).
        assertRate(score, QualityMetric.MISS, 13, 45);
        assertRate(score, QualityMetric.FALSE_STOP, 0, 15);
        assertRate(score, QualityMetric.MODEL_LESS, 0, 60);
        assertRate(score, QualityMetric.REASK, 1, 60);
        assertRate(score, QualityMetric.CITATION_ACCURACY, 132, 180);
        assertRate(score, QualityMetric.ACTION_HIT, 47, 60);
        // What the local measurement did not count.
        assertRate(score, QualityMetric.FRICTION, 10, 15);
        assertRate(score, QualityMetric.OVER_BLOCK, 0, 15);
        assertRate(score, QualityMetric.DEFERRAL, 0, 60);
        assertThat(score.rate(QualityMetric.CONSISTENCY).defined()).isFalse();
        assertThat(score.decisionMillis()).isEqualTo(new QualitySpread(60, 7550.0, 8026.0));
        assertThat(score.answerTokens()).isEqualTo(new QualitySpread(60, 132.0, 144.0));
        assertThat(score.answers()).isEqualTo(60);
        assertThat(score.incompleteAnswers()).isZero();
        // The 10 control cases were measured apart.
        assertThat(score.cases()).isEqualTo(70);
        assertThat(score.unmeasuredCases()).isEqualTo(10);

        // The intervals count roots: 45 cases to stop are 25 roots, 15 to allow are 10. The local intervals counted
        // answers and were narrower (17.7% to 43.4%, and up to 20.4%).
        QualityRate miss = score.rate(QualityMetric.MISS);
        assertThat(miss.roots()).isEqualTo(25);
        assertThat(miss.lower()).isCloseTo(0.1492198695151742, EXACT);
        assertThat(miss.upper()).isCloseTo(0.4847946364368685, EXACT);
        QualityRate falseStop = score.rate(QualityMetric.FALSE_STOP);
        assertThat(falseStop.roots()).isEqualTo(10);
        assertThat(falseStop.lower()).isZero();
        assertThat(falseStop.upper()).isCloseTo(0.2775327998628892, EXACT);
        assertThat(score.rate(QualityMetric.CITATION_ACCURACY).roots()).isEqualTo(25);

        Map<QualityCaseKind, QualityScore> byKind = QualityScorer.scoreByKind(cases, sixty,
                QualityActionBasis.FIRST_ANSWER);
        assertRate(byKind.get(QualityCaseKind.OUTSIDER), QualityMetric.MISS, 3, 15);
        assertRate(byKind.get(QualityCaseKind.INSIDER), QualityMetric.MISS, 2, 15);
        assertRate(byKind.get(QualityCaseKind.AUTOMATION), QualityMetric.MISS, 8, 15);
        assertRate(byKind.get(QualityCaseKind.NORMAL_WORK), QualityMetric.ACTION_HIT, 15, 15);

        // The local measurement wrote first answers only, so nothing is scored on the final action yet.
        QualityScore closing = QualityScorer.score(cases, sixty, QualityActionBasis.FINAL);
        assertThat(closing.scoredAnswers()).isZero();
        assertThat(closing.incompleteAnswers()).isEqualTo(60);

        // With the control cases: all ten stopped, nine with the one right action.
        List<QualityAnswer> seventy = new ArrayList<>(sixty);
        seventy.addAll(QualityAnswerFixtures.localAnswers("n1-ver-base.jsonl"));
        Map<QualityCaseGrade, QualityScore> byGrade = QualityScorer.scoreByGrade(cases, seventy,
                QualityActionBasis.FIRST_ANSWER);
        assertRate(byGrade.get(QualityCaseGrade.MUST_CATCH), QualityMetric.MISS, 0, 10);
        assertRate(byGrade.get(QualityCaseGrade.MUST_CATCH), QualityMetric.ACTION_HIT, 9, 10);
        assertRate(byGrade.get(QualityCaseGrade.ORDINARY), QualityMetric.MISS, 13, 45);
    }
}
