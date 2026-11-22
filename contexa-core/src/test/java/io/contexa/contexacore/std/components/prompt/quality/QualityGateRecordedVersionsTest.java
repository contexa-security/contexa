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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

/**
 * Quality P35 and P8 on the measurements of plan 6's check of the quality gate (the default case set, 70 cases, one
 * run, recorded on 2026-11-22): the version in use v1.0 against six candidates made from it, with the noise of the
 * renamed one, as the gate reads them. Before P35 the version that challenges every request was only warned of, though
 * it challenges the ten control cases v1.0 blocks (K186); the renamed version, which answers every case as v1.0 does,
 * must still pass. The friction of v1.0 is already 10 of 15 answers: the default limit of 20 points is three more of
 * them. No model is called: the answers are the recorded ones.
 */
class QualityGateRecordedVersionsTest {

    private static final String RESOURCE = "prompt-quality/gate-measurement/gate-70x1.tsv";
    private static final String MODEL = "qwen3:8b";
    private static final String CASE_SET = "recorded-case-set";
    private static final String CURRENT = "v1.0";
    private static final String RENAMED = "1-renamed";
    private static final String REWORDED = "2-reworded";
    private static final String NO_JUDGING = "3-no-judging";
    private static final String CHALLENGE_ALL = "4-challenge-all";
    private static final String DEFER_ALL = "5-defer-all";
    private static final String ALLOW_MUST_CATCH = "6-allow-must-catch";

    private static final Recorded RECORDED = Recorded.read();

    /** The noise of the gate check: v1.0 and the renamed version, taken as two measurements of one version. */
    private static final QualityNoise NOISE = QualityNoise.between(RECORDED.cases(),
            RECORDED.measurement(CURRENT, CURRENT), RECORDED.measurement(RENAMED, CURRENT),
            QualityActionBasis.FIRST_ANSWER);

    private static QualityGateResult gate(QualityMeasurement current, QualityMeasurement candidate) {
        return gate(current, candidate, QualityGateSettings.defaults());
    }

    private static QualityGateResult gate(QualityMeasurement current, QualityMeasurement candidate,
                                          QualityGateSettings settings) {
        return QualityGateEvaluator.evaluate(new QualityGateInput(RECORDED.cases(), current, candidate, NOISE,
                settings, null));
    }

    private static QualityGateResult gate(String candidate) {
        return gate(RECORDED.measurement(CURRENT, CURRENT), RECORDED.measurement(candidate, candidate));
    }

    @Test
    void theRecordingIsTheOneOfTheGateCheck() {
        // The ten control cases are the cases that must be caught; v1.0 blocks each, the only right action.
        List<QualityCase> controls = RECORDED.controls();
        assertThat(controls).hasSize(10).allSatisfy(item ->
                assertThat(item.expectation().allowedActions()).containsExactly(QualityAction.BLOCK));
        assertThat(RECORDED.actions(CURRENT, controls)).containsOnly(QualityAction.BLOCK);
        assertThat(RECORDED.actions(CHALLENGE_ALL, controls)).containsOnly(QualityAction.CHALLENGE);
        assertThat(RECORDED.actions(DEFER_ALL, controls)).containsOnly(QualityAction.ESCALATE);
        // The renamed version answered every case as v1.0 did: the noise of every action rate is zero.
        assertThat(NOISE.width(QualityMetric.MISS)).hasValue(0.0);
        assertThat(NOISE.width(QualityMetric.FRICTION)).hasValue(0.0);
    }

    @Test
    void theControlCasesChallengedOrDeferredAreBlockedByTheirOwnRow() {
        QualityMeasurement current = RECORDED.measurement(CURRENT, CURRENT);

        for (QualityAction weaker : List.of(QualityAction.CHALLENGE, QualityAction.ESCALATE)) {
            // v1.0 with nothing changed but the ten control cases.
            QualityMeasurement weakened = RECORDED.measurement(CURRENT, "controls-" + weaker,
                    item -> item.grade() == QualityCaseGrade.MUST_CATCH ? weaker : null);
            QualityGateResult result = gate(current, weakened);

            QualityGateFinding finding = result.finding(QualityGateCondition.MUST_CATCH_NOT_WEAKENED);
            assertThat(finding.status()).as("%s", weaker).isEqualTo(QualityGateStatus.BLOCKED);
            assertThat(finding.caseKeys()).as("%s", weaker)
                    .containsExactlyElementsOf(RECORDED.controls().stream().map(QualityCase::key).toList());
            assertThat(finding.figures()).containsEntry("gradedCases", 10).containsEntry("weakenedCases", 10)
                    .containsEntry("weakenedAnswers", 10).containsEntry("currentAlsoOutsideCases", 0);
            assertThat(result.status()).isEqualTo(QualityGateStatus.BLOCKED);
            if (weaker == QualityAction.CHALLENGE) {
                // Before P35 no row blocked it: the controls are not allowed, and the rates of the gate do not move.
                assertThat(result.findings()).filteredOn(other -> other.condition()
                                != QualityGateCondition.MUST_CATCH_NOT_WEAKENED)
                        .extracting(QualityGateFinding::status).doesNotContain(QualityGateStatus.BLOCKED);
            }
        }
    }

    @Test
    void theVersionThatChallengesEveryRequestIsBlockedForTheControlCases() {
        QualityGateResult result = gate(CHALLENGE_ALL);

        QualityGateFinding finding = result.finding(QualityGateCondition.MUST_CATCH_NOT_WEAKENED);
        assertThat(finding.status()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(finding.figures()).containsEntry("weakenedCases", 10).containsEntry("weakenedAnswers", 10);
        assertThat(result.status()).isEqualTo(QualityGateStatus.BLOCKED);
        // Its friction rise blocks it too; the rows of the plan alone only warned of it (gate-verdicts.md).
        assertThat(status(result, QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT))
                .isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(result.findings()).filteredOn(other -> other.condition()
                        != QualityGateCondition.MUST_CATCH_NOT_WEAKENED
                        && other.condition() != QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT)
                .extracting(QualityGateFinding::status).doesNotContain(QualityGateStatus.BLOCKED);
        assertThat(status(gate(DEFER_ALL), QualityGateCondition.MUST_CATCH_NOT_WEAKENED))
                .isEqualTo(QualityGateStatus.BLOCKED);
    }

    @Test
    void theRenamedVersionIsNotBlockedAndAWeakVersionMeasuredAgainOnlyWarns() {
        QualityGateResult renamed = gate(RENAMED);

        assertThat(status(renamed, QualityGateCondition.MUST_CATCH_NOT_WEAKENED)).isEqualTo(QualityGateStatus.PASSED);
        assertThat(status(renamed, QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT))
                .isEqualTo(QualityGateStatus.PASSED);
        assertThat(renamed.finding(QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT).figures())
                .containsEntry("increase", 0.0);
        assertThat(renamed.findings()).extracting(QualityGateFinding::status)
                .doesNotContain(QualityGateStatus.BLOCKED);
        assertThat(renamed.status()).isEqualTo(QualityGateStatus.WARNING);

        // In use, the version that challenges everything does not block its own measurement taken again.
        QualityGateResult again = gate(RECORDED.measurement(CHALLENGE_ALL, CHALLENGE_ALL),
                RECORDED.measurement(CHALLENGE_ALL, CHALLENGE_ALL + "-again"));
        QualityGateFinding finding = again.finding(QualityGateCondition.MUST_CATCH_NOT_WEAKENED);
        assertThat(finding.status()).isEqualTo(QualityGateStatus.WARNING);
        assertThat(finding.figures()).containsEntry("weakenedCases", 0).containsEntry("currentAlsoOutsideCases", 10);
        assertThat(again.status()).isEqualTo(QualityGateStatus.WARNING);
    }

    @Test
    void theFrictionOfTheVersionThatChallengesEveryRequestRisesBeyondTheDefaultLimit() {
        QualityGateResult result = gate(CHALLENGE_ALL);
        QualityGateFinding byDefault = result.finding(QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT);

        // 10 of 15 to 14 of 15: 26.7 points over the 20 of the default, whatever the significance (p = 0.0625 on the
        // four roots that turn), with one answer to spare.
        assertThat(byDefault.status()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(byDefault.figures()).containsEntry("pairedCases", 15).containsEntry("currentRate", 10.0 / 15)
                .containsEntry("candidateRate", 14.0 / 15).containsEntry("limit", 0.20);
        assertThat(byDefault.figures().get("increase").doubleValue()).isCloseTo(4.0 / 15, within(1e-12));
        assertThat(result.comparisons().get(QualityMetric.FRICTION).verdict()).isEqualTo(QualityVerdict.UNDECIDABLE);
        assertThat(result.comparisons().get(QualityMetric.FRICTION).worseProbability()).isEqualTo(1.0 / 16);
        // A limit over the rise lets it through on the friction alone.
        QualityGateResult looser = gate(RECORDED.measurement(CURRENT, CURRENT),
                RECORDED.measurement(CHALLENGE_ALL, CHALLENGE_ALL), new QualityGateSettings(0.05, 0.05, 200, 300, 0.27));
        assertThat(status(looser, QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT))
                .isEqualTo(QualityGateStatus.PASSED);
        // The version that defers everything stops all normal work: 33.3 points, over the default.
        QualityGateFinding deferred = gate(DEFER_ALL).finding(QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT);
        assertThat(deferred.status()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(deferred.figures().get("increase").doubleValue()).isCloseTo(5.0 / 15, within(1e-12));
    }

    @Test
    void onTheDefaultCaseSetThreeMoreAnswersThatStopNormalWorkBlockAndTwoDoNot() {
        QualityMeasurement current = RECORDED.measurement(CURRENT, CURRENT);
        // The normal cases v1.0 allows, in the order of the recording.
        List<String> allowedByCurrent = RECORDED.cases().stream()
                .filter(item -> !item.shouldStop())
                .filter(item -> RECORDED.actions(CURRENT, List.of(item)).get(0) == QualityAction.ALLOW)
                .map(QualityCase::key).toList();
        assertThat(allowedByCurrent).hasSize(5);
        Function<Integer, QualityGateFinding> challenging = count -> gate(current,
                RECORDED.measurement(CURRENT, "challenges-" + count,
                        item -> allowedByCurrent.subList(0, count).contains(item.key()) ? QualityAction.CHALLENGE
                                : null)).finding(QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT);

        QualityGateFinding three = challenging.apply(3);
        assertThat(three.status()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(three.figures().get("increase").doubleValue()).isCloseTo(3.0 / 15, within(1e-12));
        QualityGateFinding two = challenging.apply(2);
        assertThat(two.status()).isEqualTo(QualityGateStatus.PASSED);
        assertThat(two.figures().get("increase").doubleValue()).isCloseTo(2.0 / 15, within(1e-12));
    }

    @Test
    void theVerdictsOfTheSixVersionsWithTheTwoNewRows() {
        Map<String, List<QualityGateStatus>> expected = new LinkedHashMap<>();
        // The version, then: the weakened control cases, the friction limit, and the whole verdict.
        expected.put(RENAMED, List.of(QualityGateStatus.PASSED, QualityGateStatus.PASSED, QualityGateStatus.WARNING));
        expected.put(REWORDED, List.of(QualityGateStatus.PASSED, QualityGateStatus.PASSED, QualityGateStatus.BLOCKED));
        expected.put(NO_JUDGING, List.of(QualityGateStatus.PASSED, QualityGateStatus.PASSED,
                QualityGateStatus.WARNING));
        expected.put(CHALLENGE_ALL, List.of(QualityGateStatus.BLOCKED, QualityGateStatus.BLOCKED,
                QualityGateStatus.BLOCKED));
        expected.put(DEFER_ALL, List.of(QualityGateStatus.BLOCKED, QualityGateStatus.BLOCKED,
                QualityGateStatus.BLOCKED));
        expected.put(ALLOW_MUST_CATCH, List.of(QualityGateStatus.PASSED, QualityGateStatus.PASSED,
                QualityGateStatus.BLOCKED));

        expected.forEach((version, statuses) -> {
            QualityGateResult result = gate(version);
            assertThat(List.of(status(result, QualityGateCondition.MUST_CATCH_NOT_WEAKENED),
                    status(result, QualityGateCondition.FRICTION_INCREASE_WITHIN_LIMIT), result.status()))
                    .as(version).isEqualTo(statuses);
        });
    }

    private static QualityGateStatus status(QualityGateResult result, QualityGateCondition condition) {
        return result.finding(condition).status();
    }

    /** The recorded cases and, per version, the first answer of each case. */
    private record Recorded(List<QualityCase> cases, Map<String, Map<String, QualityAnswer>> answers) {

        static Recorded read() {
            List<QualityCase> cases = new ArrayList<>();
            Map<String, Map<String, QualityAnswer>> answers = new LinkedHashMap<>();
            try (InputStream input = QualityGateRecordedVersionsTest.class.getClassLoader()
                    .getResourceAsStream(RESOURCE)) {
                if (input == null) {
                    throw new IllegalStateException("The recorded measurements are missing: " + RESOURCE);
                }
                BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
                List<String> versions = null;
                for (String line = reader.readLine(); line != null; line = reader.readLine()) {
                    if (line.isBlank() || line.startsWith("#")) {
                        continue;
                    }
                    String[] columns = line.split("\t");
                    if (versions == null) {
                        versions = List.of(columns).subList(5, columns.length);
                        versions.forEach(version -> answers.put(version, new LinkedHashMap<>()));
                        continue;
                    }
                    String key = columns[0];
                    Set<QualityAction> allowed = EnumSet.noneOf(QualityAction.class);
                    for (String action : columns[4].split(",")) {
                        allowed.add(QualityAction.parse(action));
                    }
                    cases.add(QualityFixtures.of(key, columns[1], QualityCaseClass.valueOf(columns[3]), allowed,
                            QualityCaseGrade.valueOf(columns[2]), QualityCaseOrigin.CONTEXA, null));
                    for (int index = 0; index < versions.size(); index++) {
                        answers.get(versions.get(index)).put(key, answer(key, columns[5 + index]));
                    }
                }
            }
            catch (IOException exception) {
                throw new UncheckedIOException(exception);
            }
            return new Recorded(List.copyOf(cases), answers);
        }

        /** A cell: the first action, the cited and the accurate facts, and r when asked again, m without the model. */
        private static QualityAnswer answer(String key, String cell) {
            if ("FAILED".equals(cell)) {
                return QualityAnswer.failed(key, 1, "recorded as failed");
            }
            String[] parts = cell.split(" ");
            String[] facts = parts[1].split("/");
            List<String> flags = List.of(parts).subList(2, parts.length);
            return new QualityAnswer(key, 1, QualityAction.parse(parts[0]), null, flags.contains("r"),
                    flags.contains("m"), Integer.parseInt(facts[0]), Integer.parseInt(facts[1]), null, null, false,
                    null);
        }

        List<QualityCase> controls() {
            return cases.stream().filter(item -> item.grade() == QualityCaseGrade.MUST_CATCH).toList();
        }

        List<QualityAction> actions(String version, List<QualityCase> of) {
            return of.stream().map(item -> answers.get(version).get(item.key()).firstAction()).toList();
        }

        /** The recorded answers of the version, as a measurement of the prompt version named. */
        QualityMeasurement measurement(String version, String promptVersion) {
            return measurement(version, promptVersion, item -> null);
        }

        /** The recorded answers of the version with those the change gives an action for replaced by it. */
        QualityMeasurement measurement(String version, String promptVersion,
                                       Function<QualityCase, QualityAction> change) {
            List<QualityAnswer> taken = new ArrayList<>();
            for (QualityCase item : cases) {
                QualityAnswer recorded = answers.get(version).get(item.key());
                QualityAction changed = change.apply(item);
                taken.add(changed == null ? recorded : new QualityAnswer(item.key(), 1, changed, null,
                        recorded.reasked(), recorded.decidedWithoutModel(), recorded.citedFacts(),
                        recorded.accurateCitedFacts(), null, null, false, null));
            }
            return new QualityMeasurement(promptVersion, MODEL, CASE_SET, 1, taken);
        }
    }
}
