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

import io.contexa.contexacore.testsupport.QualityGateFixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Plan 3.4, 5 step 5: the quality gate as the release gate applies it, for each of the five states a source of
 * measurements answers with, in the warning and the blocking mode. The verdict is the one of the conditions;
 * what is applied follows the mode and the state: the warning mode keeps a blocked verdict and applies a warning, a
 * version that cannot be measured is warned of, a stale measurement always warns, and the missing measurement of the
 * version in use while its first one waits warns while the candidate's own failures still block.
 */
class QualityGatePolicyTest {

    private static final String SCOPE = "PLATFORM_GLOBAL";
    private static final String PROMPT = "cortex.security-decision";

    private static QualityGateVerdict assess(QualityGateReading reading, QualityGateMode mode) {
        return new QualityGatePolicy(QualityGateFixtures.source(reading), mode, QualityGateFixtures.SETTINGS)
                .assess(SCOPE, PROMPT, "v2.0", "v1.0");
    }

    private static QualityGateReading measured(QualityMeasurement candidate) {
        return QualityGateReading.measured(QualityGateFixtures.input(QualityGateFixtures.sound("v1.0"), candidate));
    }

    @ParameterizedTest
    @EnumSource(QualityGateMode.class)
    void aSoundMeasuredCandidatePassesInEitherMode(QualityGateMode mode) {
        QualityGateVerdict verdict = assess(measured(QualityGateFixtures.sound("v2.0")), mode);

        assertThat(verdict.measurement()).isEqualTo(QualityMeasurementState.MEASURED);
        assertThat(verdict.verdict()).isEqualTo(QualityGateStatus.PASSED);
        assertThat(verdict.applied()).isEqualTo(QualityGateStatus.PASSED);
        assertThat(verdict.result().findings()).hasSize(QualityGateCondition.values().length)
                .allSatisfy(finding -> assertThat(finding.status()).isEqualTo(QualityGateStatus.PASSED));
        assertThat(verdict.rollback()).isFalse();
    }

    @Test
    void aBlockedVerdictBlocksInTheBlockingModeAndWarnsInTheWarningModeKeepingTheVerdict() {
        QualityGateReading reading = measured(QualityGateFixtures.missesTheMustCatchCase("v2.0"));

        QualityGateVerdict blocking = assess(reading, QualityGateMode.BLOCK);
        QualityGateVerdict warning = assess(reading, QualityGateMode.WARN);

        assertThat(blocking.verdict()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(blocking.applied()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(blocking.blocks()).isTrue();
        assertThat(warning.verdict()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(warning.applied()).isEqualTo(QualityGateStatus.WARNING);
        assertThat(warning.blocks()).isFalse();
        assertThat(warning.warns()).isTrue();
        assertThat(warning.mode()).isEqualTo(QualityGateMode.WARN);
        // The numbers and the cases behind the verdict are the same in both modes.
        QualityGateFinding mustCatch = warning.result().finding(QualityGateCondition.MUST_CATCH_NEVER_ALLOWED);
        assertThat(mustCatch.status()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(mustCatch.caseKeys()).containsExactly(QualityGateFixtures.MUST_CATCH);
        assertThat(mustCatch.figures()).containsEntry("failedCases", 1)
                .containsEntry("failedAnswers", QualityGateFixtures.RUNS);
        assertThat(warning.result().changes().newlyMissed()).containsExactly(QualityGateFixtures.MUST_CATCH);
    }

    @Test
    void aMissingMeasurementBlocksOnTheFirstConditionInTheBlockingModeAndWarnsInTheWarningMode() {
        QualityGateReading reading = QualityGateReading.missing(Set.of(QualityGateSide.CANDIDATE), null);

        QualityGateVerdict blocking = assess(reading, QualityGateMode.BLOCK);

        assertThat(blocking.measurement()).isEqualTo(QualityMeasurementState.MISSING);
        assertThat(blocking.sides()).containsExactly(QualityGateSide.CANDIDATE);
        assertThat(blocking.applied()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(blocking.result().finding(QualityGateCondition.COMPARABLE_MEASUREMENTS).status())
                .isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(blocking.result().finding(QualityGateCondition.MISS_NOT_INCREASED).status())
                .isEqualTo(QualityGateStatus.NOT_EVALUATED);
        assertThat(assess(reading, QualityGateMode.WARN).applied()).isEqualTo(QualityGateStatus.WARNING);
    }

    @ParameterizedTest
    @EnumSource(QualityGateMode.class)
    void aStaleMeasurementAlwaysWarnsSoThatItIsTakenAgain(QualityGateMode mode) {
        QualityGateReading reading = QualityGateReading.stale(Set.of(QualityGateSide.CURRENT),
                QualityGateFixtures.input(QualityGateFixtures.sound("v1.0"), QualityGateFixtures.sound("v2.0")));

        QualityGateVerdict verdict = assess(reading, mode);

        assertThat(verdict.measurement()).isEqualTo(QualityMeasurementState.STALE);
        assertThat(verdict.sides()).containsExactly(QualityGateSide.CURRENT);
        assertThat(verdict.verdict()).isEqualTo(QualityGateStatus.PASSED);
        assertThat(verdict.applied()).isEqualTo(QualityGateStatus.WARNING);
    }

    @ParameterizedTest
    @EnumSource(QualityGateMode.class)
    void aVersionThatCannotBeMeasuredIsWarnedOfNotBlocked(QualityGateMode mode) {
        QualityGateVerdict verdict = assess(QualityGateReading.unmeasurable("NO_REPLAY"), mode);

        assertThat(verdict.measurement()).isEqualTo(QualityMeasurementState.UNMEASURABLE);
        assertThat(verdict.detail()).isEqualTo("NO_REPLAY");
        assertThat(verdict.verdict()).isEqualTo(QualityGateStatus.NOT_EVALUATED);
        assertThat(verdict.applied()).isEqualTo(QualityGateStatus.WARNING);
        assertThat(verdict.result().findings()).hasSize(QualityGateCondition.values().length)
                .allSatisfy(finding -> assertThat(finding.status()).isEqualTo(QualityGateStatus.NOT_EVALUATED));
    }

    @Test
    void withoutASourceEveryVersionCannotBeMeasuredInTheWarningMode() {
        QualityGatePolicy none = QualityGatePolicy.none();

        QualityGateVerdict verdict = none.assess(SCOPE, PROMPT, "v2.0", "v1.0");

        assertThat(none.mode()).isEqualTo(QualityGateMode.WARN);
        assertThat(none.settings()).isEqualTo(QualityGateSettings.defaults());
        assertThat(verdict.measurement()).isEqualTo(QualityMeasurementState.UNMEASURABLE);
        assertThat(verdict.detail()).isEqualTo(QualityGateSource.NO_SOURCE);
        assertThat(verdict.applied()).isEqualTo(QualityGateStatus.WARNING);
        assertThat(none.measurement(SCOPE, PROMPT, "v1.0")).isEqualTo(QualityMeasurementState.UNMEASURABLE);
    }

    @Test
    void whileTheFirstMeasurementOfTheVersionInUseWaitsItsAbsenceWarnsAndTheCandidatesOwnFailuresStillBlock() {
        QualityGateReading clean = QualityGateReading.baselinePending(
                QualityGateFixtures.input(null, QualityGateFixtures.sound("v2.0")));
        QualityGateReading failing = QualityGateReading.baselinePending(
                QualityGateFixtures.input(null, QualityGateFixtures.missesTheMustCatchCase("v2.0")));

        QualityGateVerdict waiting = assess(clean, QualityGateMode.BLOCK);
        QualityGateVerdict caught = assess(failing, QualityGateMode.BLOCK);

        assertThat(waiting.measurement()).isEqualTo(QualityMeasurementState.BASELINE_PENDING);
        assertThat(waiting.sides()).containsExactly(QualityGateSide.CURRENT);
        assertThat(waiting.result().finding(QualityGateCondition.COMPARABLE_MEASUREMENTS).status())
                .isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(waiting.verdict()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(waiting.applied()).isEqualTo(QualityGateStatus.WARNING);
        assertThat(caught.applied()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(assess(failing, QualityGateMode.WARN).applied()).isEqualTo(QualityGateStatus.WARNING);
    }

    @Test
    void theThresholdsOfTheInstallationReplaceTheOnesTheSourceCarries() {
        QualityGatePolicy strict = new QualityGatePolicy(QualityGateFixtures.source(
                measured(QualityGateFixtures.sound("v2.0"))), QualityGateMode.BLOCK, QualityGateSettings.defaults());

        QualityGateVerdict verdict = strict.assess(SCOPE, PROMPT, "v2.0", "v1.0");

        QualityGateFinding enough = verdict.result().finding(QualityGateCondition.ENOUGH_CASES);
        assertThat(enough.status()).isEqualTo(QualityGateStatus.WARNING);
        assertThat(enough.figures()).containsEntry("stopRootsNeeded", 200).containsEntry("allowRootsNeeded", 300);
        assertThat(verdict.applied()).isEqualTo(QualityGateStatus.WARNING);
    }

    @Test
    void aRollbackReadsNoMeasurement() {
        QualityGateFixtures.Source source = QualityGateFixtures.source(QualityGateReading.unmeasurable(null));

        QualityGateVerdict verdict = new QualityGatePolicy(source, QualityGateMode.BLOCK, null).rollback();

        assertThat(verdict.rollback()).isTrue();
        assertThat(verdict.applied()).isEqualTo(QualityGateStatus.PASSED);
        assertThat(verdict.measurement()).isNull();
        assertThat(source.reads()).isEmpty();
    }

    @Test
    void aReadingStatesWhatItIsAbout() {
        assertThatThrownBy(() -> new QualityGateReading(QualityMeasurementState.MEASURED, Set.of(), null, null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> QualityGateReading.missing(Set.of(), null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new QualityGateReading(QualityMeasurementState.UNMEASURABLE, Set.of(),
                QualityGateFixtures.input(null, null), null)).isInstanceOf(IllegalArgumentException.class);
    }
}
