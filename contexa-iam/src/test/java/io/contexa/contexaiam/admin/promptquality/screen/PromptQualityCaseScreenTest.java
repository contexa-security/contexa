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
package io.contexa.contexaiam.admin.promptquality.screen;

import io.contexa.contexacore.std.components.prompt.quality.QualityAction;
import io.contexa.contexacore.std.components.prompt.quality.QualityAnswer;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseExpectation;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseResource;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSet;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSetReader;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.measure.MeasuredQualityGateSource;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseScreen.AnswerForm;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.Improved;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.InputLine;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.InputSummary;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Quality plan 3.2: what the screen of the labelled cases works out itself: a case's result on the first answer, what
 * changing its answer alone did, the summary of its input, the chance to tell a better version, the reading of an
 * answer the screen sends, and the refusal of a decision that is not sealed.
 */
class PromptQualityCaseScreenTest {

    private static final QualityCaseSet DEFAULTS = QualityCaseSetReader.contexaDefault();

    private static QualityCase stopCase() {
        return DEFAULTS.cases().stream().filter(QualityCase::shouldStop)
                .filter(item -> !item.expectation().allows(QualityAction.ALLOW))
                .filter(item -> item.expectation().allowedActions().size() < 4)
                .filter(item -> !item.expectation().allows(QualityAction.CHALLENGE))
                .findFirst().orElseThrow();
    }

    private static QualityAnswer answer(String key, int run, QualityAction action) {
        return new QualityAnswer(key, run, action, action, false, false, 0, 0, 7000L, 130, false, null);
    }

    @Test
    void aCaseIsMissedRightOffTheAnswerOrNotMeasured() {
        QualityCase item = stopCase();
        String key = item.key();

        assertThat(PromptQualityCaseScreen.result(item, List.of(answer(key, 1, QualityAction.BLOCK),
                answer(key, 2, QualityAction.ALLOW)))).isEqualTo("MISS");
        assertThat(PromptQualityCaseScreen.result(item, List.of(answer(key, 1, QualityAction.BLOCK)))).isEqualTo("HIT");
        assertThat(PromptQualityCaseScreen.result(item, List.of(answer(key, 1, QualityAction.CHALLENGE))))
                .isEqualTo("OFF");
        assertThat(PromptQualityCaseScreen.result(item, List.of(QualityAnswer.failed(key, 1, "busy")))).isEqualTo("NONE");
        assertThat(PromptQualityCaseScreen.result(item, null)).isEqualTo("NONE");
    }

    /** Plan 3.2: the answers right on the present answer and wrong on the first one count apart. */
    @Test
    void whatChangingTheAnswerAloneDidIsCountedApart() {
        QualityCase item = stopCase();
        QualityCaseExpectation first = item.expectation();
        QualityCaseExpectation present = new QualityCaseExpectation(Set.of(QualityAction.BLOCK, QualityAction.CHALLENGE),
                null, first.classification(), first.kind(), first.rationale(), List.of());
        QualityCase changed = new QualityCase(item.key(), item.input(), present, item.grade(), null,
                item.environment(), item.origin(), item.addedAt());
        PromptQualityCases.AnswerChange change = new PromptQualityCases.AnswerChange(1, item.key(), "lee",
                Instant.parse("2026-11-21T08:50:00Z"), item.grade(), item.grade(), first, present, "a", "b");
        PromptQualityMeasurements.CaseHistory one = new PromptQualityMeasurements.CaseHistory(null, List.of(
                answer(item.key(), 1, QualityAction.CHALLENGE), answer(item.key(), 2, QualityAction.CHALLENGE),
                answer(item.key(), 3, QualityAction.BLOCK), QualityAnswer.failed(item.key(), 4, "busy")));

        Improved improved = PromptQualityCaseScreen.improved(changed, List.of(change), List.of(one));

        assertThat(improved).isEqualTo(new Improved(1, 3, 2, 0));
        assertThat(PromptQualityCaseScreen.improved(changed, List.of(), List.of(one))).isNull();
    }

    @Test
    void theInputIsSummarizedInItsFiveViews() {
        QualityCase item = DEFAULTS.find("S11").orElseThrow();

        InputSummary summary = QualityCaseInputSummary.of(item.input());

        assertThat(summary.request()).extracting(InputLine::name).contains("request", "resource", "resourceClass",
                "requestedAt", "items");
        assertThat(summary.request()).filteredOn(line -> "items".equals(line.name())).extracting(InputLine::value)
                .containsExactly("480");
        assertThat(summary.session()).extracting(InputLine::name).contains("user", "clientIp", "authentication", "mfa");
        assertThat(summary.deviation()).extracting(InputLine::name).contains("TARGET", "SIZE");
        assertThat(summary.deviation()).filteredOn(line -> "SIZE".equals(line.name())).extracting(InputLine::value)
                .allSatisfy(value -> assertThat(value).startsWith("480 items").contains("APR-"));
        assertThat(summary.records()).extracting(InputLine::value).anySatisfy(value -> assertThat(value)
                .contains("APR-107dabe3a78d-1"));
        assertThat(summary.unknown()).extracting(InputLine::value).contains("PeerCohort");
        assertThat(MeasuredQualityGateSource.caseName(item)).endsWith("(S11)").contains("/api/");
    }

    @Test
    void aResourceIsNamedByItsMethodAndTemplateElseByItsName() {
        assertThat(PromptQualityCaseScreen.resourceName(new QualityCaseResource("CRITICAL", "a.b.Operations#export",
                "POST", "/api/projects/{key}/exports"))).isEqualTo("POST /api/projects/{key}/exports");
        assertThat(PromptQualityCaseScreen.resourceName(new QualityCaseResource("CRITICAL", "a.b.Operations#export",
                null, null))).isEqualTo("Operations#export");
        assertThat(PromptQualityCaseScreen.resourceName(QualityCaseResource.NONE)).isNull();
    }

    /** Plan 3.2: 45 independent roots tell a version 10 points better about a fifth to a third of the time. */
    @Test
    void theChanceToTellABetterVersionGrowsWithTheRoots() {
        double base = 14.0 / 45.0;
        double few = QualityCasePower.of(25, base, 0.05);
        double plan = QualityCasePower.of(45, base, 0.05);
        double target = QualityCasePower.of(200, base, 0.05);

        assertThat(QualityCasePower.of(0, base, 0.05)).isZero();
        assertThat(few).isLessThan(plan);
        assertThat(plan).isCloseTo(0.29, within(0.02));
        assertThat(target).isCloseTo(0.91, within(0.02)).isLessThan(QualityCasePower.of(400, base, 0.05));
        assertThat(QualityCasePower.of(200, base, 0.01)).isLessThan(target);
        assertThat(QualityCasePower.bivariateNormal(0, 0, 0)).isCloseTo(0.25, within(1e-4));
        assertThat(QualityCasePower.inverseNormal(0.975)).isCloseTo(1.95996, within(1e-3));
        assertThatThrownBy(() -> QualityCasePower.of(10, 0.05, 0.05)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void anAnswerTheScreenCannotReadIsInvalid() {
        AnswerForm right = new AnswerForm(List.of("BLOCK", "CHALLENGE"), "BLOCK", "THREAT", "INSIDER", "차단",
                null, List.of("a=b", " "), "ORDINARY");
        assertThat(PromptQualityCaseScreen.parse(right).expectation().decidingFacts()).containsExactly("a=b");
        assertThat(PromptQualityCaseScreen.parse(right).grade()).isEqualTo(QualityCaseGrade.ORDINARY);

        for (AnswerForm wrong : List.of(
                new AnswerForm(List.of(), null, "THREAT", "INSIDER", "차단", null, null, "ORDINARY"),
                new AnswerForm(List.of("STOP"), null, "THREAT", "INSIDER", "차단", null, null, "ORDINARY"),
                new AnswerForm(List.of("BLOCK"), "ALLOW", "THREAT", "INSIDER", "차단", null, null, "ORDINARY"),
                new AnswerForm(List.of("BLOCK"), null, "THREAT", "INSIDER", null, " ", null, "ORDINARY"),
                new AnswerForm(List.of("BLOCK"), null, null, "INSIDER", "차단", null, null, "ORDINARY"),
                new AnswerForm(List.of("BLOCK"), null, "THREAT", "INSIDER", "차단", null, null, "SEVERE"))) {
            assertThatThrownBy(() -> PromptQualityCaseScreen.parse(wrong))
                    .isInstanceOfSatisfying(PromptQualityCaseScreen.RefusedException.class,
                            refused -> assertThat(refused.code()).isEqualTo(PromptQualityCaseScreen.INVALID));
        }
    }

    /** Only a sealed decision becomes a case: an id no package has is refused as NOT_SEALED, nothing kept. */
    @Test
    void aDecisionThatIsNotSealedIsRefused() {
        PromptQualityCases cases = mock(PromptQualityCases.class);
        SealedEvidencePackageRepository sealed = mock(SealedEvidencePackageRepository.class);
        when(sealed.findByPackageId("p-1")).thenReturn(Optional.empty());
        PromptQualityCaseScreen screen = new PromptQualityCaseScreen(cases, null, null, null, () -> sealed, null, null);
        AnswerForm answer = new AnswerForm(List.of("BLOCK"), null, "THREAT", "INSIDER", "차단", null, null, "ORDINARY");

        assertThatThrownBy(() -> screen.promote(null, " p-1 ", answer, "admin"))
                .isInstanceOfSatisfying(PromptQualityCaseScreen.RefusedException.class,
                        refused -> assertThat(refused.code()).isEqualTo(PromptQualityCaseScreen.NOT_SEALED));
        assertThatThrownBy(() -> new PromptQualityCaseScreen(cases, null, null, null, null, null, null)
                .promote(null, "p-1", answer, "admin"))
                .isInstanceOfSatisfying(PromptQualityCaseScreen.RefusedException.class,
                        refused -> assertThat(refused.code()).isEqualTo(PromptQualityCaseScreen.NOT_SEALED));
        assertThatThrownBy(() -> screen.promote(null, " ", answer, "admin"))
                .isInstanceOfSatisfying(PromptQualityCaseScreen.RefusedException.class,
                        refused -> assertThat(refused.code()).isEqualTo(PromptQualityCaseScreen.INVALID));
        verify(cases, never()).promote(any(), any(), any(), any(), any(), any(), any(), any());
    }

    /** K199: a package kept without its seal (the sealing failed) is refused as NOT_SEALED; a sealed one is kept. */
    @Test
    void aDecisionWhoseSealingFailedIsRefused() {
        PromptQualityCases cases = mock(PromptQualityCases.class);
        SealedEvidencePackageRepository sealed = mock(SealedEvidencePackageRepository.class);
        SealedEvidencePackage failed = SealedEvidencePackage.builder().packageId("p-failed").sealState("FAILED").build();
        SealedEvidencePackage kept = SealedEvidencePackage.builder().packageId("p-sealed").build();
        when(sealed.findByPackageId("p-failed")).thenReturn(Optional.of(failed));
        when(sealed.findByPackageId("p-sealed")).thenReturn(Optional.of(kept));
        QualityCase item = DEFAULTS.find("S11").orElseThrow();
        when(cases.promote(any(), any(), any(), any(), any(), any(), any(), any())).thenReturn(new PromptQualityCases
                .Kept(7L, "tenant-a", "security-decision", item, "PENDING", "p-sealed", null, "admin",
                Instant.parse("2026-11-23T00:00:00Z"), "admin", Instant.parse("2026-11-23T00:00:00Z"), null, null));
        PromptQualityCaseScreen screen = new PromptQualityCaseScreen(cases, null, null, null, () -> sealed, null, null);
        AnswerForm answer = new AnswerForm(List.of("BLOCK"), null, "THREAT", "INSIDER", "차단", null, null, "ORDINARY");

        assertThatThrownBy(() -> screen.promote(null, "p-failed", answer, "admin"))
                .isInstanceOfSatisfying(PromptQualityCaseScreen.RefusedException.class,
                        refused -> assertThat(refused.code()).isEqualTo(PromptQualityCaseScreen.NOT_SEALED));
        verify(cases, never()).promote(any(), any(), any(), any(), any(), any(), any(), any());

        assertThat(screen.promote(null, "p-sealed", answer, "admin").key()).isEqualTo(item.key());
        verify(cases).promote(any(), any(), any(), any(), any(), any(), any(), any());
    }
}
