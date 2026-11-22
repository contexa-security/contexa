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

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Plan 3.2: what a labelled case is, and what it refuses to be.
 */
class QualityCaseTest {

    private static final Instant MADE = Instant.parse("2026-11-20T00:00:00Z");

    @Test
    void aCaseCountsUnderItsRootAndKnowsWhetherItCameInLater() {
        QualityCase original = QualityFixtures.threat("S01");
        QualityCase variant = QualityFixtures.threat("OUT-S01", "S01");
        QualityCase ownRoot = QualityFixtures.threat("S02", "S02");
        QualityCase later = QualityFixtures.of("NEW", null, QualityCaseClass.THREAT, QualityFixtures.STOP,
                QualityCaseGrade.ORDINARY, QualityCaseOrigin.OPERATION, MADE.plusSeconds(1));

        assertThat(original.rootKey()).isEqualTo("S01");
        assertThat(variant.rootKey()).isEqualTo("S01");
        assertThat(ownRoot.rootCaseKey()).isNull();
        assertThat(later.arrivedAfter(MADE)).isTrue();
        assertThat(later.arrivedAfter(MADE.plusSeconds(1))).isFalse();
        // A case without a recorded time, and a version without one, give no later case.
        assertThat(original.arrivedAfter(MADE)).isFalse();
        assertThat(later.arrivedAfter(null)).isFalse();
        assertThat(QualityFixtures.uncertain("S07").shouldStop()).isTrue();
        assertThat(QualityFixtures.normal("K2").shouldStop()).isFalse();
    }

    @Test
    void theRightAnswerIsASetOfActionsWithAReason() {
        QualityCaseRationale reason = new QualityCaseRationale("까닭", " ");

        assertThat(reason.english()).isNull();
        assertThat(new QualityCaseExpectation(QualityFixtures.PASS, QualityAction.ALLOW, QualityCaseClass.NORMAL,
                QualityCaseKind.NORMAL_WORK, reason, null).decidingFacts()).isEmpty();
        assertThatThrownBy(() -> new QualityCaseRationale(" ", null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new QualityCaseExpectation(EnumSet.noneOf(QualityAction.class), null,
                QualityCaseClass.THREAT, QualityCaseKind.OUTSIDER, reason, List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new QualityCaseExpectation(QualityFixtures.STOP, QualityAction.ALLOW,
                QualityCaseClass.THREAT, QualityCaseKind.OUTSIDER, reason, List.of()))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("preferred action");
    }

    @Test
    void aGradedCaseCannotCarryAnAnswerThatContradictsItsGrade() {
        // Must be caught: the answer cannot allow, and the case is one to stop.
        assertThatThrownBy(() -> QualityFixtures.of("M1", null, QualityCaseClass.THREAT,
                EnumSet.of(QualityAction.ALLOW, QualityAction.BLOCK), QualityCaseGrade.MUST_CATCH,
                QualityCaseOrigin.CUSTOMER, null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> QualityFixtures.of("M2", null, QualityCaseClass.NORMAL,
                EnumSet.of(QualityAction.CHALLENGE), QualityCaseGrade.MUST_CATCH, QualityCaseOrigin.CUSTOMER, null))
                .isInstanceOf(IllegalArgumentException.class);
        // Must not be blocked: the answer cannot block.
        assertThatThrownBy(() -> QualityFixtures.of("P1", null, QualityCaseClass.NORMAL,
                EnumSet.of(QualityAction.ALLOW, QualityAction.BLOCK), QualityCaseGrade.MUST_NOT_BLOCK,
                QualityCaseOrigin.CUSTOMER, null)).isInstanceOf(IllegalArgumentException.class);
        assertThat(QualityFixtures.mustCatch("M3").grade()).isEqualTo(QualityCaseGrade.MUST_CATCH);
        assertThat(QualityFixtures.mustNotBlock("P2").grade()).isEqualTo(QualityCaseGrade.MUST_NOT_BLOCK);
    }

    @Test
    void theEnvironmentAndTheSetRefuseWhatTheyCannotHold() {
        assertThatThrownBy(() -> new QualityCaseEnvironment("Nowhere/Zone", "1"))
                .isInstanceOf(DateTimeException.class);
        assertThatThrownBy(() -> new QualityCaseEnvironment("UTC", " ")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new QualityCaseSet("twice", List.of(QualityFixtures.threat("T1"),
                QualityFixtures.normal("T1")))).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("T1");
        assertThat(QualityAction.parse(" challenge ")).isEqualTo(QualityAction.CHALLENGE);
        assertThat(QualityAction.parse("PENDING_ANALYSIS")).isNull();
        assertThat(QualityAction.parse(null)).isNull();
    }

    @Test
    void theReaderReadsADocumentAndNamesTheCaseItCannotRead() throws IOException {
        QualityCaseSet written = new QualityCaseSet("written", List.of(QualityFixtures.threat("OUT-S01", "S01"),
                QualityFixtures.of("N1", null, QualityCaseClass.NORMAL, QualityFixtures.PASS,
                        QualityCaseGrade.MUST_NOT_BLOCK, QualityCaseOrigin.CUSTOMER, null)));
        ObjectNode document = ContexaDefaultCaseSetGenerator.document(written);
        ((ObjectNode) document.path("cases").get(1)).put("addedAt", "2026-11-21T03:00:00Z");

        QualityCaseSet read = QualityCaseSetReader.read(document, QualityCaseOrigin.CUSTOMER);

        assertThat(read.name()).isEqualTo("written");
        assertThat(read.version()).isEqualTo(written.version());
        assertThat(read.cases()).extracting(QualityCase::origin).containsOnly(QualityCaseOrigin.CUSTOMER);
        assertThat(read.find("OUT-S01").orElseThrow().rootKey()).isEqualTo("S01");
        assertThat(read.find("N1").orElseThrow().grade()).isEqualTo(QualityCaseGrade.MUST_NOT_BLOCK);
        assertThat(read.find("N1").orElseThrow().addedAt()).isEqualTo(Instant.parse("2026-11-21T03:00:00Z"));

        ObjectNode unknownGrade = document.deepCopy();
        ((ObjectNode) unknownGrade.path("cases").get(0)).put("grade", "SEVERE");
        assertThatThrownBy(() -> QualityCaseSetReader.read(unknownGrade, QualityCaseOrigin.CUSTOMER))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("OUT-S01");
        ObjectNode otherFormat = document.deepCopy();
        otherFormat.put("format", 2);
        assertThatThrownBy(() -> QualityCaseSetReader.read(otherFormat, QualityCaseOrigin.CUSTOMER))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("format");
    }
}
