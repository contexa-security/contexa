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
package io.contexa.contexacore.verification.inspection;

import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * W6-7 (P6-CHANGE-5): the facts the prompt states are compared with the host's own records of them; without a host
 * source the check says the facts are not compared.
 */
class SourceTruthCheckTest {

    private static final String PROMPT = """
            === DECISION FACTS ===
            [F5] Approval: APR-1 by pm-11, APPROVED, up to 500 items, used 480 before this request
            [F8] OnCall: not on call
            """;

    @Test
    void withoutAHostSourceTheFactsAreNotCompared() {
        PromptInspectionTally tally = tally(PROMPT);

        new SourceTruthCheck(null).inspect(tally);

        assertThat(tally.result().unverifiable()).isEqualTo(1);
        assertThat(tally.result().mismatched()).isZero();
    }

    @Test
    void aLineHoldingTheSourcePieceMatchesAndAnotherValueIsAMismatch() {
        PromptInspectionTally tally = tally(PROMPT);
        PromptFactSourceVerifier verifier = subject -> List.of(
                new PromptFactSourceVerifier.SourceFact(PromptBlock.DECISION_FACTS, "Approval", "used 480 before this request", null, "work.export_job"),
                new PromptFactSourceVerifier.SourceFact(PromptBlock.DECISION_FACTS, "OnCall", "on call", "not on call", "work.oncall_roster"));

        new SourceTruthCheck(verifier).inspect(tally);

        assertThat(tally.result().matched()).isEqualTo(1);
        assertThat(tally.result().mismatched()).isEqualTo(1);
        assertThat(tally.result().findings()).singleElement().satisfies(finding -> {
            assertThat(finding.entry()).isEqualTo("OnCall");
            assertThat(finding.factId()).isEqualTo("F8");
            assertThat(finding.actual()).isEqualTo("not on call");
        });
    }

    @Test
    void aFactTheSourceKeepsWithoutALineIsAMismatch() {
        PromptInspectionTally tally = tally(PROMPT);
        PromptFactSourceVerifier verifier = subject -> List.of(
                new PromptFactSourceVerifier.SourceFact(PromptBlock.DECISION_FACTS, "Ticket", "no ticket found", null, "work.itsm_ticket"));

        new SourceTruthCheck(verifier).inspect(tally);

        assertThat(tally.result().mismatched()).isEqualTo(1);
        assertThat(tally.result().findings()).singleElement().extracting(PromptInspectionFinding::actual).isEqualTo("no line");
    }

    @Test
    void aFactTheUnknownLineNamesIsItsMissingNotationNotALeftOutLine() {
        PromptInspectionTally tally = tally("""
                === DECISION FACTS ===
                [F5] Approval: APR-1 by pm-11, APPROVED, up to 500 items, used 480 before this request
                Unknown: not-integrated: [U1] ClientSignals, [U3] OnCall, [U4] PeerCohort
                """);
        PromptFactSourceVerifier verifier = subject -> List.of(
                new PromptFactSourceVerifier.SourceFact(PromptBlock.DECISION_FACTS, "OnCall", "not on call", null, "work.oncall_roster"));

        new SourceTruthCheck(verifier).inspect(tally);

        assertThat(tally.result().mismatched()).isZero();
        assertThat(tally.result().matched()).isEqualTo(1);
    }

    @Test
    void aSourceThatCannotBeReadNowInspectsThePackageAgainLater() {
        PromptInspectionTally tally = tally(PROMPT);
        PromptFactSourceVerifier verifier = subject -> {
            throw new PromptInspectionUnavailableException("work database down", new IllegalStateException());
        };

        assertThatThrownBy(() -> new SourceTruthCheck(verifier).inspect(tally))
                .isInstanceOf(PromptInspectionUnavailableException.class);
    }

    private static PromptInspectionTally tally(String prompt) {
        PromptInspectionSubject subject = mock(PromptInspectionSubject.class);
        when(subject.prompt()).thenReturn(InspectedPrompt.parse(prompt));
        return new PromptInspectionTally(SourceTruthCheck.CODE, subject);
    }
}
