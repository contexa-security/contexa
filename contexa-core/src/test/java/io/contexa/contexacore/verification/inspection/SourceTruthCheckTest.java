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

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.ApprovalRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.OnCallRecord;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * W6-7 (P6-CHANGE-5), plan 2.1 of the prompt quality redesign: the facts the sealed decision collected are compared with
 * the host's own records of them, not the prompt's lines; without a host source the check says the facts are not
 * compared.
 */
class SourceTruthCheckTest {

    private static final Instant AT = Instant.parse("2026-09-30T05:30:00Z");

    @Test
    void withoutAHostSourceTheFactsAreNotCompared() {
        PromptInspectionTally tally = tally(collected());

        new SourceTruthCheck(null).inspect(tally);

        assertThat(tally.result().unverifiable()).isEqualTo(1);
        assertThat(tally.result().mismatched()).isZero();
    }

    @Test
    void aCollectedValueHoldingTheSourcePieceMatchesAndAnotherValueIsAMismatch() {
        PromptInspectionTally tally = tally(collected());
        PromptFactSourceVerifier verifier = subject -> List.of(
                new PromptFactSourceVerifier.SourceFact(PromptBlock.DECISION_FACTS, "Approval", "used 480 before this request", null, "work.export_job"),
                new PromptFactSourceVerifier.SourceFact(PromptBlock.DECISION_FACTS, "Approval", "APR-1 by pm-11", null, "work.approval"),
                new PromptFactSourceVerifier.SourceFact(PromptBlock.DECISION_FACTS, "OnCall", "on call", "not on call", "work.oncall_roster"));

        new SourceTruthCheck(verifier).inspect(tally);

        assertThat(tally.result().matched()).isEqualTo(2);
        assertThat(tally.result().mismatched()).isEqualTo(1);
        assertThat(tally.result().findings()).singleElement().satisfies(finding -> {
            assertThat(finding.entry()).isEqualTo("OnCall");
            assertThat(finding.expected()).isEqualTo("on call");
            assertThat(finding.actual()).isEqualTo("not on call");
            assertThat(finding.sourceRef()).isEqualTo("work.oncall_roster");
        });
    }

    /** The prompt's lines are not read: a line that says otherwise than what was collected changes nothing here. */
    @Test
    void thePromptsLinesAreNotRead() {
        PromptInspectionTally tally = tally(collected(), """
                === DECISION FACTS ===
                [F8] OnCall: on call
                """);
        PromptFactSourceVerifier verifier = subject -> List.of(
                new PromptFactSourceVerifier.SourceFact(PromptBlock.DECISION_FACTS, "OnCall", "not on call", null, "work.oncall_roster"));

        new SourceTruthCheck(verifier).inspect(tally);

        assertThat(tally.result().matched()).isEqualTo(1);
        assertThat(tally.result().mismatched()).isZero();
        assertThat(new SourceTruthCheck(verifier).dictionaryPromptOnly()).isFalse();
    }

    @Test
    void aFactTheSourceKeepsAndTheDecisionDidNotCollectIsAMismatch() {
        CanonicalSecurityContext context = collected();
        context.getFrictionProfile().setOnCall(null);
        PromptInspectionTally tally = tally(context);
        PromptFactSourceVerifier verifier = subject -> List.of(
                new PromptFactSourceVerifier.SourceFact(PromptBlock.DECISION_FACTS, "OnCall", "not on call", null, "work.oncall_roster"));

        new SourceTruthCheck(verifier).inspect(tally);

        assertThat(tally.result().mismatched()).isEqualTo(1);
        assertThat(tally.result().findings()).singleElement().extracting(PromptInspectionFinding::actual)
                .isEqualTo("not collected");
    }

    @Test
    void aFactTheSealedDecisionFactsNameUnknownIsItsMissingNotation() {
        CanonicalSecurityContext context = collected();
        context.getFrictionProfile().setOnCall(null);
        context.setDecisionFacts(new DecisionFacts(List.of(), List.of(), null, List.of("ClientSignals", "OnCall")));
        PromptInspectionTally tally = tally(context);
        PromptFactSourceVerifier verifier = subject -> List.of(
                new PromptFactSourceVerifier.SourceFact(PromptBlock.DECISION_FACTS, "OnCall", "not on call", null, "work.oncall_roster"));

        new SourceTruthCheck(verifier).inspect(tally);

        assertThat(tally.result().mismatched()).isZero();
        assertThat(tally.result().matched()).isEqualTo(1);
    }

    /** A line the sealed context keeps no structured value of cannot be compared, and says so. */
    @Test
    void aFactOfALineWithoutAStructuredValueIsNotCompared() {
        PromptInspectionTally tally = tally(collected());
        PromptFactSourceVerifier verifier = subject -> List.of(
                new PromptFactSourceVerifier.SourceFact(PromptBlock.DECISION_FACTS, "Ticket", "no ticket found", null, "work.itsm_ticket"));

        new SourceTruthCheck(verifier).inspect(tally);

        assertThat(tally.result().unverifiable()).isEqualTo(1);
        assertThat(tally.result().mismatched()).isZero();
        assertThat(tally.result().findings()).singleElement().satisfies(finding -> {
            assertThat(finding.entry()).isEqualTo("Ticket");
            assertThat(finding.sourceRef()).isEqualTo("work.itsm_ticket");
        });
    }

    @Test
    void withoutTheSealedContextTheFactsAreNotCompared() {
        PromptInspectionTally tally = tally(null);
        PromptFactSourceVerifier verifier = subject -> List.of(
                new PromptFactSourceVerifier.SourceFact(PromptBlock.DECISION_FACTS, "OnCall", "not on call", null, "work.oncall_roster"));

        new SourceTruthCheck(verifier).inspect(tally);

        assertThat(tally.result().unverifiable()).isEqualTo(1);
        assertThat(tally.result().matched()).isZero();
        assertThat(tally.result().mismatched()).isZero();
    }

    @Test
    void aSourceThatCannotBeReadNowInspectsThePackageAgainLater() {
        PromptInspectionTally tally = tally(collected());
        PromptFactSourceVerifier verifier = subject -> {
            throw new PromptInspectionUnavailableException("work database down", new IllegalStateException());
        };

        assertThatThrownBy(() -> new SourceTruthCheck(verifier).inspect(tally))
                .isInstanceOf(PromptInspectionUnavailableException.class);
    }

    /**
     * N-SRC-2: a host that does not keep the records of the sealed decision (the run rows the showcase removes when the
     * run ends) has the facts counted once as not compared, where it looked; it is not a source without facts.
     */
    @Test
    void aHostThatDoesNotKeepTheDecisionsRecordsCountsTheFactsAsNotCompared() {
        PromptInspectionTally tally = tally(collected());
        PromptFactSourceVerifier verifier = new PromptFactSourceVerifier() {
            @Override
            public List<PromptFactSourceVerifier.SourceFact> sourceFacts(PromptInspectionSubject subject) {
                return List.of();
            }

            @Override
            public PromptFactSourceVerifier.SourceReading read(PromptInspectionSubject subject) {
                return PromptFactSourceVerifier.SourceReading.notKept("work.run_principal");
            }
        };

        new SourceTruthCheck(verifier).inspect(tally);

        assertThat(tally.result().unverifiable()).isEqualTo(1);
        assertThat(tally.result().matched()).isZero();
        assertThat(tally.result().mismatched()).isZero();
        assertThat(tally.result().findings()).singleElement().satisfies(finding -> {
            assertThat(finding.sourceRef()).isEqualTo("work.run_principal");
            assertThat(finding.reason()).contains("does not keep the records of this decision");
        });
    }

    /** N-SRC-2: a host that keeps the records but no fact of them leaves nothing to compare, and nothing is counted. */
    @Test
    void aHostThatKeepsNoFactOfTheDecisionLeavesNothingToCompare() {
        PromptInspectionTally tally = tally(collected());

        new SourceTruthCheck(subject -> List.of()).inspect(tally);

        assertThat(tally.result().matched()).isZero();
        assertThat(tally.result().mismatched()).isZero();
        assertThat(tally.result().unverifiable()).isZero();
    }

    /** What the decision collected: approval APR-1 by pm-11 up to 500 items with 480 used, and not on call. */
    private static CanonicalSecurityContext collected() {
        CanonicalSecurityContext context = new CanonicalSecurityContext();
        context.setRequestObservedAt(AT);
        context.setAttributes(new HashMap<>());
        FrictionProfile friction = new FrictionProfile();
        friction.setApprovalRecords(List.of(ApprovalRecord.builder().approvalId("APR-1").approver("pm-11")
                .status("APPROVED").maxItems(500).usedItems(480).build()));
        friction.setOnCall(OnCallRecord.builder().onCall(false).build());
        context.setFrictionProfile(friction);
        return context;
    }

    private static PromptInspectionTally tally(CanonicalSecurityContext context) {
        return tally(context, "");
    }

    private static PromptInspectionTally tally(CanonicalSecurityContext context, String prompt) {
        PromptInspectionSubject subject = mock(PromptInspectionSubject.class);
        when(subject.canonicalContext()).thenReturn(context);
        when(subject.prompt()).thenReturn(InspectedPrompt.parse(prompt));
        return new PromptInspectionTally(SourceTruthCheck.CODE, subject);
    }
}
