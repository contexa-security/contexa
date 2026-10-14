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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W3-2: the value of the past record state says what the retrieval state says, each fact once.
 */
class SecurityDecisionPromptValuesTest {

    @Test
    void aRetrievalThatTimedOutIsNotRetrievedAndSaysSoOnce() {
        SecurityDecisionPromptSections.RagState timedOut = new SecurityDecisionPromptSections.RagState(
                true, "TIMEOUT", "TIMEOUT", "NOT_APPLICABLE", "UNAVAILABLE", "NONE", 0, false, 0, 0, 0);

        assertThat(SecurityDecisionPromptValues.pastRecordsState(timedOut)).isEqualTo("not retrieved (TIMEOUT)");
    }

    @Test
    void aStateWithItsOwnReasonKeepsTheReason() {
        SecurityDecisionPromptSections.RagState unavailable = new SecurityDecisionPromptSections.RagState(
                true, "UNAVAILABLE", "VECTOR_STORE_DOWN", "NOT_APPLICABLE", "UNAVAILABLE", "NONE", 0, false, 0, 0, 0);
        SecurityDecisionPromptSections.RagState zero = new SecurityDecisionPromptSections.RagState(
                true, "ZERO_RESULTS", "NO_DIRECT_PERSONAL_COMPARABLE", "ZERO_RESULTS_DECLARED", "NOT_APPLICABLE", "NONE",
                0, false, 0, 0, 0);
        SecurityDecisionPromptSections.RagState found = new SecurityDecisionPromptSections.RagState(
                true, "AVAILABLE", null, "PROJECTED", "APPLICABLE", "SAME_RESOURCE", 5, false, 9, 5, 4);

        assertThat(SecurityDecisionPromptValues.pastRecordsState(unavailable))
                .isEqualTo("not retrieved (UNAVAILABLE: VECTOR_STORE_DOWN)");
        assertThat(SecurityDecisionPromptValues.pastRecordsState(zero)).isEqualTo("none found (NO_DIRECT_PERSONAL_COMPARABLE)");
        assertThat(SecurityDecisionPromptValues.pastRecordsState(found))
                .isEqualTo("5 records of 9 candidates (5 authorized, 4 denied, relevance SAME_RESOURCE, PROJECTED)");
    }

    @Test
    void supportingCasesAreWrittenOnlyWhenThereAreSome() {
        String section = "\n=== SUPPORTING LEARNING CONTEXT ===\nSupportingBaselineStatus: AVAILABLE\n"
                + "SupportingComparableCount: 2\nSupportingComparableSummary: two cohort records\n";

        assertThat(SecurityDecisionPromptValues.supportingCases(0, section)).isNull();
        assertThat(SecurityDecisionPromptValues.supportingCases(2, null)).isNull();
        assertThat(SecurityDecisionPromptValues.supportingCases(2, section)).isEqualTo(
                "SupportingComparableCount: 2; SupportingComparableSummary: two cohort records; reference only");
    }

    /**
     * R1b-3: the past record forms are written once, for the render, the dictionary and the prompt inspector: the record
     * line of twelve fields and the search state line.
     */
    @Test
    void thePastRecordFormsAreTheSharedOnes() {
        Map<String, String> formats = SecurityDecisionPromptDictionary.ENTRIES.stream()
                .filter(entry -> entry.block() == PromptBlock.PAST_RECORDS || entry.block() == PromptBlock.SECOND_PASS)
                .collect(Collectors.toMap(PromptDictionaryEntry::name, PromptDictionaryEntry::formatPattern));

        assertThat(PastRecordLineValues.RECORD_FORMAT).isEqualTo(".+( / .+){11}");
        assertThat(formats.get("PastRecord{i}")).isEqualTo(PastRecordLineValues.RECORD_FORMAT);
        assertThat(formats.get("NewPastRecord{i}")).isEqualTo(PastRecordLineValues.RECORD_FORMAT);
        assertThat(formats.get("PastRecordsState")).isEqualTo(PastRecordLineValues.STATE_FORMAT);
        assertThat(PastRecordLineValues.COUNTED_STATE.matcher("5 records of 9 candidates (5 authorized)").matches()).isTrue();
        assertThat(PastRecordLineValues.EMPTY_STATE.matcher("not retrieved (TIMEOUT)").matches()).isTrue();
        assertThat(PastRecordLineValues.NOT_RETRIEVED_STATES).contains("TIMEOUT", "NOT_REQUESTED");
    }

    /**
     * R1b-3: the retrieval state's metadata form is the record's own, written for the sealed package and read back by
     * the prompt inspector; an absent state reads as nothing.
     */
    @Test
    void theRetrievalStateReadsBackFromItsMetadataForm() {
        SecurityDecisionPromptSections.RagState state = new SecurityDecisionPromptSections.RagState(true, "COMPLETED",
                null, "PROJECTED", "APPLICABLE", "HIGH", 2, true, 5, 2, 3, "TIMEOUT");
        SecurityDecisionPromptSections.RagState bare = new SecurityDecisionPromptSections.RagState(false, null, "NONE",
                null, null, null, 0, false, 0, 0, 0);

        assertThat(SecurityDecisionPromptSections.RagState.fromMetadata(state.toMetadata())).isEqualTo(state);
        assertThat(SecurityDecisionPromptSections.RagState.fromMetadata(bare.toMetadata())).isEqualTo(bare);
        assertThat(bare.toMetadata()).doesNotContainKeys("retrievalState", "earlierRetrievalState");
    }
}
