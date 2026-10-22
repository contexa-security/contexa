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

import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.DrawnPrompt;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.Outcome;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.ReasonFinding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Finding 12 of the v21 plan (bundle v21.5): the counted fact of the past records ({@code PastRecordCounts}, the
 * request's action counted over the user's past allowed records on this target) states an earlier allowed record on the
 * same target, as the dictionary's use of that entry says. The v21 output contract lets PAST_RECORD_SAME_TARGET cite it,
 * the system text names it, and the response check no longer asks again for a citation the line states.
 */
class V21PastRecordCountsCitationTest {

    private static final String CODE = "PAST_RECORD_SAME_TARGET";

    /** The past records of a sealed v21.4 prompt (S17, protocol-287fec9b), with one record line and one records line. */
    private static final String PROMPT = """
            === RECORDS AND COMPARISONS (time zone UTC) ===
            [F4] Assignment: assigned to HX-310 (DESIGN); worked on HX-310 on 21 of the last 30 days

            === PAST RECORDS (scope PERSONAL_RETRIEVED_SUBSET; time zone UTC) ===
            PastRecordsState: 10 records of 10 candidates (10 authorized, 0 denied, relevance SAME_RESOURCE, PROJECTED)
            [P1] PastRecordCounts: EXPORT on this target 10 (last 28 h before this request); on other targets 0; entry point POST /api/projects/{projectKey}/exports used 10 times before
            [P2] PastRecord1: 09-29 Tue 16:01 (28 h before this request) ×3 / EXPORT / /api/projects/{projectKey}/exports / projectKey=HX-310 / 10 items / class SENSITIVE / 10.40.21.0/24 zone CORPORATE / Edge/140 on WINDOWS / PASSWORD login / allowed / same target: yes / authorized as ALLOWED_USER_SCOPE (scope USER, tenant bound, purpose match)
            """;

    @Test
    void theSameTargetCodeMayCiteTheCountedFactAsWellAsARecordButNoOtherLine() {
        List<ReasonFinding> findings = SecurityDecisionV21FactChecks.reasonFindings(null, DrawnPrompt.of(PROMPT),
                List.of(citation("P1"), citation("P2"), citation("F4")));

        assertThat(findings).extracting(ReasonFinding::outcome)
                .containsExactly(Outcome.UNDECIDED, Outcome.UNDECIDED, Outcome.MISMATCH);
        assertThat(findings.get(2).reason()).isEqualTo("the code does not cite DECISION_FACTS.Assignment");
        assertThat(SecurityDecisionFactChecks.reasonViolation(findings.subList(0, 2)))
                .as("no corrective retry for the counted fact or a record").isNull();
    }

    @Test
    void theSystemTextNamesTheCountedFactAmongTheLinesTheCodeCites() {
        assertThat(SecurityDecisionOutputContractV4.systemOutputBlock()).contains("- " + CODE
                + ": an earlier allowed record on the same target; PastRecordCounts, PastRecord\n");
    }

    @Test
    void everyCitableLineTheDictionaryUsesForTheCodeIsALineTheCodeCites() {
        List<String> cited = SecurityDecisionOutputContractV4.find(CODE).orElseThrow().citedFacts();
        List<String> used = SecurityDecisionPromptDictionary.V21_ENTRIES.stream()
                .filter(entry -> entry.block().factPrefix() != null)
                .filter(entry -> entry.decisionUse() != null && entry.decisionUse().contains(CODE))
                .map(V21PastRecordCountsCitationTest::name)
                .toList();

        assertThat(used).containsExactly("PAST_RECORDS.PastRecordCounts", "PAST_RECORDS.PastRecord{i}");
        assertThat(cited).containsExactlyInAnyOrderElementsOf(used);
    }

    private static SecurityDecisionOutputContract.Citation citation(String fact) {
        return new SecurityDecisionOutputContract.Citation(CODE, fact);
    }

    private static String name(PromptDictionaryEntry entry) {
        return entry.block().name() + "." + entry.name();
    }
}
