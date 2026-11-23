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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.DrawnPrompt;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.Outcome;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.ReasonFinding;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Quality plan 3.3, 3.6: the citation check counts what the response check found of the reason codes, in the terms of
 * the citation accuracy: the cited facts, those of them the prompt drew, and those of these the check named.
 */
class SecurityDecisionCitationCheckTest {

    private static final DrawnPrompt PROMPT = new DrawnPrompt(Set.of(),
            Map.of("F1", "DECISION_FACTS.DeviationsFromBaseline", "P1", "PAST_RECORDS.PastRecord1"),
            Map.of("U1", "Policy"));

    @Test
    void theCountsAreThoseOfTheFindingsTheResponseCheckWorkedOut() {
        SecurityDecisionCitationCheck check = SecurityDecisionCitationCheck.checked(PROMPT, List.of(
                new ReasonFinding("DEVIATION_TIME", "F1", Outcome.MATCH, "the line"),
                new ReasonFinding("THREAT_MATCH", "P1", Outcome.UNDECIDED, "cannot be decided"),
                new ReasonFinding("MATERIAL_MISSING_EVIDENCE", "U1", Outcome.MATCH, "the UNKNOWN line names Policy"),
                new ReasonFinding("DEVIATION_NETWORK", "F1", Outcome.MISMATCH, "the line does not state it"),
                new ReasonFinding("DEVIATION_TIME", "F9", Outcome.MISMATCH, "the prompt gives no fact this ID")));

        assertThat(check.state()).isEqualTo(SecurityDecisionCitationCheck.State.CHECKED);
        assertThat(check.cited()).isEqualTo(5);
        assertThat(check.present()).as("a line ID or an ID of the UNKNOWN line").isEqualTo(4);
        assertThat(check.flagged()).as("named on a line that exists").isEqualTo(1);
        assertThat(check.undecided()).isEqualTo(1);
        assertThat(check.unsupported()).isTrue();
        // The citation accuracy of this answer: the present ones the check did not name, of all cited.
        assertThat(check.present() - check.flagged()).isEqualTo(3);
        assertThat(check.findings()).extracting(SecurityDecisionCitationCheck.Finding::present)
                .containsExactly(true, true, true, true, false);
        assertThat(check.findings().get(3).reason()).isEqualTo("the line does not state it");
    }

    @Test
    void anAnswerWithoutANamedCodeIsNotUnsupported() {
        SecurityDecisionCitationCheck check = SecurityDecisionCitationCheck.checked(PROMPT, List.of(
                new ReasonFinding("DEVIATION_TIME", "F1", Outcome.MATCH, "the line"),
                new ReasonFinding("THREAT_MATCH", "P1", Outcome.UNDECIDED, "cannot be decided")));

        assertThat(check.cited()).isEqualTo(2);
        assertThat(check.present()).isEqualTo(2);
        assertThat(check.flagged()).isZero();
        assertThat(check.unsupported()).isFalse();
    }

    /** An answer whose citations could not be checked keeps how many facts it cites, counted as the check counts them. */
    @Test
    void anUncheckedAnswerKeepsOnlyHowManyFactsItCites() {
        List<SecurityDecisionOutputContract.Citation> citations = new ArrayList<>();
        citations.add(new SecurityDecisionOutputContract.Citation("DEVIATION_TIME", "F1"));
        citations.add(null);
        citations.add(new SecurityDecisionOutputContract.Citation(null, "F1"));
        citations.add(new SecurityDecisionOutputContract.Citation("DEVIATION_NETWORK", null));

        SecurityDecisionCitationCheck check = SecurityDecisionCitationCheck.skipped(citations);

        assertThat(check.state()).isEqualTo(SecurityDecisionCitationCheck.State.SKIPPED);
        assertThat(check.cited()).as("a citation without a code is none, as the check reads it").isEqualTo(2);
        assertThat(check.present()).isNull();
        assertThat(check.flagged()).isNull();
        assertThat(check.undecided()).isNull();
        assertThat(check.unsupported()).isNull();
        assertThat(check.findings()).isEmpty();
        assertThat(SecurityDecisionCitationCheck.skipped(null).cited()).isZero();
    }

    /** The check travels in metadata maps and in a replay's answer, so it is written and read as JSON as it is. */
    @Test
    void itIsWrittenAndReadAsJson() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        SecurityDecisionCitationCheck check = SecurityDecisionCitationCheck.checked(PROMPT, List.of(
                new ReasonFinding("DEVIATION_TIME", "F1", Outcome.MATCH, "the line"),
                new ReasonFinding("DEVIATION_TIME", "F9", Outcome.MISMATCH, "the prompt gives no fact this ID")));

        String json = mapper.writeValueAsString(check);

        assertThat(mapper.readTree(json).path("state").asText()).isEqualTo("CHECKED");
        assertThat(mapper.readTree(json).path("findings").get(1).path("outcome").asText()).isEqualTo("MISMATCH");
        assertThat(mapper.readValue(json, SecurityDecisionCitationCheck.class)).isEqualTo(check);
        SecurityDecisionCitationCheck skipped = SecurityDecisionCitationCheck.skipped(List.of());
        assertThat(mapper.readValue(mapper.writeValueAsString(skipped), SecurityDecisionCitationCheck.class))
                .isEqualTo(skipped);
        assertThat(SecurityDecisionCitationCheck.of(check)).isSameAs(check);
        assertThat(SecurityDecisionCitationCheck.of("CHECKED")).isNull();
    }
}
