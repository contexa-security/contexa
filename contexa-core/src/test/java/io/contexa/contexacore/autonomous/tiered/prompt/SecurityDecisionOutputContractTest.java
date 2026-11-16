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

import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What the output contracts share since v3 (dictionary 4, W4-2): the four responses and the form of a fact ID. The v3
 * reason codes, schema and output block went with the v20 bundle (plan 6-2); what the v19 and v20 contract said of a
 * repeat and of a missing fact the v1.0 prompt and the output contract v4 codes still say.
 */
class SecurityDecisionOutputContractTest {

    @Test
    void theActionsAreTheFourResponsesInOrderOfStrength() {
        assertThat(SecurityDecisionOutputContract.ACTIONS).containsExactly("ALLOW", "CHALLENGE", "ESCALATE", "BLOCK");
        assertThat(SecurityDecisionOutputContractV4.ACTIONS).isEqualTo(SecurityDecisionOutputContract.ACTIONS);
    }

    @Test
    void aFactIdIsTheLetterOfItsBlockAndANumber() {
        Pattern factId = Pattern.compile(SecurityDecisionOutputContract.FACT_ID_PATTERN);

        assertThat(Set.of("B1", "S2", "R3", "F12", "P4", "U1")).allMatch(id -> factId.matcher(id).matches());
        assertThat(Set.of("X1", "F123", "f1", "F", "1")).noneMatch(id -> factId.matcher(id).matches());
        assertThat(SecurityDecisionOutputContractV4.FACT_ID_PATTERN).isEqualTo(SecurityDecisionOutputContract.FACT_ID_PATTERN);
    }

    /** N-FRIC-1 (Q-87): a repeat in the session is a fact; alone it asks for no stronger action. */
    @Test
    void aRepeatAloneIsNoReasonForAStrongerAction() {
        String judgment = SecurityDecisionPromptDocument.product().draw(AssembledPrompt.JUDGMENT, Set.of(), null);

        assertThat(judgment).contains("A repeat, a new target or a large volume matters only through the mismatch it"
                + " makes with the work's records, purpose or the usual behaviour");
        assertThat(SecurityDecisionOutputContractV4.find("REPEAT_IN_SESSION")).isPresent();
    }

    /** N-UID-1 (Q-87): the missing-evidence code cites the line that names the missing fact. */
    @Test
    void theMissingEvidenceCodeCitesTheUnknownLine() {
        assertThat(SecurityDecisionOutputContractV4.find("MATERIAL_MISSING_EVIDENCE").orElseThrow().citedFacts())
                .containsExactly("UNKNOWN.Unknown");
    }
}
