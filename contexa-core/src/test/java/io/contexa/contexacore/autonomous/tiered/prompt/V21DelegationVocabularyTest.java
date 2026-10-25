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

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RL-2 (bundle v21.15): the reason codes a model needs to say what it reads of a delegation or a policy. In the A6
 * measurement 45 of 84 rejected citations were {@code RECORD_COVERS_WORK} on a delegation or policy line and 12 were
 * {@code DELEGATION_SCOPE_DRIFT} for an amount the delegation's words do not allow; each rejection asked the model
 * again, and an answer given again turned three BLOCKs into ALLOWs.
 */
class V21DelegationVocabularyTest {

    private static final SecurityDecisionFactChecks.DrawnPrompt PROMPT = new SecurityDecisionFactChecks.DrawnPrompt(
            Set.of("DECISION_FACTS.Delegation", "DECISION_FACTS.Policy", "DECISION_FACTS.Assignment"),
            Map.of("F10", "DECISION_FACTS.Delegation", "F2", "DECISION_FACTS.Policy", "F3", "DECISION_FACTS.Assignment"),
            Map.of());

    private static List<SecurityDecisionFactChecks.ReasonFinding> findings(CanonicalSecurityContext context, String code,
                                                                          String fact) {
        return SecurityDecisionV21FactChecks.reasonFindings(context, PROMPT,
                List.of(new SecurityDecisionOutputContract.Citation(code, fact)));
    }

    @Test
    void aDelegationOrPolicyThatCoversTheWorkIsCitedUnderTheRecordCode() {
        assertThat(findings(null, "RECORD_COVERS_WORK", "F10")).singleElement()
                .satisfies(finding -> assertThat(finding.outcome()).isEqualTo(SecurityDecisionFactChecks.Outcome.MATCH));
        assertThat(findings(null, "RECORD_COVERS_WORK", "F2")).singleElement()
                .satisfies(finding -> assertThat(finding.outcome()).isEqualTo(SecurityDecisionFactChecks.Outcome.MATCH));
        // A line the code does not cite is still refused.
        assertThat(findings(null, "RECORD_COVERS_WORK", "F3")).singleElement()
                .satisfies(finding -> assertThat(finding.outcome()).isEqualTo(SecurityDecisionFactChecks.Outcome.MISMATCH));
    }

    @Test
    void theModelsReadingThatARequestExceedsTheDelegationsObjectiveIsItsOwnJudgment() {
        SecurityDecisionOutputContractV4.ReasonCode exceeded = SecurityDecisionOutputContractV4
                .find("DELEGATION_OBJECTIVE_EXCEEDED").orElseThrow();

        assertThat(exceeded.group()).isEqualTo(SecurityDecisionOutputContractV4.Group.DELEGATION);
        assertThat(exceeded.citedFacts()).containsExactly("DECISION_FACTS.Delegation", "SESSION.DelegationActivity");
        // Held on the line it cites, whether or not the core measured a drift.
        assertThat(findings(null, "DELEGATION_OBJECTIVE_EXCEEDED", "F10")).singleElement()
                .satisfies(finding -> assertThat(finding.outcome()).isEqualTo(SecurityDecisionFactChecks.Outcome.MATCH));
        assertThat(findings(CanonicalSecurityContext.builder()
                        .delegation(CanonicalSecurityContext.Delegation.builder().delegated(true).objectiveDrift(false).build())
                        .build(), "DELEGATION_OBJECTIVE_EXCEEDED", "F10")).singleElement()
                .satisfies(finding -> assertThat(finding.outcome()).isEqualTo(SecurityDecisionFactChecks.Outcome.MATCH));
    }

    @Test
    void theCoresOwnDriftCodeStillHoldsOnlyWhereTheCoreMeasuredADrift() {
        CanonicalSecurityContext noDrift = CanonicalSecurityContext.builder()
                .delegation(CanonicalSecurityContext.Delegation.builder().delegated(true).objectiveDrift(false).build())
                .build();
        CanonicalSecurityContext drift = CanonicalSecurityContext.builder()
                .delegation(CanonicalSecurityContext.Delegation.builder().delegated(true).objectiveDrift(true).build())
                .build();

        assertThat(findings(noDrift, "DELEGATION_SCOPE_DRIFT", "F10")).singleElement()
                .satisfies(finding -> assertThat(finding.outcome()).isEqualTo(SecurityDecisionFactChecks.Outcome.MISMATCH));
        assertThat(findings(drift, "DELEGATION_SCOPE_DRIFT", "F10")).singleElement()
                .satisfies(finding -> assertThat(finding.outcome()).isEqualTo(SecurityDecisionFactChecks.Outcome.MATCH));
    }
}
