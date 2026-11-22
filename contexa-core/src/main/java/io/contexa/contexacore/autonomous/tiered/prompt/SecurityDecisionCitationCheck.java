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

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.DrawnPrompt;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.Outcome;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.ReasonFinding;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * What the response check found of the reason codes of the answer a decision kept (quality plan 3.3, 3.6): how many
 * facts the codes cite, how many of those are lines the prompt drew, how many of these the check named, and each code's
 * finding. The decision path works the findings out to decide whether to ask the model again and reduced them to one
 * text; this keeps them, so that the citation accuracy can be counted on every decision and on every replay:
 * {@code (present - flagged) / cited}. It is taken of the answer that was kept, asked again or not, and nothing here
 * changes an answer.
 *
 * @param state       whether the citations were checked or the check was left out
 * @param cited       how many facts the reason codes cite (one per reason code the answer gave)
 * @param present     how many of the cited facts are IDs the prompt drew; null when the check was left out
 * @param flagged     how many of the present ones the check named: the code may not cite that line, the line does not
 *                    state what the code says, or the code is none of the output contract; null when left out
 * @param undecided   how many the facts could not decide; null when the check was left out
 * @param unsupported whether the check named any reason code of the kept answer (a flagged one, or one citing a fact
 *                    the prompt does not draw), whether or not the model was asked again; null when left out
 * @param findings    each reason code with the fact it cites and what it came to; empty when the check was left out
 */
public record SecurityDecisionCitationCheck(State state, int cited, Integer present, Integer flagged,
                                            Integer undecided, Boolean unsupported, List<Finding> findings) {

    /** The pipeline and response metadata key of the citation check of the answer that was kept. */
    public static final String METADATA_KEY = "securityDecisionCitationCheck";

    /** Whether the citations of an answer were checked. */
    public enum State {
        /** The citations were checked against the facts the prompt was drawn from. */
        CHECKED,
        /**
         * The check was left out, because the canonical context the prompt was drawn from was not there (plan 6-2).
         * Such an answer is no answer without a wrong citation: only the number of cited facts is known.
         */
        SKIPPED
    }

    /**
     * One reason code with the fact it cites.
     *
     * @param present whether the cited fact is an ID the prompt drew
     * @param reason  why it came to that, in the words of the check
     */
    public record Finding(String code, String fact, Outcome outcome, boolean present, String reason) {
    }

    public SecurityDecisionCitationCheck {
        Objects.requireNonNull(state, "state");
        findings = findings == null ? List.of() : List.copyOf(findings);
    }

    /** The check of an answer whose citations were checked, from the findings the response check worked out. */
    public static SecurityDecisionCitationCheck checked(DrawnPrompt prompt, List<ReasonFinding> reasonFindings) {
        List<Finding> findings = new ArrayList<>();
        int present = 0;
        int flagged = 0;
        int undecided = 0;
        boolean unsupported = false;
        for (ReasonFinding finding : reasonFindings == null ? List.<ReasonFinding>of() : reasonFindings) {
            boolean onALine = prompt != null && finding.fact() != null
                    && (prompt.lineIds().containsKey(finding.fact()) || prompt.unknownIds().containsKey(finding.fact()));
            if (onALine) {
                present++;
            }
            if (finding.outcome() == Outcome.MISMATCH) {
                unsupported = true;
                if (onALine) {
                    flagged++;
                }
            }
            if (finding.outcome() == Outcome.UNDECIDED) {
                undecided++;
            }
            findings.add(new Finding(finding.code(), finding.fact(), finding.outcome(), onALine, finding.reason()));
        }
        return new SecurityDecisionCitationCheck(State.CHECKED, findings.size(), present, flagged, undecided,
                unsupported, findings);
    }

    /** The check of an answer whose citations could not be checked: how many facts it cites, and nothing else. */
    public static SecurityDecisionCitationCheck skipped(List<SecurityDecisionOutputContract.Citation> citations) {
        int cited = 0;
        for (SecurityDecisionOutputContract.Citation citation
                : citations == null ? List.<SecurityDecisionOutputContract.Citation>of() : citations) {
            if (citation != null && citation.code() != null) {
                cited++;
            }
        }
        return new SecurityDecisionCitationCheck(State.SKIPPED, cited, null, null, null, null, List.of());
    }

    /** The citation check a metadata map carries under {@link #METADATA_KEY}, or null. */
    public static SecurityDecisionCitationCheck of(Object value) {
        return value instanceof SecurityDecisionCitationCheck check ? check : null;
    }
}
