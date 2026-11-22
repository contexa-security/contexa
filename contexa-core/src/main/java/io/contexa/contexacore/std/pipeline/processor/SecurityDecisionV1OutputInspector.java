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
package io.contexa.contexacore.std.pipeline.processor;

import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionCitationCheck;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionRawOutputContractInspector.Inspection;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The response check of a v1.0 security decision (plan 2.2 B6): the v21 check as it is, then what v1.0 checks besides it,
 * in this order: a reason that rests on past records of the same target the prompt does not draw (A16, from v19), the
 * boundaries of the decision rules on the core's conclusions (B5, B6) and the minimum action floors when the host
 * enforces them (B4). What it finds joins the v21 findings in the one text the corrective retry names. The v21 check
 * stays a class of its own, so the v21 bundle's response check sources stay as they were.
 */
public final class SecurityDecisionV1OutputInspector {

    /** The pipeline metadata of a v1.0 rule an answer still breaks after the retry, kept for a person's review. */
    public static final String V1_RULE_BREACH = "securityDecisionV1RuleBreach";

    /** The prefix of a minimum action floor an answer breaks (W4-5), as the v20 response check names it. */
    public static final String MINIMUM_ACTION_VIOLATION = "MINIMUM_ACTION_VIOLATION";

    /**
     * The request parameter a strategy sets when the version of the event replaces an answer that still breaks a
     * decision rule (plan 6-2, decision D6).
     */
    public static final String FALLBACK_PARAMETER = "securityDecisionV1FallbackOnViolation";

    private final SecurityDecisionV21OutputInspector v21OutputInspector = new SecurityDecisionV21OutputInspector();

    /**
     * What a v1.0 answer is checked for besides the v21 checks: a reason that rests on past records the prompt does
     * not draw (from v19), the boundaries of the decision rules on the core's conclusions (the fallback variants), and
     * the minimum action floors when the host enforces them.
     *
     * @param conclusions the decision facts in the conclusions notation the context kept beside the records
     * @param boundaries  whether the boundaries are checked, on the facts the prompt states (every v1.0 variant with
     *                    the conclusions kept)
     * @param floors      the minimum action check when the host enforces the floors; null in observe mode
     * @param fallback    whether a boundary still broken after the retry is replaced by the action it names (the
     *                    v19 and v20 behaviour); without it the answer stays and the breach is recorded for review
     */
    public record V1Rules(DecisionFacts conclusions, boolean boundaries,
                          SecurityDecisionRawOutputContractInspector.MinimumActionCheck floors, boolean fallback) {
    }

    /**
     * The inspection of an answer with the explanations it gave as the record keeps them, whether the only thing wrong
     * is reason codes the lines do not support (RL-4), the v1.0 rule (boundary or floor) it breaks, if any, and what
     * the check found of each reason code (quality plan 3.6).
     */
    public record V1Inspection(Inspection inspection, List<Map<String, Object>> hypotheses,
                               boolean unsupportedCodesOnly, String ruleViolation,
                               SecurityDecisionCitationCheck citationCheck) {

        public V1Inspection(Inspection inspection, List<Map<String, Object>> hypotheses,
                            boolean unsupportedCodesOnly, String ruleViolation) {
            this(inspection, hypotheses, unsupportedCodesOnly, ruleViolation, null);
        }

        /** The v21 inspection of an answer that has no v1.0 rules to meet. */
        public static V1Inspection of(SecurityDecisionV21OutputInspector.V21Inspection v21) {
            return new V1Inspection(v21.inspection(), v21.hypotheses(), v21.unsupportedCodesOnly(), null,
                    v21.citationCheck());
        }
    }

    /** The v21 check of the answer, then the v1.0 rules; without rules, the v21 check alone. */
    public V1Inspection inspect(String rawResponse, String requestId, String attempt,
                                SecurityDecisionV21OutputInspector.V21Check check, V1Rules rules) {
        SecurityDecisionV21OutputInspector.V21Inspection v21 = v21OutputInspector.inspect(rawResponse, requestId, attempt,
                check);
        Inspection inspection = v21.inspection();
        SecurityDecisionResponseLite response = inspection.response();
        if (rules == null || check == null || inspection.parsingFallback() || response == null) {
            return V1Inspection.of(v21);
        }
        SecurityDecisionFactChecks.DrawnPrompt drawn = SecurityDecisionFactChecks.DrawnPrompt.of(check.userPrompt());
        List<String> parts = new ArrayList<>();
        // v1.0 (A16, from v19): a reason resting on past records of the same target the prompt does not draw.
        String pastRecordClaim = SecurityDecisionFactChecks.pastRecordClaimViolation(drawn, response.getReasoning());
        if (pastRecordClaim != null) {
            parts.add(pastRecordClaim);
        }
        String rule = null;
        // v1.0 (B5, B6): the boundaries of the decision rules, read on the conclusions they state.
        if (rules.boundaries()) {
            rule = SecurityDecisionFactChecks.boundaryViolation(check.context(), rules.conclusions(), drawn,
                    response.getAction());
        }
        // v1.0 (B4): the minimum action floors, when the host enforces them.
        if (rule == null && rules.floors() != null) {
            rule = minimumActionViolation(rules.floors(), response.getAction());
        }
        if (rule != null) {
            parts.add(rule);
        }
        if (parts.isEmpty()) {
            return V1Inspection.of(v21);
        }
        // The v1.0 findings follow the v21 findings in the one text the retry names; they are more than reason codes.
        String found = inspection.semanticViolation();
        String violation = found != null ? found + "; " + String.join("; ", parts) : String.join("; ", parts);
        Inspection joined = new Inspection(response, false, inspection.parseFailureCategory(),
                inspection.rawOutputHash(), inspection.rawOutputLength(), violation, violation);
        return new V1Inspection(joined, v21.hypotheses(), false, rule, v21.citationCheck());
    }

    /**
     * v1.0 (B4): the floors an answer is weaker than, as the v20 response check names them, or null: each rule that
     * applies with the action it asks for.
     */
    static String minimumActionViolation(SecurityDecisionRawOutputContractInspector.MinimumActionCheck check,
                                         String action) {
        List<MinimumActionRules.Hit> hits = MinimumActionRules.evaluate(check.facts(), check.resourceClass(),
                check.actionFamily(), check.settings());
        if (!MinimumActionRules.violatedBy(action, hits)) {
            return null;
        }
        List<String> rules = new ArrayList<>();
        for (MinimumActionRules.Hit hit : hits) {
            rules.add(hit.rule().code() + " requires " + hit.requiredAction() + " or a stronger action");
        }
        return MINIMUM_ACTION_VIOLATION + ": " + String.join("; ", rules);
    }
}
