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
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;

/**
 * What the response checks of a security decision share: the inspection of an answer, the inputs of the minimum action
 * rules, and the fallback of a rule an answer still breaks after the corrective retry. The checks themselves are the
 * v21 check of the form and of what an answer says and the v1.0 rules after it (plan 6-2: the v19 and v20 checks of
 * this class went with their bundles).
 */
public final class SecurityDecisionRawOutputContractInspector {

    /** N-OUT-1 (G1-1): the pipeline metadata key of the fallback of a contract violation left after the retry. */
    public static final String CONTRACT_FALLBACK_ACTION = "securityDecisionContractFallbackAction";

    private SecurityDecisionRawOutputContractInspector() {
    }

    /**
     * N-OUT-1 (G1-1, decision A): the fallback of a contract violation left after the corrective retry. It is ESCALATE
     * (decision A: the code does not choose the response) unless the broken rule asks for one action ESCALATE does not
     * give: a boundary that requires BLOCK gives BLOCK, the low risk boundary that requires ALLOW gives ALLOW.
     */
    public static String fallbackActionFor(String violation) {
        if ("REQUIRED_BLOCK_BOUNDARY_ACTION_MISMATCH".equals(violation)) {
            return "BLOCK";
        }
        if ("REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH".equals(violation)
                || SecurityDecisionFactChecks.REQUIRED_COVERED_WORK.equals(violation)) {
            return "ALLOW";
        }
        return "ESCALATE";
    }

    /** The minimum action rule inputs: the decision facts the prompt stated, the resource and the host's settings. */
    public record MinimumActionCheck(DecisionFacts facts, String resourceClass, String actionFamily,
                                     MinimumActionRules.Settings settings) {
    }

    public record Inspection(
            SecurityDecisionResponseLite response,
            boolean parsingFallback,
            String parseFailureCategory,
            String rawOutputHash,
            Integer rawOutputLength,
            String semanticViolation,
            String retryReason) {

        public boolean requiresRetry() {
            return parsingFallback || semanticViolation != null;
        }
    }
}
