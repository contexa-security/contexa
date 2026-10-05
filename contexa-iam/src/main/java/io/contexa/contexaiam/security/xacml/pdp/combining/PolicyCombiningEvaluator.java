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
package io.contexa.contexaiam.security.xacml.pdp.combining;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import org.springframework.security.authorization.AuthorizationDecision;

import java.util.List;
import java.util.Objects;

/**
 * Evaluates multiple policy decisions using XACML combining algorithms.
 *
 * <p>Each entry of the decision list is the result of one policy whose target matched the
 * request. A {@code null} entry is a NotApplicable result (a DENY policy whose condition was not
 * satisfied) and never takes part in combining. When no applicable decision remains,
 * DENY_UNLESS_PERMIT denies while every other algorithm falls back to the configured
 * no-matching-policy decision.</p>
 */
public class PolicyCombiningEvaluator {

    /**
     * Combine multiple authorization decisions using the specified algorithm.
     * An empty list or a list without applicable decisions falls back to PERMIT,
     * except for DENY_UNLESS_PERMIT which denies when policies matched but none applied.
     *
     * @param decisions list of decisions from all matching policies, {@code null} for NotApplicable
     * @param algorithm the combining algorithm to use
     * @return the combined authorization decision
     */
    public AuthorizationDecision evaluate(List<AuthorizationDecision> decisions, CombiningAlgorithm algorithm) {
        return evaluate(decisions, algorithm, NoPolicyDecision.PERMIT);
    }

    /**
     * Combine multiple authorization decisions using the specified algorithm.
     *
     * @param decisions        one entry per matching policy, {@code null} for NotApplicable
     * @param algorithm        the combining algorithm to use; {@code null} means FIRST_APPLICABLE
     * @param noPolicyDecision decision used when no policy matched, or when no matching policy
     *                         applied and the algorithm is not DENY_UNLESS_PERMIT
     * @return the combined authorization decision
     */
    public AuthorizationDecision evaluate(List<AuthorizationDecision> decisions, CombiningAlgorithm algorithm,
                                          NoPolicyDecision noPolicyDecision) {
        return combine(decisions, algorithm, noPolicyDecision).decision();
    }

    /**
     * Combines decisions like {@link #evaluate(List, CombiningAlgorithm, NoPolicyDecision)} and also
     * reports the algorithm and no-matching-policy decision that were applied, and whether the result
     * is that no-matching-policy decision.
     */
    public CombinedDecision combine(List<AuthorizationDecision> decisions, CombiningAlgorithm algorithm,
                                    NoPolicyDecision noPolicyDecision) {
        NoPolicyDecision fallback = noPolicyDecision != null ? noPolicyDecision : NoPolicyDecision.PERMIT;
        CombiningAlgorithm effectiveAlgorithm = algorithm != null ? algorithm : CombiningAlgorithm.FIRST_APPLICABLE;
        if (decisions == null || decisions.isEmpty()) {
            return new CombinedDecision(new AuthorizationDecision(fallback.isGranted()), effectiveAlgorithm, fallback, true);
        }
        AuthorizationDecision combined = switch (effectiveAlgorithm) {
            case DENY_OVERRIDES -> evaluateDenyOverrides(decisions);
            case PERMIT_OVERRIDES -> evaluatePermitOverrides(decisions);
            case FIRST_APPLICABLE -> evaluateFirstApplicable(decisions);
            case DENY_UNLESS_PERMIT -> evaluateDenyUnlessPermit(decisions);
        };
        return combined != null
                ? new CombinedDecision(combined, effectiveAlgorithm, fallback, false)
                : new CombinedDecision(new AuthorizationDecision(fallback.isGranted()), effectiveAlgorithm, fallback, true);
    }

    /**
     * Applies a policy effect to its condition result. An ALLOW policy is Permit when the condition
     * holds and Deny otherwise. A DENY policy is Deny when the condition holds and NotApplicable
     * ({@code null}) otherwise. A missing effect is treated like ALLOW.
     */
    public static AuthorizationDecision applyEffect(Policy.Effect effect, boolean conditionSatisfied) {
        if (effect == Policy.Effect.DENY) {
            return conditionSatisfied ? new AuthorizationDecision(false) : null;
        }
        return new AuthorizationDecision(conditionSatisfied);
    }

    /**
     * Result of combining policy decisions.
     *
     * @param decision                the combined decision
     * @param algorithm               the combining algorithm that was applied
     * @param noPolicyDecision        the no-matching-policy decision that was in effect
     * @param noPolicyDecisionApplied whether the decision is the no-matching-policy decision because
     *                                no policy matched or no matching policy applied
     */
    public record CombinedDecision(AuthorizationDecision decision, CombiningAlgorithm algorithm,
                                   NoPolicyDecision noPolicyDecision, boolean noPolicyDecisionApplied) {
    }

    private AuthorizationDecision evaluateDenyOverrides(List<AuthorizationDecision> decisions) {
        boolean hasPermit = false;
        for (AuthorizationDecision decision : decisions) {
            if (decision == null) {
                continue;
            }
            if (!decision.isGranted()) {
                return new AuthorizationDecision(false);
            }
            hasPermit = true;
        }
        return hasPermit ? new AuthorizationDecision(true) : null;
    }

    private AuthorizationDecision evaluatePermitOverrides(List<AuthorizationDecision> decisions) {
        boolean hasDeny = false;
        for (AuthorizationDecision decision : decisions) {
            if (decision == null) {
                continue;
            }
            if (decision.isGranted()) {
                return new AuthorizationDecision(true);
            }
            hasDeny = true;
        }
        return hasDeny ? new AuthorizationDecision(false) : null;
    }

    private AuthorizationDecision evaluateFirstApplicable(List<AuthorizationDecision> decisions) {
        return decisions.stream().filter(Objects::nonNull).findFirst().orElse(null);
    }

    private AuthorizationDecision evaluateDenyUnlessPermit(List<AuthorizationDecision> decisions) {
        for (AuthorizationDecision decision : decisions) {
            if (decision != null && decision.isGranted()) {
                return new AuthorizationDecision(true);
            }
        }
        return new AuthorizationDecision(false);
    }
}
