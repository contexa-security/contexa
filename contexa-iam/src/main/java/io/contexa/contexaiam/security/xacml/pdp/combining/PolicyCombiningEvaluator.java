package io.contexa.contexaiam.security.xacml.pdp.combining;

import org.springframework.security.authorization.AuthorizationDecision;

import java.util.List;

/**
 * Evaluates multiple policy decisions using XACML combining algorithms.
 */
public class PolicyCombiningEvaluator {

    /**
     * Combine multiple authorization decisions using the specified algorithm.
     *
     * @param decisions list of decisions from all matching policies
     * @param algorithm the combining algorithm to use
     * @return the combined authorization decision
     */
    public AuthorizationDecision evaluate(List<AuthorizationDecision> decisions, CombiningAlgorithm algorithm) {
        if (decisions.isEmpty()) {
            return new AuthorizationDecision(true);
        }

        return switch (algorithm) {
            case DENY_OVERRIDES -> evaluateDenyOverrides(decisions);
            case PERMIT_OVERRIDES -> evaluatePermitOverrides(decisions);
            case FIRST_APPLICABLE -> evaluateFirstApplicable(decisions);
            case DENY_UNLESS_PERMIT -> evaluateDenyUnlessPermit(decisions);
        };
    }

    private AuthorizationDecision evaluateDenyOverrides(List<AuthorizationDecision> decisions) {
        boolean hasAllow = false;
        for (AuthorizationDecision decision : decisions) {
            if (!decision.isGranted()) {
                return new AuthorizationDecision(false);
            }
            hasAllow = true;
        }
        return new AuthorizationDecision(hasAllow);
    }

    private AuthorizationDecision evaluatePermitOverrides(List<AuthorizationDecision> decisions) {
        for (AuthorizationDecision decision : decisions) {
            if (decision.isGranted()) {
                return new AuthorizationDecision(true);
            }
        }
        return new AuthorizationDecision(false);
    }

    private AuthorizationDecision evaluateFirstApplicable(List<AuthorizationDecision> decisions) {
        return decisions.get(0);
    }

    private AuthorizationDecision evaluateDenyUnlessPermit(List<AuthorizationDecision> decisions) {
        for (AuthorizationDecision decision : decisions) {
            if (decision.isGranted()) {
                return new AuthorizationDecision(true);
            }
        }
        return new AuthorizationDecision(false);
    }
}
