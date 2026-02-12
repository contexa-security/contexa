package io.contexa.contexaidentity.security.core.mfa.policy;

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;

public interface MfaPolicyProvider {

    MfaDecision evaluateInitialMfaRequirement(FactorContext ctx);

    NextFactorDecision evaluateNextFactor(FactorContext ctx);

    boolean isFactorAvailableForUser(String username, AuthType factorType, FactorContext ctx);

    default Integer getRequiredFactorCount(String userId, String flowType) {
        
        if ("mfa".equalsIgnoreCase(flowType)) {
            return 2;
        } else if ("mfa-stepup".equalsIgnoreCase(flowType)) {
            return 1;
        }
        return 1;
    }
}