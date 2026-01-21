package io.contexa.contexaidentity.security.core.mfa.policy;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexacommon.enums.AuthType;

public interface MfaPolicyProvider {

    MfaDecision evaluateInitialMfaRequirement(FactorContext ctx);

    NextFactorDecision evaluateNextFactor(FactorContext ctx);

    boolean isFactorAvailableForUser(String username, AuthType factorType, FactorContext ctx);

    CompletionDecision evaluateCompletion(FactorContext ctx, AuthenticationFlowConfig mfaFlowConfig);

    default Integer getRequiredFactorCount(String userId, String flowType) {
        
        if ("mfa".equalsIgnoreCase(flowType)) {
            return 2;
        } else if ("mfa-stepup".equalsIgnoreCase(flowType)) {
            return 1;
        }
        return 1;
    }
}