package io.contexa.contexaidentity.security.core.mfa.policy;

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;

public interface MfaPolicyProvider {

    MfaDecision evaluateInitialMfaRequirement(FactorContext ctx);

    NextFactorDecision evaluateNextFactor(FactorContext ctx);

    boolean isFactorAvailableForUser(String username, AuthType factorType, FactorContext ctx);

    Integer getRequiredFactorCount(String userId, String flowType);
}