package io.contexa.contexacommon.security.bridge.coverage;

import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;

import java.util.LinkedHashSet;
import java.util.Set;

public class BridgeCoverageEvaluator {

    public BridgeCoverageReport evaluate(
            AuthenticationStamp authenticationStamp,
            AuthorizationStamp authorizationStamp,
            DelegationStamp delegationStamp) {
        LinkedHashSet<MissingBridgeContext> missing = new LinkedHashSet<>();
        if (authenticationStamp == null || !authenticationStamp.authenticated()) {
            missing.add(MissingBridgeContext.AUTHENTICATION);
        }
        if (authenticationStamp == null || authenticationStamp.principalId() == null || authenticationStamp.principalId().isBlank()) {
            missing.add(MissingBridgeContext.PRINCIPAL_ID);
        }
        if (authorizationStamp == null) {
            missing.add(MissingBridgeContext.AUTHORIZATION);
        } else {
            if (authorizationStamp.effect() == AuthorizationEffect.UNKNOWN) {
                missing.add(MissingBridgeContext.AUTHORIZATION_EFFECT);
            }
            if (authorizationStamp.effectiveAuthorities().isEmpty() && authorizationStamp.effectiveRoles().isEmpty()) {
                missing.add(MissingBridgeContext.AUTHORIZATION_AUTHORITIES);
            }
        }
        if (delegationStamp == null) {
            missing.add(MissingBridgeContext.DELEGATION);
        }

        BridgeCoverageLevel level = resolveLevel(authenticationStamp, authorizationStamp, delegationStamp);
        return new BridgeCoverageReport(level, resolveScore(level), Set.copyOf(missing));
    }

    private BridgeCoverageLevel resolveLevel(
            AuthenticationStamp authenticationStamp,
            AuthorizationStamp authorizationStamp,
            DelegationStamp delegationStamp) {
        boolean authenticationReady = authenticationStamp != null
                && authenticationStamp.authenticated()
                && authenticationStamp.principalId() != null
                && !authenticationStamp.principalId().isBlank();
        if (!authenticationReady) {
            return BridgeCoverageLevel.NONE;
        }
        if (authorizationStamp == null) {
            return BridgeCoverageLevel.AUTHENTICATION_ONLY;
        }
        if (delegationStamp != null && delegationStamp.delegated()) {
            return BridgeCoverageLevel.DELEGATION_CONTEXT;
        }
        return BridgeCoverageLevel.AUTHORIZATION_CONTEXT;
    }

    private int resolveScore(BridgeCoverageLevel level) {
        return switch (level) {
            case NONE -> 0;
            case AUTHENTICATION_ONLY -> 40;
            case AUTHORIZATION_CONTEXT -> 75;
            case DELEGATION_CONTEXT -> 90;
        };
    }
}
