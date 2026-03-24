package io.contexa.contexacommon.security.bridge.coverage;

import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

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
        }
        else {
            if (authorizationStamp.effect() == AuthorizationEffect.UNKNOWN) {
                missing.add(MissingBridgeContext.AUTHORIZATION_EFFECT);
            }
            if (authorizationStamp.effectiveAuthorities().isEmpty() && authorizationStamp.effectiveRoles().isEmpty()) {
                missing.add(MissingBridgeContext.AUTHORIZATION_AUTHORITIES);
            }
        }
        if (requiresDelegationMetadata(delegationStamp)) {
            missing.add(MissingBridgeContext.DELEGATION);
        }

        BridgeCoverageLevel level = resolveLevel(authenticationStamp, authorizationStamp, delegationStamp, missing);
        return new BridgeCoverageReport(
                level,
                resolveScore(level, missing, authorizationStamp),
                missing,
                resolveSummary(level, missing),
                resolveRemediationHints(missing)
        );
    }

    private BridgeCoverageLevel resolveLevel(
            AuthenticationStamp authenticationStamp,
            AuthorizationStamp authorizationStamp,
            DelegationStamp delegationStamp,
            LinkedHashSet<MissingBridgeContext> missing) {
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
        if (delegationStamp != null && delegationStamp.delegated() && !missing.contains(MissingBridgeContext.DELEGATION)) {
            return BridgeCoverageLevel.DELEGATION_CONTEXT;
        }
        return BridgeCoverageLevel.AUTHORIZATION_CONTEXT;
    }

    private int resolveScore(
            BridgeCoverageLevel level,
            LinkedHashSet<MissingBridgeContext> missing,
            AuthorizationStamp authorizationStamp) {
        int score = switch (level) {
            case NONE -> 0;
            case AUTHENTICATION_ONLY -> 40;
            case AUTHORIZATION_CONTEXT -> 75;
            case DELEGATION_CONTEXT -> 90;
        };
        if (level == BridgeCoverageLevel.AUTHORIZATION_CONTEXT) {
            if (missing.contains(MissingBridgeContext.AUTHORIZATION_EFFECT)) {
                score -= 10;
            }
            if (missing.contains(MissingBridgeContext.AUTHORIZATION_AUTHORITIES)) {
                score -= 10;
            }
            if (missing.contains(MissingBridgeContext.DELEGATION)) {
                score -= 8;
            }
            if (authorizationStamp != null && "AUTHENTICATION_DERIVED".equalsIgnoreCase(authorizationStamp.decisionSource())) {
                score -= 7;
            }
        }
        return Math.max(0, Math.min(100, score));
    }

    private String resolveSummary(BridgeCoverageLevel level, LinkedHashSet<MissingBridgeContext> missing) {
        return switch (level) {
            case NONE -> "Bridge did not establish a trusted authenticated principal for the current request.";
            case AUTHENTICATION_ONLY -> "Bridge resolved authentication, but request-level authorization context is still incomplete.";
            case AUTHORIZATION_CONTEXT -> {
                if (missing.contains(MissingBridgeContext.AUTHORIZATION_EFFECT) || missing.contains(MissingBridgeContext.AUTHORIZATION_AUTHORITIES)) {
                    yield "Bridge resolved authentication and partial authorization context for the current request.";
                }
                if (missing.contains(MissingBridgeContext.DELEGATION)) {
                    yield "Bridge resolved authentication and authorization context, but delegated execution metadata is incomplete for this request.";
                }
                yield "Bridge resolved authentication and authorization context for the current request.";
            }
            case DELEGATION_CONTEXT -> "Bridge resolved authentication, authorization, and delegated execution context for the current request.";
        };
    }

    private List<String> resolveRemediationHints(LinkedHashSet<MissingBridgeContext> missing) {
        List<String> hints = new ArrayList<>();
        for (MissingBridgeContext missingContext : missing) {
            switch (missingContext) {
                case AUTHENTICATION -> hints.add("Provide an authentication bridge so the client principal can be normalized into SecurityContext.");
                case PRINCIPAL_ID -> hints.add("Expose a stable principal identifier through SecurityContext, headers, session, or request attributes.");
                case AUTHORIZATION -> hints.add("Provide an authorization stamp or map effective roles and permissions from the client authorization flow.");
                case AUTHORIZATION_EFFECT -> hints.add("Populate an explicit authorization effect such as ALLOW or DENY for the current request.");
                case AUTHORIZATION_AUTHORITIES -> hints.add("Expose effective roles or authorities for the current request so post-auth scope reasoning can start.");
                case DELEGATION -> hints.add("If delegated agents are used, propagate agent identity, objective, and allowed scope metadata for the current request.");
            }
        }
        return List.copyOf(hints);
    }

    private boolean requiresDelegationMetadata(DelegationStamp delegationStamp) {
        if (delegationStamp == null || !delegationStamp.delegated()) {
            return false;
        }
        boolean missingAgent = delegationStamp.agentId() == null || delegationStamp.agentId().isBlank();
        boolean missingObjective = (delegationStamp.objectiveId() == null || delegationStamp.objectiveId().isBlank())
                && (delegationStamp.objectiveSummary() == null || delegationStamp.objectiveSummary().isBlank());
        boolean missingScope = delegationStamp.allowedOperations().isEmpty() && delegationStamp.allowedResources().isEmpty();
        return missingAgent || missingObjective || missingScope;
    }
}
