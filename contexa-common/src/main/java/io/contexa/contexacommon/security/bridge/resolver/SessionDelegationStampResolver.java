package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeObjectExtractor;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.SessionBridgeSupport;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;

public class SessionDelegationStampResolver implements DelegationStampResolver {

    @Override
    public Optional<DelegationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties) {
        BridgeProperties.Delegation.Session config = resolveConfig(properties);
        if (!config.isEnabled()) {
            return Optional.empty();
        }
        HttpSession session = request.getSession(false);
        if (session == null) {
            return Optional.empty();
        }

        Optional<SessionBridgeSupport.ResolvedSessionAttribute> resolvedSessionAttribute = SessionBridgeSupport.resolveBest(
                session,
                config.getAttribute(),
                config.getAttributeCandidates(),
                config.isAutoDiscover(),
                candidate -> scoreDelegationCandidate(candidate, config)
        );
        if (resolvedSessionAttribute.isEmpty()) {
            return Optional.empty();
        }

        Object sessionDelegation = resolvedSessionAttribute.get().attributeValue();
        String agentId = BridgeObjectExtractor.extractString(sessionDelegation, config.getAgentIdKeys());
        String objectiveId = BridgeObjectExtractor.extractString(sessionDelegation, config.getObjectiveIdKeys());
        String objectiveFamily = BridgeObjectExtractor.extractString(sessionDelegation, config.getObjectiveFamilyKeys());
        Boolean delegated = BridgeObjectExtractor.extractBoolean(sessionDelegation, config.getDelegatedKeys());
        List<String> allowedOperations = List.copyOf(new LinkedHashSet<>(BridgeObjectExtractor.extractStringSet(sessionDelegation, config.getAllowedOperationsKeys())));
        List<String> allowedResources = List.copyOf(new LinkedHashSet<>(BridgeObjectExtractor.extractStringSet(sessionDelegation, config.getAllowedResourcesKeys())));
        Boolean approvalRequired = BridgeObjectExtractor.extractBoolean(sessionDelegation, config.getApprovalRequiredKeys());
        Boolean privilegedExportAllowed = BridgeObjectExtractor.extractBoolean(sessionDelegation, config.getPrivilegedExportAllowedKeys());
        Boolean containmentOnly = BridgeObjectExtractor.extractBoolean(sessionDelegation, config.getContainmentOnlyKeys());
        Instant expiresAt = BridgeObjectExtractor.extractInstant(sessionDelegation, config.getExpiresAtKeys());

        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>(BridgeObjectExtractor.extractAttributes(sessionDelegation, config.getAttributeKeys()));
        attributes.put("delegationResolver", "SESSION");
        attributes.put("bridgeSessionAttribute", resolvedSessionAttribute.get().attributeName());
        attributes.put("bridgeSessionDetectionScore", resolvedSessionAttribute.get().score());

        return Optional.of(new DelegationStamp(
                resolveSubjectId(request, sessionDelegation, config),
                agentId,
                Boolean.TRUE.equals(delegated),
                objectiveId,
                objectiveFamily,
                BridgeObjectExtractor.extractString(sessionDelegation, config.getObjectiveSummaryKeys()),
                allowedOperations,
                allowedResources,
                approvalRequired,
                privilegedExportAllowed,
                containmentOnly,
                expiresAt,
                attributes
        ));
    }

    private BridgeProperties.Delegation.Session resolveConfig(BridgeProperties properties) {
        if (properties == null || properties.getDelegation() == null || properties.getDelegation().getSession() == null) {
            return new BridgeProperties.Delegation.Session();
        }
        return properties.getDelegation().getSession();
    }

    private int scoreDelegationCandidate(Object candidate, BridgeProperties.Delegation.Session config) {
        int score = 0;
        if (BridgeObjectExtractor.extractBoolean(candidate, config.getDelegatedKeys()) != null) {
            score += 1;
        }
        if (BridgeObjectExtractor.extractString(candidate, config.getAgentIdKeys()) != null) {
            score += 3;
        }
        if (BridgeObjectExtractor.extractString(candidate, config.getObjectiveIdKeys()) != null) {
            score += 3;
        }
        if (BridgeObjectExtractor.extractString(candidate, config.getObjectiveFamilyKeys()) != null) {
            score += 2;
        }
        if (BridgeObjectExtractor.extractString(candidate, config.getObjectiveSummaryKeys()) != null) {
            score += 1;
        }
        if (!BridgeObjectExtractor.extractStringSet(candidate, config.getAllowedOperationsKeys()).isEmpty()) {
            score += 2;
        }
        if (!BridgeObjectExtractor.extractStringSet(candidate, config.getAllowedResourcesKeys()).isEmpty()) {
            score += 2;
        }
        if (BridgeObjectExtractor.extractBoolean(candidate, config.getApprovalRequiredKeys()) != null) {
            score += 1;
        }
        if (BridgeObjectExtractor.extractBoolean(candidate, config.getPrivilegedExportAllowedKeys()) != null) {
            score += 1;
        }
        if (BridgeObjectExtractor.extractBoolean(candidate, config.getContainmentOnlyKeys()) != null) {
            score += 1;
        }
        if (BridgeObjectExtractor.extractInstant(candidate, config.getExpiresAtKeys()) != null) {
            score += 1;
        }
        if (BridgeObjectExtractor.extractString(candidate, config.getPrincipalIdKeys()) != null) {
            score += 1;
        }
        return score;
    }

    private String resolveSubjectId(HttpServletRequest request, Object sessionDelegation, BridgeProperties.Delegation.Session config) {
        String subjectId = BridgeObjectExtractor.extractString(sessionDelegation, config.getPrincipalIdKeys());
        if (subjectId != null && !subjectId.isBlank()) {
            return subjectId;
        }
        return SecurityContextStampSupport.resolveCurrentPrincipalId(request);
    }
}
