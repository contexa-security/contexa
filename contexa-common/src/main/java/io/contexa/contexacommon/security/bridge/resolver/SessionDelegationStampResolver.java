package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeObjectExtractor;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
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
        Object sessionDelegation = session.getAttribute(config.getAttribute());
        if (sessionDelegation == null) {
            return Optional.empty();
        }

        String agentId = BridgeObjectExtractor.extractString(sessionDelegation, config.getAgentIdKeys());
        String objectiveId = BridgeObjectExtractor.extractString(sessionDelegation, config.getObjectiveIdKeys());
        Boolean delegated = BridgeObjectExtractor.extractBoolean(sessionDelegation, config.getDelegatedKeys());
        List<String> allowedOperations = List.copyOf(new LinkedHashSet<>(BridgeObjectExtractor.extractStringSet(sessionDelegation, config.getAllowedOperationsKeys())));
        List<String> allowedResources = List.copyOf(new LinkedHashSet<>(BridgeObjectExtractor.extractStringSet(sessionDelegation, config.getAllowedResourcesKeys())));
        Boolean approvalRequired = BridgeObjectExtractor.extractBoolean(sessionDelegation, config.getApprovalRequiredKeys());
        Boolean containmentOnly = BridgeObjectExtractor.extractBoolean(sessionDelegation, config.getContainmentOnlyKeys());
        Instant expiresAt = BridgeObjectExtractor.extractInstant(sessionDelegation, config.getExpiresAtKeys());

        if (delegated == null && agentId == null && objectiveId == null && allowedOperations.isEmpty() && allowedResources.isEmpty()) {
            return Optional.empty();
        }

        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>(BridgeObjectExtractor.extractAttributes(sessionDelegation, config.getAttributeKeys()));
        attributes.put("delegationResolver", "SESSION");

        return Optional.of(new DelegationStamp(
                resolveSubjectId(request, sessionDelegation, config),
                agentId,
                Boolean.TRUE.equals(delegated),
                objectiveId,
                BridgeObjectExtractor.extractString(sessionDelegation, config.getObjectiveSummaryKeys()),
                allowedOperations,
                allowedResources,
                approvalRequired,
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

    private String resolveSubjectId(HttpServletRequest request, Object sessionDelegation, BridgeProperties.Delegation.Session config) {
        String subjectId = BridgeObjectExtractor.extractString(sessionDelegation, config.getPrincipalIdKeys());
        if (subjectId != null && !subjectId.isBlank()) {
            return subjectId;
        }
        return SecurityContextStampSupport.resolveCurrentPrincipalId(request);
    }
}

