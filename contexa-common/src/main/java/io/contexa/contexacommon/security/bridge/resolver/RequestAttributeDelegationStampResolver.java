package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import jakarta.servlet.http.HttpServletRequest;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;

public class RequestAttributeDelegationStampResolver implements DelegationStampResolver {

    @Override
    public Optional<DelegationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties) {
        BridgeProperties.RequestAttributes config = properties.getDelegation().getRequestAttributes();
        if (!config.isEnabled()) {
            return Optional.empty();
        }
        Object delegated = request.getAttribute(config.getDelegated());
        Object agentId = request.getAttribute(config.getAgentId());
        Object objectiveId = request.getAttribute(config.getObjectiveId());
        if (delegated == null && agentId == null && objectiveId == null) {
            return Optional.empty();
        }
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("delegationResolver", "REQUEST_ATTRIBUTE");
        return Optional.of(new DelegationStamp(
                request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : null,
                text(agentId),
                delegated instanceof Boolean booleanValue ? booleanValue : Boolean.parseBoolean(text(delegated)),
                text(objectiveId),
                text(request.getAttribute(config.getObjectiveSummary())),
                split(request.getAttribute(config.getAllowedOperations())),
                split(request.getAttribute(config.getAllowedResources())),
                parseBoolean(request.getAttribute(config.getApprovalRequired())),
                parseBoolean(request.getAttribute(config.getContainmentOnly())),
                null,
                attributes
        ));
    }

    private List<String> split(Object raw) {
        if (raw == null) {
            return List.of();
        }
        String text = raw.toString();
        if (text.isBlank()) {
            return List.of();
        }
        return List.of(text.split("\\s*,\\s*"));
    }

    private Boolean parseBoolean(Object raw) {
        if (raw instanceof Boolean booleanValue) {
            return booleanValue;
        }
        if (raw instanceof String text && !text.isBlank()) {
            return Boolean.parseBoolean(text);
        }
        return null;
    }

    private String text(Object raw) {
        return raw != null ? raw.toString() : null;
    }
}
