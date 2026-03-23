package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import jakarta.servlet.http.HttpServletRequest;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;

public class HeaderDelegationStampResolver implements DelegationStampResolver {

    @Override
    public Optional<DelegationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties) {
        BridgeProperties.Headers config = properties.getDelegation().getHeaders();
        if (!config.isEnabled()) {
            return Optional.empty();
        }
        String delegated = request.getHeader(config.getDelegated());
        String agentId = request.getHeader(config.getAgentId());
        String objectiveId = request.getHeader(config.getObjectiveId());
        if (delegated == null && agentId == null && objectiveId == null) {
            return Optional.empty();
        }
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("delegationResolver", "HEADER");
        return Optional.of(new DelegationStamp(
                request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : null,
                agentId,
                Boolean.parseBoolean(delegated),
                objectiveId,
                request.getHeader(config.getObjectiveSummary()),
                split(request.getHeader(config.getAllowedOperations())),
                split(request.getHeader(config.getAllowedResources())),
                parseBoolean(request.getHeader(config.getApprovalRequired())),
                parseBoolean(request.getHeader(config.getContainmentOnly())),
                null,
                attributes
        ));
    }

    private List<String> split(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        return List.of(raw.split("\\s*,\\s*"));
    }

    private Boolean parseBoolean(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        return Boolean.parseBoolean(raw);
    }
}
