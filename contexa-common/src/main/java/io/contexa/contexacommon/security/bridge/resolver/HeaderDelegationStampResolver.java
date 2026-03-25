package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.time.format.DateTimeParseException;
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
        String objectiveFamily = request.getHeader(config.getObjectiveFamily());
        String expiresAt = request.getHeader(config.getExpiresAt());
        if (delegated == null && agentId == null && objectiveId == null && objectiveFamily == null && expiresAt == null) {
            return Optional.empty();
        }
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("delegationResolver", "HEADER");
        return Optional.of(new DelegationStamp(
                SecurityContextStampSupport.resolveSubjectIdFromHeaders(request, properties),
                agentId,
                Boolean.parseBoolean(delegated),
                objectiveId,
                objectiveFamily,
                request.getHeader(config.getObjectiveSummary()),
                split(request.getHeader(config.getAllowedOperations())),
                split(request.getHeader(config.getAllowedResources())),
                parseBoolean(request.getHeader(config.getApprovalRequired())),
                parseBoolean(request.getHeader(config.getPrivilegedExportAllowed())),
                parseBoolean(request.getHeader(config.getContainmentOnly())),
                parseInstant(expiresAt),
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

    private Instant parseInstant(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(raw.trim());
        }
        catch (DateTimeParseException ignored) {
            return null;
        }
    }
}
