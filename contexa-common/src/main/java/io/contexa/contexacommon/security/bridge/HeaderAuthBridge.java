package io.contexa.contexacommon.security.bridge;

import jakarta.servlet.http.HttpServletRequest;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class HeaderAuthBridge implements AuthBridge {

    private final BridgeProperties.Headers properties;

    public HeaderAuthBridge(BridgeProperties.Headers properties) {
        this.properties = properties != null ? properties : new BridgeProperties.Headers();
    }

    @Override
    public BridgedUser extractUser(HttpServletRequest request) {
        if (!properties.isEnabled()) {
            return null;
        }
        String authenticated = request.getHeader(properties.getAuthenticated());
        if (authenticated != null && !authenticated.isBlank() && !Boolean.parseBoolean(authenticated)) {
            return null;
        }
        String principalId = request.getHeader(properties.getPrincipalId());
        if (principalId == null || principalId.isBlank()) {
            return null;
        }
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        putIfPresent(attributes, "authenticationType", request.getHeader(properties.getAuthenticationType()));
        putIfPresent(attributes, "authenticationAssurance", request.getHeader(properties.getAuthenticationAssurance()));
        putIfPresent(attributes, "mfaCompleted", request.getHeader(properties.getMfaCompleted()));
        putIfPresent(attributes, "authenticationTime", request.getHeader(properties.getAuthenticationTime()));
        return new BridgedUser(
                principalId,
                textOrFallback(request.getHeader(properties.getDisplayName()), principalId),
                splitValues(request.getHeader(properties.getAuthorities())),
                attributes
        );
    }

    private void putIfPresent(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }

    private String textOrFallback(String value, String fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return value;
    }

    private Set<String> splitValues(String raw) {
        if (raw == null || raw.isBlank()) {
            return Set.of();
        }
        return Set.of(raw.split("\\s*,\\s*"));
    }
}
