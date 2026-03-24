package io.contexa.contexacommon.security.bridge;

import jakarta.servlet.http.HttpServletRequest;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class RequestAttributeAuthBridge implements AuthBridge {

    private final BridgeProperties.RequestAttributes properties;

    public RequestAttributeAuthBridge(BridgeProperties.RequestAttributes properties) {
        this.properties = properties != null ? properties : new BridgeProperties.RequestAttributes();
    }

    @Override
    public BridgedUser extractUser(HttpServletRequest request) {
        if (!properties.isEnabled()) {
            return null;
        }
        Object authenticated = request.getAttribute(properties.getAuthenticated());
        if (authenticated != null && !Boolean.parseBoolean(authenticated.toString())) {
            return null;
        }
        Object principal = request.getAttribute(properties.getPrincipalId());
        if (principal == null || principal.toString().isBlank()) {
            return null;
        }
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("bridgeAuthenticationSource", "REQUEST_ATTRIBUTE");
        putIfPresent(attributes, "authenticationType", request.getAttribute(properties.getAuthenticationType()));
        putIfPresent(attributes, "authenticationAssurance", request.getAttribute(properties.getAuthenticationAssurance()));
        putIfPresent(attributes, "mfaCompleted", request.getAttribute(properties.getMfaCompleted()));
        putIfPresent(attributes, "authenticationTime", request.getAttribute(properties.getAuthenticationTime()));
        return new BridgedUser(
                principal.toString(),
                toText(request.getAttribute(properties.getDisplayName()), principal.toString()),
                splitValues(request.getAttribute(properties.getAuthorities())),
                attributes
        );
    }

    private void putIfPresent(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }

    private String toText(Object value, String fallback) {
        if (value == null || value.toString().isBlank()) {
            return fallback;
        }
        return value.toString();
    }

    private Set<String> splitValues(Object raw) {
        if (raw == null) {
            return Set.of();
        }
        String text = raw.toString();
        if (text.isBlank()) {
            return Set.of();
        }
        return Set.of(text.split("\\s*,\\s*"));
    }
}
