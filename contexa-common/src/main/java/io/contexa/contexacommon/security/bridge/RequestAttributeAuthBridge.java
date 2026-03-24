package io.contexa.contexacommon.security.bridge;

import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
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

        Optional<RequestAttributeBridgeSupport.ResolvedRequestAttribute> resolvedAttribute = RequestAttributeBridgeSupport.resolveBest(
                request,
                properties.getAttribute(),
                properties.getAttributeCandidates(),
                properties.isAutoDiscover(),
                this::scoreAuthenticationCandidate
        );
        if (resolvedAttribute.isPresent()) {
            Object authenticatedObject = resolvedAttribute.get().attributeValue();
            String principalId = BridgeObjectExtractor.extractString(authenticatedObject, properties.getPrincipalIdKeys());
            if (principalId != null && !principalId.isBlank()) {
                String displayName = BridgeObjectExtractor.extractString(authenticatedObject, properties.getDisplayNameKeys());
                Set<String> authorities = BridgeObjectExtractor.extractStringSet(authenticatedObject, properties.getAuthoritiesKeys());
                LinkedHashMap<String, Object> attributes = new LinkedHashMap<>(BridgeObjectExtractor.extractAttributes(authenticatedObject, properties.getAttributeKeys()));
                attributes.put("bridgeAuthenticationSource", "REQUEST_ATTRIBUTE");
                attributes.put("bridgeRequestAttribute", resolvedAttribute.get().attributeName());
                attributes.put("bridgeRequestDetectionScore", resolvedAttribute.get().score());

                String authenticationType = BridgeObjectExtractor.extractString(authenticatedObject, properties.getAuthenticationTypeKeys());
                if (authenticationType != null) {
                    attributes.put("authenticationType", authenticationType);
                }
                String authenticationAssurance = BridgeObjectExtractor.extractString(authenticatedObject, properties.getAuthenticationAssuranceKeys());
                if (authenticationAssurance != null) {
                    attributes.put("authenticationAssurance", authenticationAssurance);
                }
                Boolean mfaCompleted = BridgeObjectExtractor.extractBoolean(authenticatedObject, properties.getMfaKeys());
                if (mfaCompleted != null) {
                    attributes.put("mfaCompleted", mfaCompleted);
                }
                Instant authenticationTime = BridgeObjectExtractor.extractInstant(authenticatedObject, properties.getAuthTimeKeys());
                if (authenticationTime != null) {
                    attributes.put("authenticationTime", authenticationTime);
                }
                return new BridgedUser(principalId, displayName != null ? displayName : principalId, authorities, Map.copyOf(attributes));
            }
        }

        Object authenticated = request.getAttribute(properties.getFlatAuthenticated());
        if (authenticated != null && !Boolean.parseBoolean(authenticated.toString())) {
            return null;
        }
        Object principal = request.getAttribute(properties.getFlatPrincipalId());
        if (principal == null || principal.toString().isBlank()) {
            return null;
        }
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("bridgeAuthenticationSource", "REQUEST_ATTRIBUTE");
        putIfPresent(attributes, "authenticationType", request.getAttribute(properties.getFlatAuthenticationType()));
        putIfPresent(attributes, "authenticationAssurance", request.getAttribute(properties.getFlatAuthenticationAssurance()));
        putIfPresent(attributes, "mfaCompleted", request.getAttribute(properties.getFlatMfaCompleted()));
        putIfPresent(attributes, "authenticationTime", request.getAttribute(properties.getFlatAuthenticationTime()));
        return new BridgedUser(
                principal.toString(),
                toText(request.getAttribute(properties.getFlatDisplayName()), principal.toString()),
                splitValues(request.getAttribute(properties.getFlatAuthorities())),
                attributes
        );
    }

    private int scoreAuthenticationCandidate(Object candidate) {
        String principalId = BridgeObjectExtractor.extractString(candidate, properties.getPrincipalIdKeys());
        if (principalId == null || principalId.isBlank()) {
            return 0;
        }

        int score = 10;
        if (matchesConfiguredType(candidate)) {
            score += 8;
        }
        if (BridgeObjectExtractor.extractString(candidate, properties.getDisplayNameKeys()) != null) {
            score += 2;
        }
        if (!BridgeObjectExtractor.extractStringSet(candidate, properties.getAuthoritiesKeys()).isEmpty()) {
            score += 4;
        }
        if (BridgeObjectExtractor.extractString(candidate, properties.getAuthenticationTypeKeys()) != null) {
            score += 2;
        }
        if (BridgeObjectExtractor.extractString(candidate, properties.getAuthenticationAssuranceKeys()) != null) {
            score += 1;
        }
        if (BridgeObjectExtractor.extractBoolean(candidate, properties.getMfaKeys()) != null) {
            score += 1;
        }
        if (BridgeObjectExtractor.extractInstant(candidate, properties.getAuthTimeKeys()) != null) {
            score += 1;
        }
        if (!BridgeObjectExtractor.extractAttributes(candidate, properties.getAttributeKeys()).isEmpty()) {
            score += 1;
        }
        return score;
    }

    private boolean matchesConfiguredType(Object candidate) {
        String configuredType = properties.getObjectTypeName();
        if (configuredType == null || configuredType.isBlank() || candidate == null) {
            return false;
        }
        return configuredType.equals(candidate.getClass().getName()) || configuredType.equals(candidate.getClass().getSimpleName());
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
