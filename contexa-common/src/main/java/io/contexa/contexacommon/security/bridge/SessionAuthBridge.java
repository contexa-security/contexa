package io.contexa.contexacommon.security.bridge;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class SessionAuthBridge implements AuthBridge {

    private final BridgeProperties.Session properties;

    public SessionAuthBridge(BridgeProperties.Session properties) {
        this.properties = properties != null ? properties : new BridgeProperties.Session();
    }

    @Override
    public BridgedUser extractUser(HttpServletRequest request) {
        if (!properties.isEnabled()) {
            return null;
        }
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        Object sessionUser = session.getAttribute(properties.getAttribute());
        if (sessionUser == null) {
            return null;
        }
        String principalId = BridgeObjectExtractor.extractString(sessionUser, properties.getPrincipalIdKeys());
        if (principalId == null || principalId.isBlank()) {
            return null;
        }
        String displayName = BridgeObjectExtractor.extractString(sessionUser, properties.getDisplayNameKeys());
        Set<String> authorities = BridgeObjectExtractor.extractStringSet(sessionUser, properties.getAuthoritiesKeys());
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>(BridgeObjectExtractor.extractAttributes(sessionUser, properties.getAttributeKeys()));

        String authenticationType = BridgeObjectExtractor.extractString(sessionUser, properties.getAuthenticationTypeKeys());
        if (authenticationType != null) {
            attributes.put("authenticationType", authenticationType);
        }

        String authenticationAssurance = BridgeObjectExtractor.extractString(sessionUser, properties.getAuthenticationAssuranceKeys());
        if (authenticationAssurance != null) {
            attributes.put("authenticationAssurance", authenticationAssurance);
        }

        Boolean mfaCompleted = BridgeObjectExtractor.extractBoolean(sessionUser, properties.getMfaKeys());
        if (mfaCompleted != null) {
            attributes.put("mfaCompleted", mfaCompleted);
        }

        Instant authenticationTime = BridgeObjectExtractor.extractInstant(sessionUser, properties.getAuthTimeKeys());
        if (authenticationTime != null) {
            attributes.put("authenticationTime", authenticationTime);
        }

        return new BridgedUser(principalId, displayName != null ? displayName : principalId, authorities, Map.copyOf(attributes));
    }
}
