package io.contexa.contexacommon.security.bridge;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
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

        Optional<SessionBridgeSupport.ResolvedSessionAttribute> resolvedSessionAttribute = SessionBridgeSupport.resolveBest(
                session,
                properties.getAttribute(),
                properties.getAttributeCandidates(),
                properties.isAutoDiscover(),
                this::scoreAuthenticationCandidate
        );
        if (resolvedSessionAttribute.isEmpty()) {
            return null;
        }

        Object sessionUser = resolvedSessionAttribute.get().attributeValue();
        String principalId = BridgeObjectExtractor.extractString(sessionUser, properties.getPrincipalIdKeys());
        if (principalId == null || principalId.isBlank()) {
            return null;
        }

        String displayName = BridgeObjectExtractor.extractString(sessionUser, properties.getDisplayNameKeys());
        Set<String> authorities = BridgeObjectExtractor.extractStringSet(sessionUser, properties.getAuthoritiesKeys());
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>(BridgeObjectExtractor.extractAttributes(sessionUser, properties.getAttributeKeys()));
        attributes.put("bridgeAuthenticationSource", "SESSION");
        BridgeSemanticBoundaryPolicy.putStructuralSelectionMetadata(
                attributes,
                "bridgeSessionAttribute",
                resolvedSessionAttribute.get().attributeName(),
                resolvedSessionAttribute.get().score());

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
        attributes.put("authenticationAssuranceEvidenceState", BridgeSemanticBoundaryPolicy.explicitOrUnavailable(authenticationAssurance));
        attributes.put("mfaCompletedEvidenceState", BridgeSemanticBoundaryPolicy.explicitOrUnavailable(mfaCompleted));
        attributes.put("authenticationTimeEvidenceState", BridgeSemanticBoundaryPolicy.explicitOrUnavailable(authenticationTime));

        return new BridgedUser(principalId, displayName != null ? displayName : principalId, authorities, Map.copyOf(attributes));
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
}
