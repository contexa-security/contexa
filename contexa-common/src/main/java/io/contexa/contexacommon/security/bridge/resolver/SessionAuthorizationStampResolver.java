package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeObjectExtractor;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeSemanticBoundaryPolicy;
import io.contexa.contexacommon.security.bridge.SessionBridgeSupport;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;

public class SessionAuthorizationStampResolver implements AuthorizationStampResolver {

    @Override
    public Optional<AuthorizationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties) {
        BridgeProperties.Authorization.Session config = resolveConfig(properties);
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
                candidate -> scoreAuthorizationCandidate(candidate, config)
        );
        if (resolvedSessionAttribute.isEmpty()) {
            return Optional.empty();
        }

        Object sessionAuthorization = resolvedSessionAttribute.get().attributeValue();
        AuthorizationEffect effect = AuthorizationEffect.from(BridgeObjectExtractor.extractString(sessionAuthorization, config.getAuthorizationEffectKeys()));
        LinkedHashSet<String> effectiveRoles = new LinkedHashSet<>(BridgeObjectExtractor.extractStringSet(sessionAuthorization, config.getRoleKeys()));
        LinkedHashSet<String> effectiveAuthorities = new LinkedHashSet<>(BridgeObjectExtractor.extractStringSet(sessionAuthorization, config.getAuthorityKeys()));
        if (effectiveAuthorities.isEmpty() && !effectiveRoles.isEmpty()) {
            effectiveAuthorities.addAll(effectiveRoles);
        }
        List<String> scopeTags = List.copyOf(new LinkedHashSet<>(BridgeObjectExtractor.extractStringSet(sessionAuthorization, config.getScopeTagKeys())));
        Boolean privileged = BridgeObjectExtractor.extractBoolean(sessionAuthorization, config.getPrivilegedKeys());
        String policyId = BridgeObjectExtractor.extractString(sessionAuthorization, config.getPolicyIdKeys());
        String policyVersion = BridgeObjectExtractor.extractString(sessionAuthorization, config.getPolicyVersionKeys());

        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>(BridgeObjectExtractor.extractAttributes(sessionAuthorization, config.getAttributeKeys()));
        attributes.put("authorizationResolver", "SESSION");
        BridgeSemanticBoundaryPolicy.putStructuralSelectionMetadata(
                attributes,
                "bridgeSessionAttribute",
                resolvedSessionAttribute.get().attributeName(),
                resolvedSessionAttribute.get().score());
        attributes.put("authorizationPrivilegedEvidenceState", BridgeSemanticBoundaryPolicy.explicitOrUnavailable(privileged));
        return Optional.of(new AuthorizationStamp(
                resolveSubjectId(request, sessionAuthorization, config),
                requestContext.requestUri(),
                requestContext.method(),
                effect,
                privileged,
                scopeTags,
                policyId,
                policyVersion,
                "SESSION",
                Instant.now(),
                List.copyOf(effectiveRoles),
                List.copyOf(effectiveAuthorities),
                attributes
        ));
    }

    private BridgeProperties.Authorization.Session resolveConfig(BridgeProperties properties) {
        if (properties == null || properties.getAuthorization() == null || properties.getAuthorization().getSession() == null) {
            return new BridgeProperties.Authorization.Session();
        }
        return properties.getAuthorization().getSession();
    }

    private int scoreAuthorizationCandidate(Object candidate, BridgeProperties.Authorization.Session config) {
        int score = 0;
        if (BridgeObjectExtractor.extractString(candidate, config.getAuthorizationEffectKeys()) != null) {
            score += 3;
        }
        if (!BridgeObjectExtractor.extractStringSet(candidate, config.getRoleKeys()).isEmpty()) {
            score += 4;
        }
        if (!BridgeObjectExtractor.extractStringSet(candidate, config.getAuthorityKeys()).isEmpty()) {
            score += 4;
        }
        if (!BridgeObjectExtractor.extractStringSet(candidate, config.getScopeTagKeys()).isEmpty()) {
            score += 2;
        }
        if (BridgeObjectExtractor.extractBoolean(candidate, config.getPrivilegedKeys()) != null) {
            score += 1;
        }
        if (BridgeObjectExtractor.extractString(candidate, config.getPolicyIdKeys()) != null) {
            score += 1;
        }
        if (BridgeObjectExtractor.extractString(candidate, config.getPolicyVersionKeys()) != null) {
            score += 1;
        }
        if (BridgeObjectExtractor.extractString(candidate, config.getPrincipalIdKeys()) != null) {
            score += 1;
        }
        return score;
    }

    private String resolveSubjectId(HttpServletRequest request, Object sessionAuthorization, BridgeProperties.Authorization.Session config) {
        String subjectId = BridgeObjectExtractor.extractString(sessionAuthorization, config.getPrincipalIdKeys());
        if (subjectId != null && !subjectId.isBlank()) {
            return subjectId;
        }
        return SecurityContextStampSupport.resolveCurrentPrincipalId(request);
    }
}
