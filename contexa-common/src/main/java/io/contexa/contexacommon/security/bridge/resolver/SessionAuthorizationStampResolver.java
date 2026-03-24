package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeObjectExtractor;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
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
        Object sessionAuthorization = session.getAttribute(config.getAttribute());
        if (sessionAuthorization == null) {
            return Optional.empty();
        }

        AuthorizationEffect effect = AuthorizationEffect.from(BridgeObjectExtractor.extractString(sessionAuthorization, config.getAuthorizationEffectKeys()));
        LinkedHashSet<String> effectiveRoles = new LinkedHashSet<>(BridgeObjectExtractor.extractStringSet(sessionAuthorization, config.getRoleKeys()));
        LinkedHashSet<String> effectiveAuthorities = new LinkedHashSet<>(BridgeObjectExtractor.extractStringSet(sessionAuthorization, config.getAuthorityKeys()));
        List<String> scopeTags = List.copyOf(new LinkedHashSet<>(BridgeObjectExtractor.extractStringSet(sessionAuthorization, config.getScopeTagKeys())));
        Boolean privileged = BridgeObjectExtractor.extractBoolean(sessionAuthorization, config.getPrivilegedKeys());
        String policyId = BridgeObjectExtractor.extractString(sessionAuthorization, config.getPolicyIdKeys());
        String policyVersion = BridgeObjectExtractor.extractString(sessionAuthorization, config.getPolicyVersionKeys());

        if (effect == AuthorizationEffect.UNKNOWN
                && effectiveRoles.isEmpty()
                && effectiveAuthorities.isEmpty()
                && scopeTags.isEmpty()
                && privileged == null
                && policyId == null
                && policyVersion == null) {
            return Optional.empty();
        }

        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>(BridgeObjectExtractor.extractAttributes(sessionAuthorization, config.getAttributeKeys()));
        attributes.put("authorizationResolver", "SESSION");
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

    private String resolveSubjectId(HttpServletRequest request, Object sessionAuthorization, BridgeProperties.Authorization.Session config) {
        String subjectId = BridgeObjectExtractor.extractString(sessionAuthorization, config.getPrincipalIdKeys());
        if (subjectId != null && !subjectId.isBlank()) {
            return subjectId;
        }
        return SecurityContextStampSupport.resolveCurrentPrincipalId(request);
    }
}

