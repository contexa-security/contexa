package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;

public class SecurityContextAuthorizationStampResolver implements AuthorizationStampResolver {

    @Override
    public Optional<AuthorizationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties) {
        BridgeProperties.Authorization.SecurityContext config = resolveConfig(properties);
        if (!config.isEnabled()) {
            return Optional.empty();
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || authentication instanceof AnonymousAuthenticationToken) {
            return Optional.empty();
        }
        String principalId = SecurityContextStampSupport.extractPrincipalId(authentication);
        if (principalId == null) {
            return Optional.empty();
        }
        List<String> authenticationAuthorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        LinkedHashSet<String> roles = new LinkedHashSet<>();
        for (String resolvedRole : SecurityContextStampSupport.extractStringList(authentication, config.getRoleKeys())) {
            String normalizedRole = normalizeRole(resolvedRole);
            if (normalizedRole != null) {
                roles.add(normalizedRole);
            }
        }
        authenticationAuthorities.stream()
                .filter(value -> value.startsWith("ROLE_"))
                .forEach(roles::add);

        LinkedHashSet<String> effectiveAuthorities = new LinkedHashSet<>();
        effectiveAuthorities.addAll(SecurityContextStampSupport.extractStringList(authentication, config.getAuthorityKeys()));
        effectiveAuthorities.addAll(authenticationAuthorities);

        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>(SecurityContextStampSupport.mergeAttributes(
                authentication.getDetails(),
                authentication.getPrincipal(),
                config.getAttributeKeys()));
        attributes.put("authorizationResolver", "SECURITY_CONTEXT");

        Boolean privileged = SecurityContextStampSupport.extractBoolean(authentication, config.getPrivilegedKeys());
        if (privileged == null) {
            privileged = effectiveAuthorities.stream().anyMatch(this::isPrivilegedAuthority)
                    || roles.stream().anyMatch(this::isPrivilegedAuthority);
        }

        return Optional.of(new AuthorizationStamp(
                principalId,
                requestContext.requestUri(),
                requestContext.method(),
                resolveEffect(authentication, config),
                privileged,
                SecurityContextStampSupport.extractStringList(authentication, config.getScopeTagKeys()),
                SecurityContextStampSupport.extractString(authentication, config.getPolicyIdKeys()),
                SecurityContextStampSupport.extractString(authentication, config.getPolicyVersionKeys()),
                "SECURITY_CONTEXT",
                Instant.now(),
                List.copyOf(roles),
                List.copyOf(effectiveAuthorities),
                attributes
        ));
    }

    private BridgeProperties.Authorization.SecurityContext resolveConfig(BridgeProperties properties) {
        if (properties == null || properties.getAuthorization() == null || properties.getAuthorization().getSecurityContext() == null) {
            return new BridgeProperties.Authorization.SecurityContext();
        }
        return properties.getAuthorization().getSecurityContext();
    }

    private AuthorizationEffect resolveEffect(Authentication authentication, BridgeProperties.Authorization.SecurityContext config) {
        String value = SecurityContextStampSupport.extractString(authentication, config.getAuthorizationEffectKeys());
        if (value == null) {
            return AuthorizationEffect.UNKNOWN;
        }
        try {
            return AuthorizationEffect.valueOf(value.trim().toUpperCase());
        }
        catch (IllegalArgumentException ignored) {
            return AuthorizationEffect.UNKNOWN;
        }
    }

    private String normalizeRole(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        if (value.startsWith("ROLE_")) {
            return value;
        }
        return "ROLE_" + value;
    }

    private boolean isPrivilegedAuthority(String value) {
        String normalized = value != null ? value.toUpperCase() : "";
        return normalized.contains("ADMIN") || normalized.contains("ROOT") || normalized.contains("SUPER") || normalized.contains("PRIVILEGED");
    }
}
