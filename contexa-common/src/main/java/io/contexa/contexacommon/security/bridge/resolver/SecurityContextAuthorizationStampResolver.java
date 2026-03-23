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
import java.util.List;
import java.util.Optional;

public class SecurityContextAuthorizationStampResolver implements AuthorizationStampResolver {

    @Override
    public Optional<AuthorizationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || authentication instanceof AnonymousAuthenticationToken) {
            return Optional.empty();
        }
        List<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        List<String> roles = authorities.stream()
                .filter(value -> value.startsWith("ROLE_"))
                .toList();
        boolean privileged = authorities.stream().anyMatch(this::isPrivilegedAuthority);
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("authorizationResolver", "SECURITY_CONTEXT");
        return Optional.of(new AuthorizationStamp(
                authentication.getName(),
                requestContext.requestUri(),
                requestContext.method(),
                AuthorizationEffect.UNKNOWN,
                privileged,
                List.of(),
                null,
                null,
                "SECURITY_CONTEXT",
                Instant.now(),
                roles,
                authorities,
                attributes
        ));
    }

    private boolean isPrivilegedAuthority(String value) {
        String normalized = value != null ? value.toUpperCase() : "";
        return normalized.contains("ADMIN") || normalized.contains("ROOT") || normalized.contains("SUPER") || normalized.contains("PRIVILEGED");
    }
}
