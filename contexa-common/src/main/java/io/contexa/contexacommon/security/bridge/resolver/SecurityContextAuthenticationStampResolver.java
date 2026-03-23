package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class SecurityContextAuthenticationStampResolver implements AuthenticationStampResolver {

    @Override
    public Optional<AuthenticationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties) {
        if (properties != null && !properties.getAuthentication().isPreferSecurityContext()) {
            return Optional.empty();
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || authentication instanceof AnonymousAuthenticationToken) {
            return Optional.empty();
        }
        List<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("securityContextAuthenticationClass", authentication.getClass().getSimpleName());
        return Optional.of(new AuthenticationStamp(
                authentication.getName(),
                resolveDisplayName(authentication),
                resolvePrincipalType(authentication),
                true,
                authentication.getClass().getSimpleName(),
                "SECURITY_CONTEXT",
                "STANDARD",
                null,
                null,
                requestContext.sessionId(),
                authorities,
                attributes
        ));
    }

    private String resolveDisplayName(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        if (principal instanceof UserDetails userDetails) {
            return userDetails.getUsername();
        }
        return authentication.getName();
    }

    private String resolvePrincipalType(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        return principal != null ? principal.getClass().getSimpleName() : "AuthenticationPrincipal";
    }
}
