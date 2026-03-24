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

import java.time.Instant;
import java.util.*;

public class SecurityContextAuthenticationStampResolver implements AuthenticationStampResolver {

    @Override
    public Optional<AuthenticationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties) {
        if (properties != null && !properties.getAuthentication().isPreferSecurityContext()) {
            return Optional.empty();
        }
        BridgeProperties.Authentication.SecurityContext config = resolveConfig(properties);
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
        List<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>(SecurityContextStampSupport.mergeAttributes(
                authentication.getPrincipal(),
                authentication.getDetails(),
                config.getAttributeKeys()));
        attributes.put("securityContextAuthenticationClass", authentication.getClass().getSimpleName());

        Boolean mfaCompleted = SecurityContextStampSupport.extractBoolean(authentication, config.getMfaKeys());
        Instant authenticationTime = SecurityContextStampSupport.extractInstant(authentication, config.getAuthTimeKeys());
        String authenticationType = SecurityContextStampSupport.extractString(authentication, config.getAuthenticationTypeKeys());
        if (authenticationType == null) {
            authenticationType = authentication.getClass().getSimpleName();
        }
        String authenticationAssurance = SecurityContextStampSupport.extractString(authentication, config.getAuthenticationAssuranceKeys());
        if (authenticationAssurance == null) {
            authenticationAssurance = Boolean.TRUE.equals(mfaCompleted) ? "HIGH" : "STANDARD";
        }

        return Optional.of(new AuthenticationStamp(
                principalId,
                resolveDisplayName(authentication, config),
                resolvePrincipalType(authentication, config),
                true,
                authenticationType,
                "SECURITY_CONTEXT",
                authenticationAssurance,
                mfaCompleted,
                authenticationTime,
                requestContext.sessionId(),
                List.copyOf(new LinkedHashSet<>(authorities)),
                Map.copyOf(attributes)
        ));
    }

    private BridgeProperties.Authentication.SecurityContext resolveConfig(BridgeProperties properties) {
        if (properties == null || properties.getAuthentication() == null || properties.getAuthentication().getSecurityContext() == null) {
            return new BridgeProperties.Authentication.SecurityContext();
        }
        return properties.getAuthentication().getSecurityContext();
    }

    private String resolveDisplayName(Authentication authentication, BridgeProperties.Authentication.SecurityContext config) {
        String extracted = SecurityContextStampSupport.extractString(authentication, config.getDisplayNameKeys());
        if (extracted != null) {
            return extracted;
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof UserDetails userDetails) {
            return userDetails.getUsername();
        }
        String principalId = SecurityContextStampSupport.extractPrincipalId(authentication);
        return principalId != null ? principalId : authentication.getName();
    }

    private String resolvePrincipalType(Authentication authentication, BridgeProperties.Authentication.SecurityContext config) {
        String extracted = SecurityContextStampSupport.extractString(authentication, config.getPrincipalTypeKeys());
        if (extracted != null) {
            return extracted;
        }
        Object principal = authentication.getPrincipal();
        return principal != null ? principal.getClass().getSimpleName() : "AuthenticationPrincipal";
    }
}
