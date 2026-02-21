package io.contexa.contexamcp.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collection;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class HighRiskToolAuthorizationService {

    private static final Set<String> NON_PRODUCTION_PROFILES = Set.of("dev", "local", "test");
    private static final String ENABLED_PROPERTY = "contexa.mcp.high-risk-tools.enabled";
    private static final String REQUIRED_ROLES_PROPERTY = "contexa.mcp.high-risk-tools.required-roles";
    private static final String REQUIRE_AUTH_PROPERTY = "contexa.mcp.high-risk-tools.require-authentication";
    private static final String ALLOWED_USERS_PROPERTY = "contexa.mcp.high-risk-tools.allowed-users";

    private final Environment environment;

    public boolean isAuthorized(String toolName) {
        boolean nonProduction = isNonProductionProfile();
        boolean enabled = environment.getProperty(ENABLED_PROPERTY, Boolean.class, nonProduction);

        if (!enabled) {
            log.error("High-risk tool disabled by environment. tool={}, property={}", toolName, ENABLED_PROPERTY);
            return false;
        }

        boolean requireAuthentication = environment.getProperty(REQUIRE_AUTH_PROPERTY, Boolean.class, !nonProduction);
        if (!requireAuthentication) {
            return true;
        }

        SecurityAuthentication auth = getAuthenticationFromSecurityContext();
        if (auth == null || !auth.authenticated()) {
            log.error("High-risk tool denied: authentication required. tool={}", toolName);
            return false;
        }

        Set<String> allowedUsers = parseCsvToUpperSet(environment.getProperty(ALLOWED_USERS_PROPERTY, ""));
        if (!allowedUsers.isEmpty() && auth.name() != null && allowedUsers.contains(auth.name().toUpperCase(Locale.ROOT))) {
            return true;
        }

        Set<String> requiredRoles = parseCsvToUpperSet(
                environment.getProperty(REQUIRED_ROLES_PROPERTY,
                        "ROLE_SECURITY_ADMIN,ROLE_SOC_ADMIN,ROLE_ADMIN"));

        if (requiredRoles.isEmpty()) {
            log.error("High-risk tool denied: required role set is empty. tool={}", toolName);
            return false;
        }

        Set<String> authoritySet = auth.authorities().stream()
                .map(role -> role.toUpperCase(Locale.ROOT))
                .collect(Collectors.toSet());

        boolean authorized = authoritySet.stream().anyMatch(requiredRoles::contains);
        if (!authorized) {
            log.error("High-risk tool denied: insufficient authority. tool={}, user={}, requiredRoles={}, authorities={}",
                    toolName, auth.name(), requiredRoles, authoritySet);
        }
        return authorized;
    }

    private boolean isNonProductionProfile() {
        String[] profiles = environment.getActiveProfiles();
        if (profiles == null || profiles.length == 0) {
            return false;
        }

        return Arrays.stream(profiles)
                .map(String::trim)
                .anyMatch(profile -> NON_PRODUCTION_PROFILES.contains(profile.toLowerCase(Locale.ROOT)));
    }

    private Set<String> parseCsvToUpperSet(String csv) {
        if (!StringUtils.hasText(csv)) {
            return Set.of();
        }

        return Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .map(value -> value.toUpperCase(Locale.ROOT))
                .collect(Collectors.toSet());
    }

    private SecurityAuthentication getAuthenticationFromSecurityContext() {
        try {
            Class<?> holderClass = Class.forName("org.springframework.security.core.context.SecurityContextHolder");
            Method getContext = holderClass.getMethod("getContext");
            Object context = getContext.invoke(null);
            if (context == null) {
                return null;
            }

            Method getAuthentication = context.getClass().getMethod("getAuthentication");
            Object authentication = getAuthentication.invoke(context);
            if (authentication == null) {
                return null;
            }

            Method isAuthenticatedMethod = authentication.getClass().getMethod("isAuthenticated");
            boolean authenticated = Boolean.TRUE.equals(isAuthenticatedMethod.invoke(authentication));

            Method getNameMethod = authentication.getClass().getMethod("getName");
            String name = (String) getNameMethod.invoke(authentication);

            Method getAuthoritiesMethod = authentication.getClass().getMethod("getAuthorities");
            Object authoritiesObject = getAuthoritiesMethod.invoke(authentication);

            Set<String> authorities = Set.of();
            if (authoritiesObject instanceof Collection<?> authorityCollection) {
                authorities = authorityCollection.stream()
                        .map(this::extractAuthority)
                        .filter(StringUtils::hasText)
                        .collect(Collectors.toSet());
            }

            return new SecurityAuthentication(authenticated, name, authorities);
        } catch (ClassNotFoundException e) {
            log.error("Spring SecurityContextHolder class not found. High-risk tool requires security context.");
            return null;
        } catch (Exception e) {
            log.error("Failed to resolve security authentication from context", e);
            return null;
        }
    }

    private String extractAuthority(Object authorityObject) {
        if (authorityObject == null) {
            return null;
        }

        try {
            Method getAuthority = authorityObject.getClass().getMethod("getAuthority");
            Object value = getAuthority.invoke(authorityObject);
            return value != null ? value.toString() : null;
        } catch (Exception ignored) {
            return authorityObject.toString();
        }
    }

    private record SecurityAuthentication(boolean authenticated, String name, Set<String> authorities) {
    }
}
