package io.contexa.contexacore.autonomous.context.support;

import org.springframework.util.StringUtils;

import java.util.*;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;

/**
 * Static utility for normalizing identity tokens (roles, authorities, permissions).
 * Extracted from DefaultCanonicalSecurityContextProvider to satisfy SRP.
 * All methods preserve original business logic without modification.
 */
public final class IdentityTokenNormalizer {

    private IdentityTokenNormalizer() {
    }

    public static List<String> normalizeRoleStrings(Object... rawValues) {
        Set<String> values = new LinkedHashSet<>();
        for (String rawValue : flattenTokens(rawValues)) {
            String normalizedRole = normalizeRoleToken(rawValue);
            if (normalizedRole != null) {
                values.add(normalizedRole);
            }
        }
        return List.copyOf(values);
    }

    public static List<String> normalizeAuthorityStrings(Object... rawValues) {
        Set<String> values = new LinkedHashSet<>();
        for (String rawValue : flattenTokens(rawValues)) {
            if (isAuthorityLikeToken(rawValue)) {
                values.add(MetadataValueResolver.normalizeScalarToken(rawValue));
            }
        }
        return List.copyOf(values);
    }

    public static List<String> normalizePermissionStrings(Object... rawValues) {
        Set<String> values = new LinkedHashSet<>();
        for (String rawValue : flattenTokens(rawValues)) {
            if (isPermissionLikeToken(rawValue)) {
                values.add(MetadataValueResolver.normalizeScalarToken(rawValue));
            }
        }
        return List.copyOf(values);
    }

    public static List<String> flattenTokens(Object... rawValues) {
        LinkedHashSet<String> values = new LinkedHashSet<>();
        for (Object rawValue : rawValues) {
            if (rawValue == null) {
                continue;
            }
            if (rawValue instanceof Collection<?> collection) {
                for (Object item : collection) {
                    addFlattenedToken(values, item);
                }
                continue;
            }
            if (rawValue.getClass().isArray()) {
                int length = java.lang.reflect.Array.getLength(rawValue);
                for (int index = 0; index < length; index++) {
                    addFlattenedToken(values, java.lang.reflect.Array.get(rawValue, index));
                }
                continue;
            }
            addFlattenedToken(values, rawValue);
        }
        return List.copyOf(values);
    }

    public static void addFlattenedToken(Set<String> values, Object rawValue) {
        if (rawValue == null) {
            return;
        }
        String text = rawValue.toString().trim();
        if (!StringUtils.hasText(text)) {
            return;
        }
        if (MetadataValueResolver.looksLikeBracketedCollection(text)) {
            text = text.substring(1, text.length() - 1).trim();
        }
        if (text.contains(",")) {
            for (String token : text.split(",")) {
                String normalized = token.trim();
                if (StringUtils.hasText(normalized)) {
                    values.add(normalized);
                }
            }
            return;
        }
        values.add(text);
    }

    public static String normalizeRoleToken(String rawValue) {
        if (!StringUtils.hasText(rawValue)) {
            return null;
        }
        if (rawValue.contains("PermissionAuthority{")) {
            return null;
        }
        String candidate = MetadataValueResolver.normalizeScalarToken(rawValue);
        if (!StringUtils.hasText(candidate)) {
            return null;
        }
        if (candidate.startsWith("ROLE_")) {
            candidate = candidate.substring("ROLE_".length());
        }
        if (candidate.isBlank()
                || candidate.contains("/")
                || candidate.contains(".")
                || candidate.contains(":")
                || candidate.contains("=")
                || candidate.contains(" ")) {
            return null;
        }
        String upper = candidate.toUpperCase(Locale.ROOT);
        if ("READ".equals(upper)
                || "WRITE".equals(upper)
                || "EXPORT".equals(upper)
                || "DELETE".equals(upper)
                || "CREATE".equals(upper)
                || "UPDATE".equals(upper)
                || "GET".equals(upper)
                || "POST".equals(upper)
                || "PUT".equals(upper)
                || "PATCH".equals(upper)) {
            return null;
        }
        return upper;
    }

    public static boolean isAuthorityLikeToken(String rawValue) {
        String candidate = MetadataValueResolver.normalizeScalarToken(rawValue);
        if (!StringUtils.hasText(candidate)) {
            return false;
        }
        if (candidate.startsWith("/")
                || candidate.contains("=")
                || candidate.contains(" ")) {
            return false;
        }
        return normalizeRoleToken(rawValue) == null;
    }

    public static boolean isPermissionLikeToken(String rawValue) {
        String candidate = MetadataValueResolver.normalizeScalarToken(rawValue);
        if (!StringUtils.hasText(candidate)) {
            return false;
        }
        if (!isAuthorityLikeToken(rawValue)) {
            return false;
        }
        return !candidate.startsWith("/")
                && !candidate.contains("=")
                && !candidate.contains(" ");
    }
}
