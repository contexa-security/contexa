package io.contexa.contexacore.autonomous.context.support;

import org.springframework.util.StringUtils;

import java.util.*;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;

/**
 * Static utility for resolving typed values from heterogeneous metadata maps.
 * Extracted from DefaultCanonicalSecurityContextProvider to satisfy SRP.
 * All methods preserve original business logic without modification.
 */
public final class MetadataValueResolver {

    private MetadataValueResolver() {
    }

    public static String firstText(Object... values) {
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            String text = value.toString();
            if (!text.isBlank()) {
                return text;
            }
        }
        return null;
    }

    public static Long resolveLong(Object... values) {
        for (Object value : values) {
            if (value instanceof Number number) {
                return number.longValue();
            }
            if (value instanceof String stringValue && !stringValue.isBlank()) {
                try {
                    return Long.parseLong(stringValue.trim());
                } catch (NumberFormatException ignored) {
                    return null;
                }
            }
        }
        return null;
    }

    public static Boolean resolveBoolean(Object... values) {
        for (Object value : values) {
            if (value instanceof Boolean booleanValue) {
                return booleanValue;
            }
            if (value instanceof String stringValue && !stringValue.isBlank()) {
                return Boolean.parseBoolean(stringValue);
            }
        }
        return null;
    }

    public static Integer resolveInteger(Object... values) {
        for (Object value : values) {
            if (value instanceof Number number) {
                return number.intValue();
            }
            if (value instanceof String stringValue && !stringValue.isBlank()) {
                try {
                    return Integer.parseInt(stringValue.trim());
                } catch (NumberFormatException ignored) {
                    return null;
                }
            }
        }
        return null;
    }

    public static Double resolveDouble(Object... values) {
        for (Object value : values) {
            if (value instanceof Number number) {
                return number.doubleValue();
            }
            if (value instanceof String stringValue && !stringValue.isBlank()) {
                try {
                    return Double.parseDouble(stringValue.trim());
                } catch (NumberFormatException ignored) {
                    return null;
                }
            }
        }
        return null;
    }

    public static List<Integer> resolveIntegerList(Object... values) {
        Set<Integer> results = new LinkedHashSet<>();
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            if (value instanceof Collection<?> collection) {
                for (Object item : collection) {
                    addInteger(results, item);
                }
                continue;
            }
            String text = value.toString();
            if (text.contains(",")) {
                for (String token : text.split(",")) {
                    addInteger(results, token);
                }
                continue;
            }
            addInteger(results, text);
        }
        return List.copyOf(results);
    }

    public static List<String> normalizeStrings(Object... rawValues) {
        Set<String> values = new LinkedHashSet<>();
        for (Object rawValue : rawValues) {
            if (rawValue == null) {
                continue;
            }
            if (rawValue instanceof Collection<?> collection) {
                for (Object item : collection) {
                    addNormalizedScalar(values, item);
                }
                continue;
            }
            if (rawValue.getClass().isArray()) {
                int length = java.lang.reflect.Array.getLength(rawValue);
                for (int index = 0; index < length; index++) {
                    addNormalizedScalar(values, java.lang.reflect.Array.get(rawValue, index));
                }
                continue;
            }
            String text = rawValue.toString();
            addDelimitedOrScalar(values, text);
        }
        return List.copyOf(values);
    }

    public static boolean looksLikeBracketedCollection(String rawValue) {
        if (!StringUtils.hasText(rawValue)) {
            return false;
        }
        String value = rawValue.trim();
        return (value.startsWith("[") && value.endsWith("]"))
                || (value.startsWith("(") && value.endsWith(")"))
                || (value.startsWith("{") && value.endsWith("}"));
    }

    public static boolean isDelimitedTokenList(String rawValue) {
        if (!StringUtils.hasText(rawValue) || !rawValue.contains(",")) {
            return false;
        }
        String[] tokens = rawValue.split(",");
        if (tokens.length < 2) {
            return false;
        }
        for (String token : tokens) {
            String normalized = normalizeScalarToken(token);
            if (!StringUtils.hasText(normalized) || normalized.contains(" ")) {
                return false;
            }
        }
        return true;
    }

    public static boolean isWrapperChar(char value) {
        return value == '[' || value == ']' || value == '{' || value == '}'
                || value == '(' || value == ')' || value == '"' || value == '\'';
    }

    public static String normalizeScalarToken(String rawValue) {
        if (!StringUtils.hasText(rawValue)) {
            return null;
        }
        String extractedAuthority = extractAuthorityLiteral(rawValue);
        String value = extractedAuthority != null ? extractedAuthority.trim() : rawValue.trim();
        while (!value.isEmpty() && isWrapperChar(value.charAt(0))) {
            value = value.substring(1).trim();
        }
        while (!value.isEmpty() && isWrapperChar(value.charAt(value.length() - 1))) {
            value = value.substring(0, value.length() - 1).trim();
        }
        if (value.isBlank()
                || "null".equalsIgnoreCase(value)
                || value.startsWith("roleId=")
                || value.startsWith("permissionId=")
                || value.startsWith("targetType=")
                || value.startsWith("actionType=")) {
            return null;
        }
        return value;
    }

    public static String extractAuthorityLiteral(String rawValue) {
        java.util.regex.Matcher quotedMatcher = java.util.regex.Pattern.compile("authority='([^']+)'").matcher(rawValue);
        if (quotedMatcher.find()) {
            return quotedMatcher.group(1);
        }
        java.util.regex.Matcher plainMatcher = java.util.regex.Pattern.compile("authority=([^,}\\]]+)").matcher(rawValue);
        if (plainMatcher.find()) {
            return plainMatcher.group(1).trim();
        }
        return null;
    }

    public static void addNormalized(Set<String> values, Object rawValue) {
        if (rawValue == null) {
            return;
        }
        String text = rawValue.toString();
        String extractedAuthority = extractAuthorityLiteral(text);
        if (StringUtils.hasText(extractedAuthority)) {
            String normalized = normalizeScalarToken(extractedAuthority);
            if (StringUtils.hasText(normalized)) {
                values.add(normalized);
            }
            return;
        }
        String normalizedText = text.trim();
        addDelimitedOrScalar(values, normalizedText);
    }

    public static void addDelimitedOrScalar(Set<String> values, String rawValue) {
        if (!StringUtils.hasText(rawValue)) {
            return;
        }
        String normalizedText = rawValue.trim();
        boolean bracketedCollection = looksLikeBracketedCollection(normalizedText);
        if (bracketedCollection) {
            normalizedText = normalizedText.substring(1, normalizedText.length() - 1).trim();
        }
        if (normalizedText.contains(",") && (bracketedCollection || isDelimitedTokenList(normalizedText))) {
            for (String token : normalizedText.split(",")) {
                String normalized = normalizeScalarToken(token);
                if (StringUtils.hasText(normalized)) {
                    values.add(normalized);
                }
            }
            return;
        }
        String normalized = normalizeScalarToken(normalizedText);
        if (StringUtils.hasText(normalized)) {
            values.add(normalized);
        }
    }

    public static void addNormalizedScalar(Set<String> values, Object rawValue) {
        if (rawValue == null) {
            return;
        }
        String normalized = normalizeScalarToken(rawValue.toString());
        if (StringUtils.hasText(normalized)) {
            values.add(normalized);
        }
    }

    public static void addInteger(Set<Integer> results, Object rawValue) {
        Integer value = resolveInteger(rawValue);
        if (value != null) {
            results.add(value);
        }
    }
}
