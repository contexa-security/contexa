package io.contexa.contexacommon.security.bridge;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.*;

public final class BridgeObjectExtractor {

    private BridgeObjectExtractor() {
    }

    public static String extractString(Object source, List<String> keys) {
        Object raw = extractRawValue(source, keys);
        if (raw == null) {
            return null;
        }
        String text = raw.toString().trim();
        return text.isBlank() ? null : text;
    }

    public static Set<String> extractStringSet(Object source, List<String> keys) {
        Object raw = extractRawValue(source, keys);
        if (raw == null) {
            return Set.of();
        }
        LinkedHashSet<String> values = new LinkedHashSet<>();
        if (raw instanceof Collection<?> collection) {
            for (Object item : collection) {
                addNormalized(values, item);
            }
            return Set.copyOf(values);
        }
        String text = raw.toString();
        if (containsDelimiter(text)) {
            for (String token : splitTextValues(text)) {
                addNormalized(values, token);
            }
            return Set.copyOf(values);
        }
        addNormalized(values, text);
        return Set.copyOf(values);
    }

    public static Instant extractInstant(Object source, List<String> keys) {
        Object raw = extractRawValue(source, keys);
        if (raw instanceof Instant instant) {
            return instant;
        }
        if (raw instanceof Number number) {
            return toInstant(number.longValue());
        }
        if (raw instanceof String text && !text.isBlank()) {
            String trimmed = text.trim();
            if (trimmed.chars().allMatch(Character::isDigit)) {
                try {
                    return toInstant(Long.parseLong(trimmed));
                }
                catch (NumberFormatException ignored) {
                    return null;
                }
            }
            try {
                return Instant.parse(trimmed);
            }
            catch (DateTimeParseException ignored) {
                return null;
            }
        }
        return null;
    }

    public static Boolean extractBoolean(Object source, List<String> keys) {
        Object raw = extractRawValue(source, keys);
        if (raw instanceof Boolean booleanValue) {
            return booleanValue;
        }
        if (raw instanceof Number number) {
            return number.intValue() != 0;
        }
        if (raw instanceof Collection<?> collection) {
            for (Object item : collection) {
                String normalized = item != null ? item.toString().trim().toLowerCase() : "";
                if (normalized.equals("mfa") || normalized.equals("otp") || normalized.equals("totp")
                        || normalized.equals("sms") || normalized.equals("webauthn") || normalized.equals("passkey")
                        || normalized.equals("biometric")) {
                    return true;
                }
            }
            return null;
        }
        if (raw instanceof String text && !text.isBlank()) {
            return Boolean.parseBoolean(text.trim());
        }
        return null;
    }

    public static Map<String, Object> extractAttributes(Object source, List<String> preferredKeys) {
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        if (source instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getKey() instanceof String key && entry.getValue() != null) {
                    attributes.put(key, entry.getValue());
                }
            }
            return Map.copyOf(attributes);
        }
        Map<String, Object> mappedSource = extractMappedSource(source);
        if (!mappedSource.isEmpty()) {
            attributes.putAll(mappedSource);
        }
        if (source == null || preferredKeys == null || preferredKeys.isEmpty()) {
            return attributes.isEmpty() ? Map.of() : Map.copyOf(attributes);
        }
        for (String key : preferredKeys) {
            if (key == null || key.isBlank()) {
                continue;
            }
            Object value = extractMemberValue(source, key);
            if (value != null) {
                attributes.put(key, value);
            }
        }
        return attributes.isEmpty() ? Map.of() : Map.copyOf(attributes);
    }

    public static Object extractRawValue(Object source, List<String> keys) {
        if (source == null || keys == null || keys.isEmpty()) {
            return null;
        }
        if (source instanceof Map<?, ?> map) {
            for (String key : keys) {
                Object value = map.get(key);
                if (value != null) {
                    return value;
                }
            }
            return null;
        }
        Map<String, Object> mappedSource = extractMappedSource(source);
        if (!mappedSource.isEmpty()) {
            for (String key : keys) {
                Object value = mappedSource.get(key);
                if (value != null) {
                    return value;
                }
            }
        }
        for (String key : keys) {
            if (key == null || key.isBlank()) {
                continue;
            }
            Object value = extractMemberValue(source, key);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private static Object extractMemberValue(Object source, String key) {
        Method accessor = findAccessor(source.getClass(), key);
        if (accessor != null) {
            try {
                return accessor.invoke(source);
            }
            catch (Exception ignored) {
            }
        }
        Field field = findField(source.getClass(), key);
        if (field != null) {
            try {
                return field.get(source);
            }
            catch (Exception ignored) {
            }
        }
        return null;
    }

    private static Method findAccessor(Class<?> type, String key) {
        for (String candidate : List.of(key, toGetterName(key), toBooleanGetterName(key))) {
            Method method = findPublicAccessor(type, candidate);
            if (method != null) {
                return method;
            }
            method = findDeclaredAccessor(type, candidate);
            if (method != null) {
                return method;
            }
        }
        return null;
    }

    private static Method findPublicAccessor(Class<?> type, String candidate) {
        try {
            return type.getMethod(candidate);
        }
        catch (NoSuchMethodException ignored) {
            return null;
        }
    }

    private static Method findDeclaredAccessor(Class<?> type, String candidate) {
        for (Class<?> current = type; current != null && current != Object.class; current = current.getSuperclass()) {
            try {
                Method method = current.getDeclaredMethod(candidate);
                method.setAccessible(true);
                return method;
            }
            catch (NoSuchMethodException ignored) {
            }
            catch (RuntimeException ignored) {
                return null;
            }
        }
        return null;
    }

    private static Field findField(Class<?> type, String key) {
        for (Class<?> current = type; current != null && current != Object.class; current = current.getSuperclass()) {
            try {
                Field field = current.getDeclaredField(key);
                field.setAccessible(true);
                return field;
            }
            catch (NoSuchFieldException ignored) {
            }
            catch (RuntimeException ignored) {
                return null;
            }
        }
        return null;
    }

    private static String toGetterName(String key) {
        if (key == null || key.isBlank()) {
            return "get";
        }
        return "get" + Character.toUpperCase(key.charAt(0)) + key.substring(1);
    }

    private static String toBooleanGetterName(String key) {
        if (key == null || key.isBlank()) {
            return "is";
        }
        return "is" + Character.toUpperCase(key.charAt(0)) + key.substring(1);
    }

    private static Map<String, Object> extractMappedSource(Object source) {
        if (source == null) {
            return Map.of();
        }
        for (String candidate : List.of("claims", "attributes", "tokenAttributes")) {
            Object mappedValue = extractMemberValue(source, candidate);
            if (mappedValue instanceof Map<?, ?> map) {
                LinkedHashMap<String, Object> normalized = new LinkedHashMap<>();
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (entry.getKey() instanceof String key && entry.getValue() != null) {
                        normalized.put(key, entry.getValue());
                    }
                }
                if (!normalized.isEmpty()) {
                    return Map.copyOf(normalized);
                }
            }
        }
        return Map.of();
    }

    private static boolean containsDelimiter(String text) {
        if (text == null) {
            return false;
        }
        return text.contains(",") || text.contains(" ");
    }

    private static List<String> splitTextValues(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        if (raw.contains(",")) {
            return List.of(raw.split("\\s*,\\s*"));
        }
        return List.of(raw.trim().split("\\s+"));
    }

    private static Instant toInstant(long numericValue) {
        if (Math.abs(numericValue) < 100000000000L) {
            return Instant.ofEpochSecond(numericValue);
        }
        return Instant.ofEpochMilli(numericValue);
    }

    private static void addNormalized(Set<String> values, Object raw) {
        if (raw == null) {
            return;
        }
        String value = raw.toString().trim();
        if (!value.isBlank()) {
            values.add(value);
        }
    }
}
