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
        if (text.contains(",")) {
            for (String token : text.split("\\s*,\\s*")) {
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
            return Instant.ofEpochMilli(number.longValue());
        }
        if (raw instanceof String text && !text.isBlank()) {
            try {
                return Instant.parse(text.trim());
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
        if (source == null || preferredKeys == null || preferredKeys.isEmpty()) {
            return Map.of();
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
        return Map.copyOf(attributes);
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
