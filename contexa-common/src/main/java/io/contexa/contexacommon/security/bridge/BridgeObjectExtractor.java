package io.contexa.contexacommon.security.bridge;

import java.lang.reflect.Method;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.*;

final class BridgeObjectExtractor {

    private BridgeObjectExtractor() {
    }

    static String extractString(Object source, List<String> keys) {
        Object raw = extractRawValue(source, keys);
        if (raw == null) {
            return null;
        }
        String text = raw.toString().trim();
        return text.isBlank() ? null : text;
    }

    static Set<String> extractStringSet(Object source, List<String> keys) {
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
            for (String token : text.split(",")) {
                addNormalized(values, token);
            }
            return Set.copyOf(values);
        }
        addNormalized(values, text);
        return Set.copyOf(values);
    }

    static Instant extractInstant(Object source, List<String> keys) {
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
            } catch (DateTimeParseException ignored) {
                return null;
            }
        }
        return null;
    }

    static Boolean extractBoolean(Object source, List<String> keys) {
        Object raw = extractRawValue(source, keys);
        if (raw instanceof Boolean booleanValue) {
            return booleanValue;
        }
        if (raw instanceof String text && !text.isBlank()) {
            return Boolean.parseBoolean(text.trim());
        }
        return null;
    }

    static Map<String, Object> extractAttributes(Object source, List<String> preferredKeys) {
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        if (source instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getKey() instanceof String key && entry.getValue() != null) {
                    attributes.put(key, entry.getValue());
                }
            }
            return Map.copyOf(attributes);
        }
        if (source == null || preferredKeys == null) {
            return Map.of();
        }
        Class<?> type = source.getClass();
        for (String key : preferredKeys) {
            try {
                Method method = findAccessor(type, key);
                if (method == null) {
                    continue;
                }
                Object value = method.invoke(source);
                if (value != null) {
                    attributes.put(key, value);
                }
            } catch (Exception ignored) {
                return Map.copyOf(attributes);
            }
        }
        return Map.copyOf(attributes);
    }

    private static Object extractRawValue(Object source, List<String> keys) {
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
        Class<?> type = source.getClass();
        for (String key : keys) {
            try {
                Method method = findAccessor(type, key);
                if (method == null) {
                    continue;
                }
                Object value = method.invoke(source);
                if (value != null) {
                    return value;
                }
            } catch (Exception ignored) {
                return null;
            }
        }
        return null;
    }

    private static Method findAccessor(Class<?> type, String key) {
        try {
            return type.getMethod(toGetterName(key));
        } catch (NoSuchMethodException ignored) {
        }
        try {
            return type.getMethod(toBooleanGetterName(key));
        } catch (NoSuchMethodException ignored) {
            return null;
        }
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
