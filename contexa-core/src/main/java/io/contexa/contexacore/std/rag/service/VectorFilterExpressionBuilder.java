package io.contexa.contexacore.std.rag.service;

import java.util.Map;
import java.util.StringJoiner;
import java.util.regex.Pattern;

public final class VectorFilterExpressionBuilder {

    private static final Pattern SAFE_FILTER_KEY = Pattern.compile("[A-Za-z_][A-Za-z0-9_.-]*");

    private VectorFilterExpressionBuilder() {
    }

    public static String buildEqualityExpression(Map<String, Object> filters) {
        if (filters == null || filters.isEmpty()) {
            return null;
        }

        StringJoiner joiner = new StringJoiner(" && ");
        for (Map.Entry<String, Object> entry : filters.entrySet()) {
            String key = validateKey(entry.getKey());
            Object value = entry.getValue();
            if (value instanceof Number || value instanceof Boolean) {
                joiner.add(key + " == " + value);
            } else {
                joiner.add(key + " == '" + escapeLiteral(value) + "'");
            }
        }
        return joiner.toString();
    }

    private static String validateKey(String key) {
        if (key == null || !SAFE_FILTER_KEY.matcher(key).matches()) {
            throw new IllegalArgumentException("Unsafe vector filter key: " + key);
        }
        return key;
    }

    private static String escapeLiteral(Object value) {
        if (value == null) {
            return "";
        }
        return String.valueOf(value)
                .replace("\\", "\\\\")
                .replace("'", "\\'");
    }
}
