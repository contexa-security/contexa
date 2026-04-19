package io.contexa.contexacore.std.llm.client;

import java.util.Locale;

public enum StructuredOutputMode {
    NATIVE_STRUCTURED,
    VALIDATED_CONVERTER,
    RAW_FORBIDDEN,
    LEGACY_RAW;

    public static StructuredOutputMode fromValue(Object value, StructuredOutputMode fallback) {
        if (value == null) {
            return fallback;
        }
        if (value instanceof StructuredOutputMode mode) {
            return mode;
        }
        String text = String.valueOf(value).trim();
        if (text.isEmpty()) {
            return fallback;
        }
        try {
            return StructuredOutputMode.valueOf(text.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ignored) {
            return fallback;
        }
    }
}
