package io.contexa.contexacore.std.pipeline.step;

import java.util.Locale;

public enum StructuredOutputPolicy {
    ALLOW_RAW_FALLBACK,
    RAW_FORBIDDEN;

    public boolean allowsRawFallback() {
        return this == ALLOW_RAW_FALLBACK;
    }

    public static StructuredOutputPolicy fromValue(Object value, StructuredOutputPolicy fallback) {
        if (value == null) {
            return fallback;
        }
        String normalized = value.toString().trim().toUpperCase(Locale.ROOT);
        for (StructuredOutputPolicy policy : values()) {
            if (policy.name().equals(normalized)) {
                return policy;
            }
        }
        return fallback;
    }
}
