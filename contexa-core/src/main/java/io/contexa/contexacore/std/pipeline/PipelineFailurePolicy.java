package io.contexa.contexacore.std.pipeline;

import java.util.Locale;

public enum PipelineFailurePolicy {
    SYNTHETIC_FALLBACK_RESPONSE,
    PROPAGATE_ERROR;

    public boolean propagatesError() {
        return this == PROPAGATE_ERROR;
    }

    public static PipelineFailurePolicy fromValue(Object value, PipelineFailurePolicy fallback) {
        if (value == null) {
            return fallback;
        }
        if (value instanceof PipelineFailurePolicy policy) {
            return policy;
        }
        String normalized = String.valueOf(value).trim().toUpperCase(Locale.ROOT);
        for (PipelineFailurePolicy policy : values()) {
            if (policy.name().equals(normalized)) {
                return policy;
            }
        }
        return fallback;
    }
}
