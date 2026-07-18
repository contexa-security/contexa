package io.contexa.contexacore.verification.runtime;

import java.util.Locale;
import java.util.Objects;

/** Explicit, audited fault scenario accepted only from an authorized admin adapter. */
public record VerificationFaultScenario(Type type, String source, String operatorId) {

    public VerificationFaultScenario {
        type = Objects.requireNonNull(type, "type must not be null");
        source = requireText("source", source);
        operatorId = requireText("operatorId", operatorId);
    }

    public static VerificationFaultScenario of(String value, String source, String operatorId) {
        return new VerificationFaultScenario(
                Type.valueOf(requireText("value", value).toUpperCase(Locale.ROOT)),
                source,
                operatorId);
    }

    private static String requireText(String field, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value.trim();
    }

    public enum Type {
        RAG_SCOPE_SLOT_FAULT,
        RUNTIME_SLOT_MULTI_FAULT
    }
}