package io.contexa.contexacore.std.pipeline.step;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public record DecisionExecutionFailure(
        DecisionFailureCategory category,
        String message,
        String technicalFallbackAction
) {

    public DecisionExecutionFailure {
        category = Objects.requireNonNull(category, "category");
        message = message != null ? message : "";
        technicalFallbackAction = normalize(technicalFallbackAction);
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("decisionFailureCategory", category.name());
        metadata.put("decisionFailureMessage", message);
        if (technicalFallbackAction != null) {
            metadata.put("decisionFailureTechnicalFallbackAction", technicalFallbackAction);
        }
        return metadata;
    }

    private static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim();
        return normalized.isEmpty() ? null : normalized;
    }
}
