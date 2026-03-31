package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public record PromptCompressionRecord(
        String scopeKey,
        PromptCompressionAction action,
        int rawCharacterCount,
        int compactCharacterCount,
        int savedEstimatedTokens,
        String reason) {

    public PromptCompressionRecord {
        scopeKey = requireText(scopeKey, "scopeKey");
        action = Objects.requireNonNull(action, "action");
        reason = requireText(reason, "reason");
        if (rawCharacterCount < 0 || compactCharacterCount < 0 || savedEstimatedTokens < 0) {
            throw new IllegalArgumentException("Compression counts must not be negative");
        }
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("scopeKey", scopeKey);
        metadata.put("action", action.name());
        metadata.put("rawCharacterCount", rawCharacterCount);
        metadata.put("compactCharacterCount", compactCharacterCount);
        metadata.put("savedEstimatedTokens", savedEstimatedTokens);
        metadata.put("reason", reason);
        return metadata;
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}