package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public record PromptOmissionRecord(
        String sectionKey,
        PromptOmissionType omissionType,
        int omittedItemCount,
        int omittedEstimatedTokens,
        String reason,
        PromptSemanticRisk semanticRisk) {

    public PromptOmissionRecord {
        sectionKey = requireText(sectionKey, "sectionKey");
        omissionType = Objects.requireNonNull(omissionType, "omissionType");
        semanticRisk = Objects.requireNonNull(semanticRisk, "semanticRisk");
        reason = requireText(reason, "reason");
        if (omittedItemCount < 0 || omittedEstimatedTokens < 0) {
            throw new IllegalArgumentException("Omission counts must not be negative");
        }
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("sectionKey", sectionKey);
        metadata.put("omissionType", omissionType.name());
        metadata.put("omittedItemCount", omittedItemCount);
        metadata.put("omittedEstimatedTokens", omittedEstimatedTokens);
        metadata.put("reason", reason);
        metadata.put("semanticRisk", semanticRisk.name());
        return metadata;
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}
