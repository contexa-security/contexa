package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public record PromptDuplicationRecord(
        String dimension,
        String primarySectionKey,
        List<String> duplicateSectionKeys,
        String sourceOwner,
        String deduplicationRule
) {

    public PromptDuplicationRecord {
        dimension = requireText(dimension, "dimension");
        primarySectionKey = requireText(primarySectionKey, "primarySectionKey");
        duplicateSectionKeys = duplicateSectionKeys == null ? List.of() : List.copyOf(duplicateSectionKeys);
        sourceOwner = requireText(sourceOwner, "sourceOwner");
        deduplicationRule = requireText(deduplicationRule, "deduplicationRule");
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("dimension", dimension);
        metadata.put("primarySectionKey", primarySectionKey);
        metadata.put("duplicateSectionKeys", duplicateSectionKeys);
        metadata.put("sourceOwner", sourceOwner);
        metadata.put("deduplicationRule", deduplicationRule);
        return metadata;
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}
