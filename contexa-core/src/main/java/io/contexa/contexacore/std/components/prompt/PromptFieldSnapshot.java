package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record PromptFieldSnapshot(
        String fieldKey,
        String sectionKey,
        String sectionTitle,
        String label,
        String valueHash,
        int valueLength,
        int lineNumber,
        String valuePreview,
        boolean compactedMarker,
        boolean truncatedMarker,
        String qualityRelevance,
        List<String> metricCodes,
        String remediationOwner,
        String requiredPolicy,
        String projectionPolicy) {

    public PromptFieldSnapshot {
        metricCodes = metricCodes == null ? List.of() : List.copyOf(metricCodes);
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("fieldKey", fieldKey);
        metadata.put("sectionKey", sectionKey);
        metadata.put("sectionTitle", sectionTitle);
        metadata.put("label", label);
        metadata.put("valueHash", valueHash);
        metadata.put("valueLength", valueLength);
        metadata.put("lineNumber", lineNumber);
        metadata.put("valuePreview", valuePreview);
        metadata.put("compactedMarker", compactedMarker);
        metadata.put("truncatedMarker", truncatedMarker);
        metadata.put("qualityRelevance", qualityRelevance);
        metadata.put("metricCodes", metricCodes);
        metadata.put("remediationOwner", remediationOwner);
        metadata.put("requiredPolicy", requiredPolicy);
        metadata.put("projectionPolicy", projectionPolicy);
        return metadata;
    }
}
