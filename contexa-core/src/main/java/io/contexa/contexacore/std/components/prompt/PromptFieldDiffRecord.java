package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record PromptFieldDiffRecord(
        String fieldKey,
        String sectionKey,
        String sectionTitle,
        String label,
        PromptFieldDiffType diffType,
        String rawValueHash,
        String finalValueHash,
        int rawLineNumber,
        int finalLineNumber,
        String reason,
        boolean blockingCandidate,
        String qualityRelevance,
        List<String> metricCodes,
        String remediationOwner,
        String requiredPolicy,
        String projectionPolicy) {

    public PromptFieldDiffRecord {
        metricCodes = metricCodes == null ? List.of() : List.copyOf(metricCodes);
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("fieldKey", fieldKey);
        metadata.put("sectionKey", sectionKey);
        metadata.put("sectionTitle", sectionTitle);
        metadata.put("label", label);
        metadata.put("diffType", diffType.name());
        metadata.put("rawValueHash", rawValueHash);
        metadata.put("finalValueHash", finalValueHash);
        metadata.put("rawLineNumber", rawLineNumber);
        metadata.put("finalLineNumber", finalLineNumber);
        metadata.put("reason", reason);
        metadata.put("blockingCandidate", blockingCandidate);
        metadata.put("qualityRelevance", qualityRelevance);
        metadata.put("metricCodes", metricCodes);
        metadata.put("remediationOwner", remediationOwner);
        metadata.put("requiredPolicy", requiredPolicy);
        metadata.put("projectionPolicy", projectionPolicy);
        return metadata;
    }
}
