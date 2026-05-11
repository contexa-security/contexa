package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.Map;

public record PromptFieldStateRecord(
        String fieldKey,
        String sourceType,
        String sourceFieldPath,
        String sourceClass,
        PromptFieldState fieldState,
        String valueType,
        String valueHash,
        int valueLength,
        String valuePreview,
        String requiredPolicy,
        String applicabilityRule,
        String applicabilityEvidence,
        String projectionPolicy,
        String promptPresenceState,
        String sealedEvidencePresenceState,
        String producerStatus,
        String absenceReasonCode,
        String absenceReasonText,
        String metricImpactPolicy,
        String blockingPolicy,
        String promptSection,
        String promptLabel) {

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("fieldKey", fieldKey);
        metadata.put("sourceType", sourceType);
        metadata.put("sourceFieldPath", sourceFieldPath);
        metadata.put("sourceClass", sourceClass);
        metadata.put("fieldState", fieldState.name());
        metadata.put("valueType", valueType);
        metadata.put("valueHash", valueHash);
        metadata.put("valueLength", valueLength);
        metadata.put("valuePreview", valuePreview);
        metadata.put("requiredPolicy", requiredPolicy);
        metadata.put("applicabilityRule", applicabilityRule);
        metadata.put("applicabilityEvidence", applicabilityEvidence);
        metadata.put("projectionPolicy", projectionPolicy);
        metadata.put("promptPresenceState", promptPresenceState);
        metadata.put("sealedEvidencePresenceState", sealedEvidencePresenceState);
        metadata.put("producerStatus", producerStatus);
        metadata.put("absenceReasonCode", absenceReasonCode);
        metadata.put("absenceReasonText", absenceReasonText);
        metadata.put("metricImpactPolicy", metricImpactPolicy);
        metadata.put("blockingPolicy", blockingPolicy);
        metadata.put("blockingCandidate", fieldState.blockingCandidate());
        metadata.put("promptSection", promptSection);
        metadata.put("promptLabel", promptLabel);
        return metadata;
    }
}
