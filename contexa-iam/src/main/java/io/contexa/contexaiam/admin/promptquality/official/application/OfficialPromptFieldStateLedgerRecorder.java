package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class OfficialPromptFieldStateLedgerRecorder {

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private final ObjectMapper objectMapper;
    private final OfficialVerificationPromptFieldStateWriter writer;

    public OfficialPromptFieldStateLedgerRecorder(
            ObjectMapper objectMapper,
            OfficialVerificationPromptFieldStateWriter writer) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.writer = Objects.requireNonNull(writer, "writer");
    }

    public void record(String aggregateRunId, String packageId, SealedEvidencePackage evidencePackage) {
        if (!StringUtils.hasText(aggregateRunId) || evidencePackage == null) {
            return;
        }
        Object ledger = parse(evidencePackage.getPromptEvidenceManifestJson()).get("fieldStateLedger");
        if (ledger instanceof List<?> rows) {
            rows.stream().filter(Map.class::isInstance).map(Map.class::cast)
                    .forEach(row -> insert(aggregateRunId, packageId, row));
        }
        writer.insertMissingActiveDefinitions(fit(packageId, 128), fit(aggregateRunId, 256));
    }

    private void insert(String aggregateRunId, String packageId, Map<?, ?> row) {
        writer.insert(new OfficialVerificationPromptFieldStateWriter.Command(
                fit(packageId, 128), fit(aggregateRunId, 256), fit(text(row.get("fieldKey")), 512),
                fit(text(row.get("sourceType")), 128), fit(text(row.get("sourceFieldPath")), 1024),
                fit(text(row.get("sourceClass")), 512), fit(text(row.get("fieldState")), 64),
                fit(text(row.get("valueType")), 256), fit(text(row.get("valueHash")), 128),
                integer(row.get("valueLength")), text(row.get("valuePreview")),
                fit(text(row.get("requiredPolicy")), 128), fit(text(row.get("applicabilityRule")), 512),
                text(row.get("applicabilityEvidence")), fit(text(row.get("projectionPolicy")), 128),
                fit(text(row.get("promptPresenceState")), 128),
                fit(text(row.get("sealedEvidencePresenceState")), 128),
                fit(text(row.get("producerStatus")), 128), fit(text(row.get("absenceReasonCode")), 128),
                text(row.get("absenceReasonText")), fit(text(row.get("metricImpactPolicy")), 128),
                fit(text(row.get("blockingPolicy")), 128), flag(row.get("blockingCandidate")),
                fit(defaultText(row.get("qualityRelevance"), "AUDIT_ONLY_SEALED_SOURCE"), 64),
                flag(row.get("rawBlockingCandidate")), flag(row.get("officialBlockingCandidate"))));
    }

    private Map<String, Object> parse(String json) {
        if (!StringUtils.hasText(json)) {
            return Map.of();
        }
        try {
            Map<String, Object> value = objectMapper.readValue(json, MAP_TYPE);
            return value == null ? Map.of() : value;
        }
        catch (Exception ignored) {
            return Map.of();
        }
    }

    private Integer integer(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        try {
            return StringUtils.hasText(text(value)) ? Integer.parseInt(text(value)) : null;
        }
        catch (NumberFormatException ignored) {
            return null;
        }
    }

    private Boolean flag(Object value) {
        return value instanceof Boolean booleanValue ? booleanValue : Boolean.parseBoolean(text(value));
    }

    private String defaultText(Object value, String fallback) {
        String text = text(value);
        return StringUtils.hasText(text) ? text : fallback;
    }

    private String fit(String value, int maxLength) {
        return StringUtils.hasText(value) && value.length() > maxLength ? value.substring(0, maxLength) : value;
    }

    private String text(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }
}