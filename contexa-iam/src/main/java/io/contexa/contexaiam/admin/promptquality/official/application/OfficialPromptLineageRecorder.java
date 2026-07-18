package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.Objects;

public final class OfficialPromptLineageRecorder {

    private final OfficialVerificationPromptLineageWriter writer;
    private final OfficialPromptExecutionMetadataReader metadataReader;

    public OfficialPromptLineageRecorder(
            OfficialVerificationPromptLineageWriter writer,
            OfficialPromptExecutionMetadataReader metadataReader) {
        this.writer = Objects.requireNonNull(writer, "writer");
        this.metadataReader = Objects.requireNonNull(metadataReader, "metadataReader");
    }

    public void record(
            String aggregateRunId,
            String packageId,
            SealedEvidencePackage evidencePackage,
            String promptHash,
            String contextHash) {
        if (!StringUtils.hasText(aggregateRunId) || evidencePackage == null) {
            return;
        }
        Map<String, Object> metadata = metadataReader.read(evidencePackage.getPromptExecutionMetadataJson());
        Boolean compressionApplied = booleanValue(metadata.get("compressionApplied"));
        Boolean rawTruthParity = effectiveRawTruthParity(evidencePackage, metadata);
        String transformationMode = firstNonBlank(
                text(metadata.get("promptViewTransformationMode")), text(metadata.get("transformationMode")));
        if (Boolean.TRUE.equals(rawTruthParity)
                && !Boolean.TRUE.equals(compressionApplied)
                && !StringUtils.hasText(transformationMode)) {
            transformationMode = "NONE";
        }
        writer.insert(command(
                aggregateRunId, packageId, evidencePackage, promptHash, contextHash,
                metadata, compressionApplied, rawTruthParity, transformationMode));
    }

    private OfficialVerificationPromptLineageWriter.Command command(
            String aggregateRunId,
            String packageId,
            SealedEvidencePackage evidencePackage,
            String promptHash,
            String contextHash,
            Map<String, Object> metadata,
            Boolean compressionApplied,
            Boolean rawTruthParity,
            String transformationMode) {
        return new OfficialVerificationPromptLineageWriter.Command(
                fit(packageId, 128), fit(aggregateRunId, 256),
                fit(firstNonBlank(promptHash, evidencePackage.getPromptHash(), text(metadata.get("promptHash"))), 160),
                fit(contextHash, 160),
                fit(firstNonBlank(evidencePackage.getSystemPromptHash(), text(metadata.get("systemPromptHash"))), 160),
                fit(firstNonBlank(evidencePackage.getUserPromptHash(), text(metadata.get("userPromptHash"))), 160),
                fit(text(metadata.get("rawPromptHash")), 160),
                fit(firstNonBlank(evidencePackage.getRawSystemPromptHash(), text(metadata.get("rawSystemPromptHash"))), 160),
                fit(firstNonBlank(evidencePackage.getRawUserPromptHash(), text(metadata.get("rawUserPromptHash"))), 160),
                fit(firstNonBlank(text(metadata.get("defaultBudgetProfile")),
                        text(metadata.get("promptBudgetProfile")), text(metadata.get("budgetProfile"))), 128),
                compressionApplied, fit(transformationMode, 128), rawTruthParity,
                integer(metadata.get("promptRawUserFieldCount")), integer(metadata.get("promptFinalUserFieldCount")),
                integer(metadata.get("promptUserFieldDiffCount")), integer(metadata.get("promptUserFieldLossCount")),
                integer(metadata.get("promptUserFieldChangedCount")), integer(metadata.get("promptUserFieldAddedCount")),
                integer(metadata.get("promptUserFieldCompactedMarkerCount")),
                integer(metadata.get("promptUserFieldTruncatedMarkerCount")),
                metadataReader.writeJson(metadata.get("promptUserFieldLineageSummary")));
    }

    private Boolean effectiveRawTruthParity(SealedEvidencePackage evidencePackage, Map<String, Object> metadata) {
        Boolean declared = nullableBoolean(metadata.get("promptRawTruthParity"));
        boolean sameSystem = normalized(evidencePackage.getRawSystemPrompt()).equals(normalized(evidencePackage.getSystemPromptText()));
        boolean sameUser = normalized(evidencePackage.getRawUserPrompt()).equals(normalized(evidencePackage.getUserPromptText()));
        return sameSystem && sameUser ? true : declared;
    }

    private String normalized(String value) {
        return value == null ? "" : value.replace("\r\n", "\n").replace('\r', '\n').stripTrailing();
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

    private Boolean booleanValue(Object value) {
        return value instanceof Boolean flag ? flag : Boolean.parseBoolean(text(value));
    }

    private Boolean nullableBoolean(Object value) {
        return value == null ? null : booleanValue(value);
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }

    private String fit(String value, int maxLength) {
        return StringUtils.hasText(value) && value.length() > maxLength ? value.substring(0, maxLength) : value;
    }

    private String text(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }
}