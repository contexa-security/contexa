package io.contexa.contexacore.std.components.prompt;

import java.util.ArrayList;
import java.util.List;

public final class PromptFieldStateLedgerFactory {

    private static final int PREVIEW_LIMIT = 240;

    private PromptFieldStateLedgerFactory() {
    }

    public static PromptFieldStateLedger create(
            PromptSourceContextSnapshot sourceSnapshot,
            PromptFieldLineageAnalysis fieldLineage) {
        List<PromptFieldStateRecord> records = new ArrayList<>();
        int sourceCount = 0;
        int rawCount = 0;
        int finalCount = 0;
        int diffCount = 0;

        if (sourceSnapshot != null && sourceSnapshot.fields() != null) {
            sourceCount = sourceSnapshot.fields().size();
            for (PromptSourceContextFieldSnapshot field : sourceSnapshot.fields()) {
                records.add(sourceRecord(field));
            }
        }

        if (fieldLineage != null) {
            if (fieldLineage.rawUserFields() != null) {
                rawCount = fieldLineage.rawUserFields().size();
                for (PromptFieldSnapshot field : fieldLineage.rawUserFields()) {
                    records.add(promptRecord(field, "RAW_USER_PROMPT_FIELD", "rawUserPrompt", "RAW_PROMPT_FIELD"));
                }
            }
            if (fieldLineage.finalUserFields() != null) {
                finalCount = fieldLineage.finalUserFields().size();
                for (PromptFieldSnapshot field : fieldLineage.finalUserFields()) {
                    records.add(promptRecord(field, "FINAL_USER_PROMPT_FIELD", "userPrompt", "FINAL_PROMPT_FIELD"));
                }
            }
            if (fieldLineage.fieldDiffs() != null) {
                diffCount = fieldLineage.fieldDiffs().size();
                for (PromptFieldDiffRecord diff : fieldLineage.fieldDiffs()) {
                    records.add(diffRecord(diff));
                }
            }
        }

        int blockingCount = (int) records.stream()
                .filter(record -> record.fieldState().blockingCandidate())
                .count();
        return new PromptFieldStateLedger(
                List.copyOf(records),
                sourceCount,
                rawCount,
                finalCount,
                diffCount,
                blockingCount);
    }

    private static PromptFieldStateRecord sourceRecord(PromptSourceContextFieldSnapshot field) {
        boolean nullValue = field == null || "null".equals(field.valueType());
        boolean traversalProblem = field != null && field.sourcePath() != null
                && (field.sourcePath().endsWith(".__error__")
                || field.sourcePath().endsWith(".__depthLimit__")
                || field.sourcePath().endsWith(".__cycle__"));
        PromptFieldState state = traversalProblem
                ? PromptFieldState.PRODUCER_NOT_AVAILABLE
                : nullValue ? PromptFieldState.UNKNOWN_WITH_REASON : PromptFieldState.VALUE_PRESENT;
        String reasonCode = traversalProblem ? "SOURCE_TRAVERSAL_LIMIT"
                : nullValue ? "SOURCE_VALUE_NULL" : null;
        String reasonText = traversalProblem
                ? "The source context field could not be fully traversed and must be reviewed before using it as proof."
                : nullValue ? "The source model field exists, but the runtime value is null. Required policy decides whether this is allowed."
                : null;
        String path = field == null ? "source.unknown" : field.sourcePath();
        return new PromptFieldStateRecord(
                "source:" + path,
                field == null ? "SOURCE_CONTEXT" : field.sourceType(),
                path,
                field == null ? "unknown" : field.valueType(),
                state,
                field == null ? "null" : field.valueType(),
                field == null ? "" : field.valueHash(),
                field == null ? 0 : field.valueLength(),
                field == null ? "" : preview(field.valueText()),
                "DISCOVERED_SOURCE_FIELD",
                "ALWAYS_CAPTURE_SOURCE_STATE",
                "source model traversal",
                "UNMAPPED_PROJECTION_POLICY",
                "SOURCE_CONTEXT_ONLY",
                "PENDING_SEALED_PACKAGE_PROJECTION",
                traversalProblem ? "PRODUCER_PARTIAL" : "PRODUCER_REPORTED",
                reasonCode,
                reasonText,
                "METRIC_MAPPING_REQUIRED",
                state.blockingCandidate() ? "BLOCKING_CANDIDATE" : "NON_BLOCKING_UNTIL_REQUIRED_POLICY_MATCH",
                null,
                null);
    }

    private static PromptFieldStateRecord promptRecord(
            PromptFieldSnapshot field,
            String sourceType,
            String prefix,
            String projectionPolicy) {
        return new PromptFieldStateRecord(
                sourceType.toLowerCase() + ":" + field.fieldKey(),
                sourceType,
                prefix + "." + field.fieldKey(),
                "prompt.line",
                field.compactedMarker() ? PromptFieldState.COMPACTED_WITH_FULL_SOURCE : PromptFieldState.VALUE_PRESENT,
                "java.lang.String",
                field.valueHash(),
                field.valueLength(),
                preview(field.valuePreview()),
                "DISCOVERED_PROMPT_FIELD",
                "ALWAYS_CAPTURE_PROMPT_FIELD",
                "prompt text parser",
                projectionPolicy,
                sourceType,
                "PENDING_SEALED_PACKAGE_PROJECTION",
                "PROMPT_RENDERED",
                field.compactedMarker() ? "COMPACTED_MARKER_PRESENT" : null,
                field.compactedMarker() ? "The prompt contains a compacted marker. The full source must remain available in the sealed package." : null,
                "PROMPT_LINEAGE",
                field.compactedMarker() ? "REQUIRES_FULL_SOURCE_REFERENCE" : "NON_BLOCKING",
                field.sectionTitle(),
                field.label());
    }

    private static PromptFieldStateRecord diffRecord(PromptFieldDiffRecord diff) {
        PromptFieldState state = switch (diff.diffType()) {
            case MISSING_IN_FINAL -> PromptFieldState.CONTRACT_MISMATCH;
            case VALUE_CHANGED -> PromptFieldState.CONTRACT_MISMATCH;
            case ADDED_IN_FINAL, SAME -> PromptFieldState.VALUE_PRESENT;
        };
        String reasonCode = switch (diff.diffType()) {
            case MISSING_IN_FINAL -> "RAW_FIELD_NOT_PRESENT_IN_FINAL_PROMPT";
            case VALUE_CHANGED -> "RAW_FIELD_VALUE_CHANGED_IN_FINAL_PROMPT";
            case ADDED_IN_FINAL -> "FINAL_FIELD_ADDED";
            case SAME -> null;
        };
        return new PromptFieldStateRecord(
                "projection:" + diff.fieldKey(),
                "PROMPT_PROJECTION_DIFF",
                "rawUserPrompt->userPrompt." + diff.fieldKey(),
                "prompt.projection",
                state,
                "java.lang.String",
                firstNonBlank(diff.finalValueHash(), diff.rawValueHash()),
                0,
                preview(diff.reason()),
                diff.blockingCandidate() ? "REQUIRED_PROMPT_PROJECTION" : "OBSERVED_PROMPT_PROJECTION",
                "RAW_AND_FINAL_PROMPT_COMPARISON",
                "prompt field lineage analyzer",
                "RAW_USER_TO_FINAL_USER_PROMPT",
                diff.diffType().name(),
                "PENDING_SEALED_PACKAGE_PROJECTION",
                "PROMPT_LINEAGE_ANALYZED",
                reasonCode,
                diff.reason(),
                "PROMPT_PROJECTION",
                state.blockingCandidate() ? "BLOCKING_CANDIDATE" : "NON_BLOCKING",
                diff.sectionTitle(),
                diff.label());
    }

    private static String firstNonBlank(String first, String second) {
        return first != null && !first.isBlank() ? first : second;
    }

    private static String preview(String value) {
        if (value == null) {
            return "";
        }
        String normalized = value.replaceAll("\\s+", " ").trim();
        if (normalized.length() <= PREVIEW_LIMIT) {
            return normalized;
        }
        return normalized.substring(0, PREVIEW_LIMIT) + "...";
    }
}
