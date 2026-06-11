/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
        boolean declaredUnknown = field != null
                && field.valueText() != null
                && ("UNKNOWN".equalsIgnoreCase(field.valueText().trim())
                || "INSUFFICIENT".equalsIgnoreCase(field.valueText().trim()));
        boolean traversalProblem = field != null && field.sourcePath() != null
                && (field.sourcePath().endsWith(".__error__")
                || field.sourcePath().endsWith(".__depthLimit__")
                || field.sourcePath().endsWith(".__cycle__"));
        PromptFieldState state = traversalProblem
                ? PromptFieldState.PRODUCER_NOT_AVAILABLE
                : (nullValue || declaredUnknown) ? PromptFieldState.UNKNOWN_WITH_REASON : PromptFieldState.VALUE_PRESENT;
        String reasonCode = traversalProblem ? "SOURCE_TRAVERSAL_LIMIT"
                : nullValue ? "SOURCE_VALUE_NULL"
                : declaredUnknown ? "SOURCE_VALUE_DECLARED_UNKNOWN" : null;
        String reasonText = traversalProblem
                ? "The source context field could not be fully traversed and must be reviewed before using it as proof."
                : nullValue ? "The source model field exists, but the runtime value is null. Required policy decides whether this is allowed."
                : declaredUnknown ? "The source model explicitly declared the value as unknown or insufficient. This must remain visible to the prompt quality contract."
                : null;
        String path = field == null ? "source.unknown" : field.sourcePath();
        PromptFieldPolicy policy = PromptFieldPolicyCatalog.resolve(
                "source:" + path,
                field == null ? "SOURCE_CONTEXT" : field.sourceType(),
                path,
                null);
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
                policy.requiredPolicy(),
                policy.applicabilityRule(),
                "source model traversal",
                policy.projectionPolicy(),
                "SOURCE_CONTEXT_ONLY",
                "PENDING_SEALED_PACKAGE_PROJECTION",
                traversalProblem ? "PRODUCER_PARTIAL" : "PRODUCER_REPORTED",
                reasonCode,
                reasonText,
                String.join(",", policy.metricCodes()),
                state.blockingCandidate() && policy.officialContractField()
                        ? "OFFICIAL_BLOCKING"
                        : "NON_BLOCKING_UNTIL_REQUIRED_POLICY_MATCH",
                null,
                null);
    }

    private static PromptFieldStateRecord promptRecord(
            PromptFieldSnapshot field,
            String sourceType,
            String prefix,
            String projectionPolicy) {
        PromptFieldPolicy policy = PromptFieldPolicyCatalog.resolve(
                sourceType.toLowerCase() + ":" + field.fieldKey(),
                sourceType,
                prefix + "." + field.fieldKey(),
                field.label());
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
                policy.requiredPolicy(),
                policy.applicabilityRule(),
                "prompt text parser",
                firstNonBlank(policy.projectionPolicy(), projectionPolicy),
                sourceType,
                "PENDING_SEALED_PACKAGE_PROJECTION",
                "PROMPT_RENDERED",
                field.compactedMarker() ? "COMPACTED_MARKER_PRESENT" : null,
                field.compactedMarker() ? "The prompt contains a compacted marker. The full source must remain available in the sealed package." : null,
                String.join(",", policy.metricCodes()),
                field.compactedMarker() && policy.officialContractField() ? "REQUIRES_FULL_SOURCE_REFERENCE" : "NON_BLOCKING",
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
        PromptFieldPolicy policy = PromptFieldPolicyCatalog.resolve(
                "projection:" + diff.fieldKey(),
                "PROMPT_PROJECTION_DIFF",
                "rawUserPrompt->userPrompt." + diff.fieldKey(),
                diff.label());
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
                diff.blockingCandidate() ? "REQUIRED_PROMPT_PROJECTION" : policy.requiredPolicy(),
                policy.applicabilityRule(),
                "prompt field lineage analyzer",
                "RAW_USER_TO_FINAL_USER_PROMPT",
                diff.diffType().name(),
                "PENDING_SEALED_PACKAGE_PROJECTION",
                "PROMPT_LINEAGE_ANALYZED",
                reasonCode,
                diff.reason(),
                String.join(",", policy.metricCodes()),
                state.blockingCandidate() && policy.officialContractField() ? "OFFICIAL_BLOCKING" : "NON_BLOCKING",
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
